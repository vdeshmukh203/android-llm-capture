#!/usr/bin/env python3
"""
android_llm_capture.py — Android LLM Network Traffic Capture
Parses Android logcat output to intercept and replay LLM API calls.
Stdlib-only. No external dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


# ---------------------------------------------------------------------------
# LLM provider URL patterns
# ---------------------------------------------------------------------------

LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":       re.compile(r'api\.openai\.com/v1/', re.IGNORECASE),
    "anthropic":    re.compile(r'api\.anthropic\.com/', re.IGNORECASE),
    "google":       re.compile(r'generativelanguage\.googleapis\.com/', re.IGNORECASE),
    "cohere":       re.compile(r'api\.cohere\.ai/', re.IGNORECASE),
    "mistral":      re.compile(r'api\.mistral\.ai/', re.IGNORECASE),
    "together":     re.compile(r'api\.together\.ai/', re.IGNORECASE),
    "huggingface":  re.compile(r'api-inference\.huggingface\.co/', re.IGNORECASE),
    "groq":         re.compile(r'api\.groq\.com/', re.IGNORECASE),
}

# Logcat patterns (OkHttp / Cronet interceptor output)
_OKHTTP_REQUEST  = re.compile(r'--> (?P<method>POST|GET|PUT|PATCH) (?P<url>https?://\S+)')
_OKHTTP_BODY     = re.compile(r'(?P<body>\{.*\}|\[.*\])')
_OKHTTP_RESPONSE = re.compile(r'<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)')
_LOGCAT_TAG      = re.compile(r'[VDIWEF]/(?P<tag>\S+)\s*\(?\d*\)?:\s*(?P<msg>.*)')
_CRONET_URL      = re.compile(
    r'(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)',
    re.IGNORECASE,
)


def _detect_provider(url: str) -> Optional[str]:
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CapturedCall:
    """Represents one complete LLM API request/response pair captured from logcat."""

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str            # "logcat" or "file"
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str  = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        resp_str = self.response_body or ""
        self.request_hash  = _sha256(req_str)
        self.response_hash = _sha256(resp_str)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def model(self) -> Optional[str]:
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough word-count-based token estimate for the request messages."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "") for m in messages if isinstance(m, dict)
        )
        return max(1, len(text.split()) * 4 // 3)


# ---------------------------------------------------------------------------
# Logcat line parser
# ---------------------------------------------------------------------------

def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """Stateful parser for a single logcat line.

    ``state`` is mutated to accumulate partial call info across successive
    lines.  Returns a :class:`CapturedCall` when a complete request+response
    pair is detected, otherwise ``None``.

    The parser understands OkHttp interceptor format and Cronet URL
    announcements.  Order of checks matters: response detection must happen
    *before* the request-body accumulation block, or response lines are
    accidentally consumed as body content.
    """
    line = line.strip()
    if not line:
        return None

    # ── OkHttp request start ────────────────────────────────────────────────
    m = _OKHTTP_REQUEST.search(line)
    if m:
        url = m.group("url")
        provider = _detect_provider(url)
        if provider:
            state.clear()
            state.update(
                url=url,
                method=m.group("method"),
                provider=provider,
                body_lines=[],
                phase="request",
            )
        return None

    # ── OkHttp response start — must be checked BEFORE body accumulation ───
    # If this check came after the body-accumulation block the response line
    # would be silently consumed while phase=="request".
    m_resp = _OKHTTP_RESPONSE.search(line)
    if m_resp and state.get("url"):
        resp_url = m_resp.group("url")
        if _detect_provider(resp_url) or resp_url == state.get("url"):
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
        return None

    # ── Request body accumulation ───────────────────────────────────────────
    if state.get("phase") == "request" and state.get("url"):
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["body_lines"].append(m_body.group("body"))
        return None

    # ── Response body ───────────────────────────────────────────────────────
    if state.get("phase") == "response":
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            call = _finalise_call(state, m_body.group("body"))
            state.clear()
            return call

    # ── Cronet URL detection ────────────────────────────────────────────────
    m_cronet = _CRONET_URL.search(line)
    if m_cronet:
        url = m_cronet.group("url")
        provider = _detect_provider(url)
        if provider:
            state.clear()
            state.update(
                url=url,
                method="POST",
                provider=provider,
                body_lines=[],
                phase="request",
            )

    return None


def _finalise_call(state: Dict, response_body: Optional[str]) -> CapturedCall:
    body_json: Optional[Dict] = None
    if state.get("body_lines"):
        try:
            body_json = json.loads(" ".join(state["body_lines"]))
        except (json.JSONDecodeError, ValueError):
            body_json = None

    # uuid4 avoids the timestamp-collision risk of a time-based hash
    call_id = uuid.uuid4().hex[:16]

    return CapturedCall(
        call_id=call_id,
        timestamp=time.time(),
        provider=state.get("provider", "unknown"),
        url=state.get("url", ""),
        method=state.get("method", "POST"),
        request_body=body_json,
        response_status=state.get("response_status"),
        response_body=response_body,
        source="logcat",
    )


# ---------------------------------------------------------------------------
# File-based parser
# ---------------------------------------------------------------------------

def parse_logcat_file(path: Path) -> List[CapturedCall]:
    """Parse a saved logcat dump file and return all detected LLM calls."""
    calls: List[CapturedCall] = []
    state: Dict = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result = parse_logcat_line(line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls


# ---------------------------------------------------------------------------
# CaptureSession (live logcat)
# ---------------------------------------------------------------------------

class CaptureSession:
    """Manages a live ADB logcat capture subprocess."""

    def __init__(
        self,
        device_serial: Optional[str] = None,
        tag_filter: str = "OkHttp",
    ) -> None:
        self.device_serial = device_serial
        self.tag_filter    = tag_filter
        self.calls: List[CapturedCall] = []
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        """Launch ``adb logcat`` as a subprocess."""
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += ["logcat", "-v", "brief", f"{self.tag_filter}:V", "*:S"]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )

    def stop(self) -> None:
        """Terminate the logcat subprocess if running."""
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """Yield :class:`CapturedCall` objects as they are detected."""
        if not self._proc:
            raise RuntimeError("Call start() before streaming.")
        if not self._proc.stdout:
            raise RuntimeError("logcat subprocess has no stdout pipe.")
        state: Dict = {}
        for line in self._proc.stdout:
            result = parse_logcat_line(line, state)
            if result:
                self.calls.append(result)
                yield result

    def export_jsonl(self, path: Path) -> None:
        """Write all captured calls to *path* in JSONL format."""
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        print(f"Exported {len(self.calls)} calls to {path}")

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        """Replay *call* against the live API, injecting *api_key*."""
        if not call.request_body:
            raise ValueError("No request body to replay.")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if call.provider == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
        elif call.provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        payload = json.dumps(call.request_body).encode()
        req = urllib.request.Request(
            call.url, data=payload, headers=headers, method=call.method
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# ADB helpers
# ---------------------------------------------------------------------------

def list_devices() -> List[str]:
    """Return serial strings for all online ADB devices."""
    try:
        out = subprocess.check_output(["adb", "devices"], timeout=10, text=True)
        lines = out.strip().splitlines()[1:]  # skip "List of devices attached" header
        return [
            parts[0]
            for line in lines
            if line.strip() and "offline" not in line
            for parts in [line.split()]
            if parts
        ]
    except Exception:
        return []


def list_packages(device: Optional[str] = None) -> List[str]:
    """Return all installed package names on a connected Android device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages"]
    try:
        out = subprocess.check_output(cmd, timeout=30, text=True)
        return [
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="android-llm-capture",
        description="Capture and replay Android LLM API calls via ADB logcat.",
    )
    sub = p.add_subparsers(dest="command")

    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None, help="Android device serial (adb -s).")
    live_p.add_argument("--tag", default="OkHttp", help="Logcat tag to filter.")
    live_p.add_argument("--output", "-o", default="captures.jsonl")
    live_p.add_argument(
        "--timeout", type=int, default=0,
        help="Stop after N seconds (0 = run until Ctrl-C).",
    )

    file_p = sub.add_parser("file", help="Parse a saved logcat dump file.")
    file_p.add_argument("logcat", help="Path to the logcat dump file.")
    file_p.add_argument("--output", "-o", default="captures.jsonl")
    file_p.add_argument("--json", action="store_true",
                        help="Output a JSON array instead of JSONL.")

    replay_p = sub.add_parser("replay", help="Replay a captured call against the live API.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id", help="call_id to replay, or 'last'.")
    replay_p.add_argument("--api-key", required=True,
                          help="API key for the provider.")

    stats_p = sub.add_parser("stats", help="Show statistics about a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    # ── live ────────────────────────────────────────────────────────────────
    if args.command == "live":
        session = CaptureSession(device_serial=args.serial, tag_filter=args.tag)
        print(f"Starting live capture (tag={args.tag}). Press Ctrl-C to stop.")
        try:
            session.start()
            start = time.time()
            for call in session.stream():
                print(
                    f"[{call.provider}] {call.method} "
                    f"{call.url[:60]} status={call.response_status}"
                )
                if args.timeout and (time.time() - start) > args.timeout:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            session.stop()
        session.export_jsonl(Path(args.output))
        return 0

    # ── file ─────────────────────────────────────────────────────────────────
    if args.command == "file":
        path = Path(args.logcat)
        if not path.is_file():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1
        calls = parse_logcat_file(path)
        out = Path(args.output)
        with out.open("w", encoding="utf-8") as fh:
            if args.json:
                fh.write(
                    json.dumps([c.to_dict() for c in calls],
                               indent=2, ensure_ascii=False)
                )
            else:
                for c in calls:
                    fh.write(c.to_jsonl() + "\n")
        print(f"Found {len(calls)} LLM calls → {out}")
        return 0

    # ── replay ───────────────────────────────────────────────────────────────
    if args.command == "replay":
        caps_path = Path(args.captures)
        calls: List[CapturedCall] = []
        with caps_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                calls.append(CapturedCall(
                    call_id=obj["call_id"],
                    timestamp=obj["timestamp"],
                    provider=obj["provider"],
                    url=obj["url"],
                    method=obj["method"],
                    request_body=obj.get("request_body"),
                    response_status=obj.get("response_status"),
                    response_body=obj.get("response_body"),
                    source=obj.get("source", "file"),
                ))
        if not calls:
            print("No calls found.", file=sys.stderr)
            return 1
        if args.call_id == "last":
            target = calls[-1]
        else:
            target = next(
                (c for c in calls if c.call_id == args.call_id), None
            )
        if not target:
            print(f"call_id {args.call_id!r} not found.", file=sys.stderr)
            return 1
        session = CaptureSession()
        result = session.replay(target, api_key=args.api_key)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    # ── stats ────────────────────────────────────────────────────────────────
    if args.command == "stats":
        raw_calls = []
        with open(args.captures, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    raw_calls.append(json.loads(line))
        by_provider: Dict[str, int] = {}
        by_model:    Dict[str, int] = {}
        for c in raw_calls:
            prov  = c.get("provider", "unknown")
            model = (c.get("request_body") or {}).get("model", "unknown")
            by_provider[prov]   = by_provider.get(prov, 0) + 1
            by_model[model]     = by_model.get(model, 0) + 1
        print(f"Total calls: {len(raw_calls)}")
        print("By provider:")
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("By model:")
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    print("android-llm-capture: specify a subcommand (live, file, replay, stats)")
    print("Use --help for usage.")
    return 1


# ---------------------------------------------------------------------------
# Public aliases
# ---------------------------------------------------------------------------

#: Backwards-compatible alias for CaptureSession
LLMCapture = CaptureSession

#: Entry point referenced by pyproject.toml
_cli = main


if __name__ == "__main__":
    sys.exit(main())
