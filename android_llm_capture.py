#!/usr/bin/env python3
"""
android_llm_capture — Android LLM Network Traffic Capture

Parses Android logcat output (OkHttp / Cronet interceptor format) to
non-invasively capture, log, and replay LLM API calls from Android apps.
Stdlib-only — no external dependencies required.

Supported providers: OpenAI, Anthropic, Google, Cohere, Mistral,
Together AI, Hugging Face Inference API, Groq.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


# ---------------------------------------------------------------------------
# LLM provider URL patterns
# ---------------------------------------------------------------------------

LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":      re.compile(r"api\.openai\.com/v1/", re.IGNORECASE),
    "anthropic":   re.compile(r"api\.anthropic\.com/", re.IGNORECASE),
    "google":      re.compile(r"generativelanguage\.googleapis\.com/", re.IGNORECASE),
    "cohere":      re.compile(r"api\.cohere\.ai/", re.IGNORECASE),
    "mistral":     re.compile(r"api\.mistral\.ai/", re.IGNORECASE),
    "together":    re.compile(r"api\.together\.ai/", re.IGNORECASE),
    "huggingface": re.compile(r"api-inference\.huggingface\.co/", re.IGNORECASE),
    "groq":        re.compile(r"api\.groq\.com/", re.IGNORECASE),
}

# OkHttp logging-interceptor patterns
_OKHTTP_REQUEST  = re.compile(r"--> (?P<method>DELETE|GET|PATCH|POST|PUT) (?P<url>https?://\S+)")
_OKHTTP_RESPONSE = re.compile(r"<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)")
_CRONET_URL      = re.compile(
    r"(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)", re.IGNORECASE
)


def _detect_provider(url: str) -> Optional[str]:
    """Return the LLM provider name for *url*, or ``None`` if not recognised."""
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _extract_json_fragment(text: str) -> Optional[str]:
    """
    Return the first complete JSON object or array found in *text*.

    Scans character-by-character to locate balanced brackets while correctly
    handling string literals (including escaped quotes).  Returns ``None`` when
    no complete JSON structure is present.  This is more robust than a greedy
    regex when multiple JSON structures appear on the same log line.
    """
    for start_ch, end_ch in (("{", "}"), ("[", "]")):
        start = text.find(start_ch)
        if start == -1:
            continue
        depth = 0
        in_string = False
        escaped = False
        for i, ch in enumerate(text[start:], start):
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_string:
                escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == start_ch:
                depth += 1
            elif ch == end_ch:
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
    return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CapturedCall:
    """A single captured LLM API request/response pair."""

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str            # "logcat" | "file"
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str  = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        resp_str = self.response_body or ""
        self.request_hash  = _sha256(req_str)
        self.response_hash = _sha256(resp_str)

    def to_dict(self) -> dict:
        """Return a plain dict representation (suitable for JSON encoding)."""
        return asdict(self)

    def to_jsonl(self) -> str:
        """Return a single-line JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def model(self) -> Optional[str]:
        """The ``model`` field from the request body, if present."""
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """
        Rough token-count heuristic for the prompt messages (word × 4/3).

        This is an approximation only — actual token counts depend on the
        provider's tokeniser and are not available from logcat alone.
        """
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "") for m in messages if isinstance(m, dict)
        )
        return max(1, len(text.split()) * 4 // 3)


# ---------------------------------------------------------------------------
# Logcat line parser  (stateful, call parse_logcat_line per line)
# ---------------------------------------------------------------------------


def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """
    Parse a single logcat line, updating *state* for multi-line calls.

    *state* is a mutable dict that accumulates partial call information
    across consecutive log lines.  Returns a :class:`CapturedCall` when a
    complete request+response pair is detected; otherwise returns ``None``.

    The caller is responsible for creating and passing the same dict for
    every line in a contiguous logcat stream.
    """
    line = line.strip()
    if not line:
        return None

    # OkHttp request start — clears any previous partial state
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

    # OkHttp response header — must be checked BEFORE body accumulation so it
    # is not swallowed when phase=="request" (the body block would return None).
    m_resp = _OKHTTP_RESPONSE.search(line)
    if m_resp and state.get("url"):
        resp_url = m_resp.group("url")
        if _detect_provider(resp_url) or resp_url == state.get("url"):
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
        return None

    # Body accumulation during request phase
    if state.get("phase") == "request" and state.get("url"):
        fragment = _extract_json_fragment(line)
        if fragment:
            state["body_lines"].append(fragment)
        return None

    # Response body — first JSON fragment completes the call
    if state.get("phase") == "response":
        fragment = _extract_json_fragment(line)
        if fragment:
            call = _finalise_call(state, fragment)
            state.clear()
            return call

    # Cronet URL detection (method defaults to POST)
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
    """Construct a :class:`CapturedCall` from accumulated parser *state*."""
    body_json: Optional[Dict] = None
    raw_body = " ".join(state.get("body_lines", []))
    if raw_body:
        try:
            body_json = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            body_json = None

    # Include URL + request body in the ID to reduce collision probability
    call_id = _sha256(f"{time.time_ns()}{state.get('url', '')}{raw_body}")[:16]

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
# JSONL helpers
# ---------------------------------------------------------------------------


def load_jsonl(path: Path) -> List[CapturedCall]:
    """Load a JSONL captures file and return a list of :class:`CapturedCall`."""
    calls: List[CapturedCall] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {lineno} of {path}: {exc}") from exc
            calls.append(
                CapturedCall(
                    call_id=obj["call_id"],
                    timestamp=obj["timestamp"],
                    provider=obj["provider"],
                    url=obj["url"],
                    method=obj["method"],
                    request_body=obj.get("request_body"),
                    response_status=obj.get("response_status"),
                    response_body=obj.get("response_body"),
                    source=obj.get("source", "file"),
                )
            )
    return calls


# ---------------------------------------------------------------------------
# CaptureSession — live logcat
# ---------------------------------------------------------------------------


class CaptureSession:
    """
    Manage a live ADB logcat capture session.

    Parameters
    ----------
    device_serial:
        ADB device serial (``adb -s``).  Pass ``None`` to use the default
        connected device.
    tag_filter:
        Logcat tag to pass to ``adb logcat``.  Default ``"OkHttp"`` matches
        the OkHttp logging interceptor used by most Android LLM clients.
    """

    def __init__(
        self,
        device_serial: Optional[str] = None,
        tag_filter: str = "OkHttp",
    ) -> None:
        self.device_serial = device_serial
        self.tag_filter = tag_filter
        self.calls: List[CapturedCall] = []
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        """Launch ``adb logcat`` as a background subprocess."""
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
        except FileNotFoundError as exc:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            ) from exc

    def stop(self) -> None:
        """Terminate the logcat subprocess."""
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """
        Yield :class:`CapturedCall` objects as they are detected from logcat.

        :meth:`start` must be called first.  The generator cleans up the
        subprocess via :meth:`stop` when it exits — whether by exhaustion,
        ``break``, or exception.
        """
        if not self._proc:
            raise RuntimeError("Call start() before streaming.")
        state: Dict = {}
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                result = parse_logcat_line(line, state)
                if result:
                    self.calls.append(result)
                    yield result
        finally:
            self.stop()

    def export_jsonl(self, path: Path) -> None:
        """Write all captured calls to a JSONL file at *path*."""
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        print(f"Exported {len(self.calls)} calls to {path}")

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        """
        Replay a captured call against the live API.

        Adds the appropriate authorisation header for the call's provider.
        OpenAI and Anthropic headers are handled explicitly; all other
        providers receive a generic ``Authorization: Bearer`` header.

        Parameters
        ----------
        call:    The :class:`CapturedCall` to replay.
        api_key: Provider API key.
        """
        if not call.request_body:
            raise ValueError("No request body to replay.")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if call.provider == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
        elif call.provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = json.dumps(call.request_body).encode()
        req = urllib.request.Request(
            call.url, data=payload, headers=headers, method=call.method
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="android-llm-capture",
        description="Capture and replay Android LLM API calls via ADB logcat.",
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")

    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None, metavar="SERIAL",
                        help="Android device serial (adb -s).")
    live_p.add_argument("--tag", default="OkHttp", metavar="TAG",
                        help="Logcat tag to filter (default: OkHttp).")
    live_p.add_argument("--output", "-o", default="captures.jsonl", metavar="FILE")
    live_p.add_argument("--timeout", type=int, default=0, metavar="SECONDS",
                        help="Stop after N seconds (0 = run until Ctrl-C).")

    file_p = sub.add_parser("file", help="Parse a saved logcat dump file.")
    file_p.add_argument("logcat", help="Path to the logcat dump file.")
    file_p.add_argument("--output", "-o", default="captures.jsonl", metavar="FILE")
    file_p.add_argument("--json", action="store_true",
                        help="Output a JSON array instead of JSONL.")

    replay_p = sub.add_parser("replay", help="Replay a captured call against the live API.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id", help="call_id to replay (use 'last' for the newest).")
    replay_p.add_argument("--api-key", required=True, help="Provider API key.")

    stats_p = sub.add_parser("stats", help="Show statistics about a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    return p.parse_args(argv)


def main(argv=None) -> int:
    """CLI entry point.  Returns an exit code (0 = success)."""
    args = _parse_args(argv)

    if args.command == "live":
        session = CaptureSession(device_serial=args.serial, tag_filter=args.tag)
        print(f"Starting live capture (tag={args.tag}). Press Ctrl-C to stop.")
        try:
            session.start()
            start_ts = time.time()
            for call in session.stream():
                print(
                    f"[{call.provider}] {call.method} {call.url[:60]} "
                    f"status={call.response_status}"
                )
                if args.timeout and (time.time() - start_ts) > args.timeout:
                    break
        except KeyboardInterrupt:
            pass
        session.export_jsonl(Path(args.output))
        return 0

    if args.command == "file":
        path = Path(args.logcat)
        if not path.is_file():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1
        calls = parse_logcat_file(path)
        out = Path(args.output)
        with out.open("w", encoding="utf-8") as fh:
            if args.json:
                fh.write(json.dumps([c.to_dict() for c in calls], indent=2, ensure_ascii=False))
            else:
                for c in calls:
                    fh.write(c.to_jsonl() + "\n")
        print(f"Found {len(calls)} LLM calls → {out}")
        return 0

    if args.command == "replay":
        calls = load_jsonl(Path(args.captures))
        if not calls:
            print("No calls found.", file=sys.stderr)
            return 1
        if args.call_id == "last":
            target = calls[-1]
        else:
            target = next((c for c in calls if c.call_id == args.call_id), None)
        if not target:
            print(f"call_id {args.call_id!r} not found.", file=sys.stderr)
            return 1
        result = CaptureSession().replay(target, api_key=args.api_key)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if args.command == "stats":
        calls = load_jsonl(Path(args.captures))
        by_provider: Dict[str, int] = {}
        by_model: Dict[str, int] = {}
        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model = c.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1
        print(f"Total calls : {len(calls)}")
        print("By provider :")
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {k:<18s} {v}")
        print("By model    :")
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            print(f"  {k:<30s} {v}")
        return 0

    print("android-llm-capture: specify a subcommand (live, file, replay, stats)")
    print("Use --help for usage.")
    return 1


# ---------------------------------------------------------------------------
# Public aliases and module-level helpers
# ---------------------------------------------------------------------------

#: Backwards-compatible alias for :class:`CaptureSession`.
LLMCapture = CaptureSession

#: Entry-point alias referenced by ``pyproject.toml``.
_cli = main


def list_devices() -> List[str]:
    """Return a list of connected ADB device serial strings."""
    try:
        out = subprocess.check_output(["adb", "devices"], timeout=10, text=True)
        lines = out.strip().splitlines()[1:]  # skip "List of devices attached" header
        return [ln.split()[0] for ln in lines if ln.strip() and "offline" not in ln]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []


def list_packages(device: Optional[str] = None) -> List[str]:
    """Return a list of installed package names from the Android device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages"]
    try:
        out = subprocess.check_output(cmd, timeout=30, text=True)
        return [
            ln.replace("package:", "").strip()
            for ln in out.splitlines()
            if ln.startswith("package:")
        ]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []


if __name__ == "__main__":
    sys.exit(main())
