#!/usr/bin/env python3
"""
android_llm_capture — Android LLM Network Traffic Capture

Parses Android logcat output (OkHttp / Cronet interceptor format) to intercept,
record, and replay LLM API calls made by closed Android applications.

Stdlib-only — no external dependencies required.
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
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

__all__ = [
    "CapturedCall",
    "CaptureSession",
    "LLMCapture",
    "LLM_PATTERNS",
    "parse_logcat_line",
    "parse_logcat_file",
    "load_jsonl",
    "list_devices",
    "list_packages",
    "main",
]


# ---------------------------------------------------------------------------
# LLM provider URL patterns
# ---------------------------------------------------------------------------

LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":      re.compile(r"api\.openai\.com/v1/",                   re.IGNORECASE),
    "anthropic":   re.compile(r"api\.anthropic\.com/",                   re.IGNORECASE),
    "google":      re.compile(r"generativelanguage\.googleapis\.com/",   re.IGNORECASE),
    "cohere":      re.compile(r"api\.cohere\.ai/",                       re.IGNORECASE),
    "mistral":     re.compile(r"api\.mistral\.ai/",                      re.IGNORECASE),
    "together":    re.compile(r"api\.together\.ai/",                     re.IGNORECASE),
    "huggingface": re.compile(r"api-inference\.huggingface\.co/",        re.IGNORECASE),
    "groq":        re.compile(r"api\.groq\.com/",                        re.IGNORECASE),
}

# OkHttp interceptor log patterns
_OKHTTP_REQUEST     = re.compile(r"--> (?P<method>POST|GET|PUT|PATCH|DELETE) (?P<url>https?://\S+)")
_OKHTTP_RESPONSE    = re.compile(r"<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)")
_OKHTTP_END_REQUEST = re.compile(r"--> END (POST|GET|PUT|PATCH|DELETE)")
_OKHTTP_END_RESP    = re.compile(r"<-- END HTTP")
# Body lines: JSON object or array on a single logcat line
_OKHTTP_BODY        = re.compile(r"(?P<body>\{.*\}|\[.*\])")

# Cronet (alternative HTTP client used by some Android apps)
_CRONET_URL = re.compile(
    r"(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)",
    re.IGNORECASE,
)


def _detect_provider(url: str) -> Optional[str]:
    """Return the LLM provider name matching *url*, or ``None``."""
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
    """A single captured LLM API request/response pair.

    Parameters
    ----------
    call_id:
        Short hex identifier derived from timestamp and URL.
    timestamp:
        Unix timestamp of capture (``time.time()``).
    provider:
        Detected provider name (e.g. ``"openai"``, ``"anthropic"``).
    url:
        Full request URL.
    method:
        HTTP method (``"POST"``, ``"GET"``, …).
    request_body:
        Parsed JSON request payload, or ``None`` if absent/unparseable.
    response_status:
        HTTP response status code, or ``None`` if not yet received.
    response_body:
        Raw response body string, or ``None``.
    source:
        ``"logcat"`` for live capture, ``"file"`` for parsed dumps.
    """

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str  = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        resp_str = self.response_body or ""
        self.request_hash  = _sha256(req_str)
        self.response_hash = _sha256(resp_str)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation."""
        return asdict(self)

    def to_jsonl(self) -> str:
        """Return a single JSONL line (no trailing newline)."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "CapturedCall":
        """Reconstruct a :class:`CapturedCall` from a dictionary."""
        return cls(
            call_id=d["call_id"],
            timestamp=d["timestamp"],
            provider=d["provider"],
            url=d["url"],
            method=d["method"],
            request_body=d.get("request_body"),
            response_status=d.get("response_status"),
            response_body=d.get("response_body"),
            source=d.get("source", "file"),
        )

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def model(self) -> Optional[str]:
        """Model name extracted from the request body, or ``None``."""
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough prompt-token estimate based on whitespace-split word count."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "")
            for m in messages
            if isinstance(m, dict) and isinstance(m.get("content"), str)
        )
        return max(1, len(text.split()) * 4 // 3)


# ---------------------------------------------------------------------------
# Logcat line parser
# ---------------------------------------------------------------------------

def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """Parse one logcat line and update the shared *state* accumulator.

    *state* is a mutable ``dict`` shared across consecutive calls for the same
    log stream; pass an empty ``{}`` for the first line.  Returns a
    :class:`CapturedCall` when a complete request/response pair is assembled;
    returns ``None`` otherwise.

    The parser handles:

    * OkHttp interceptor format (``--> POST …`` / ``<-- 200 …`` / ``<-- END HTTP``).
    * Cronet URL detection as a fallback for apps that bypass OkHttp.

    Parameters
    ----------
    line:
        A single logcat line (may include leading/trailing whitespace).
    state:
        Mutable accumulator dict.
    """
    line = line.strip()
    if not line:
        return None

    # ------------------------------------------------------------------
    # 1. OkHttp request START — reset and initialise state
    # ------------------------------------------------------------------
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
                resp_body_lines=[],
                phase="request",
            )
        return None

    # ------------------------------------------------------------------
    # 2. OkHttp response START — checked BEFORE body accumulation so that
    #    the response line is not silently swallowed while phase=="request".
    # ------------------------------------------------------------------
    m_resp = _OKHTTP_RESPONSE.search(line)
    if m_resp and state.get("url"):
        resp_url = m_resp.group("url")
        if _detect_provider(resp_url) or resp_url == state["url"]:
            state["response_status"] = int(m_resp.group("status"))
            state.setdefault("resp_body_lines", [])
            state["phase"] = "response"
        return None

    # ------------------------------------------------------------------
    # 3. End-of-request marker → wait for response header
    # ------------------------------------------------------------------
    if state.get("phase") == "request" and _OKHTTP_END_REQUEST.search(line):
        state["phase"] = "awaiting_response"
        return None

    # ------------------------------------------------------------------
    # 4. End-of-response marker → finalise and emit call
    # ------------------------------------------------------------------
    if state.get("phase") == "response" and _OKHTTP_END_RESP.search(line):
        raw_resp = " ".join(state.get("resp_body_lines", [])) or None
        call = _finalise_call(state, raw_resp)
        state.clear()
        return call

    # ------------------------------------------------------------------
    # 5. Body accumulation
    # ------------------------------------------------------------------
    phase = state.get("phase")

    if phase == "request" and state.get("url"):
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["body_lines"].append(m_body.group("body"))
        return None

    if phase == "response":
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["resp_body_lines"].append(m_body.group("body"))
        return None

    # ------------------------------------------------------------------
    # 6. Cronet URL detection (fallback for apps that use Cronet)
    # ------------------------------------------------------------------
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
                resp_body_lines=[],
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
    call_id = _sha256(f"{time.time()}{state.get('url', '')}")[:16]
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
    """Parse a saved logcat dump and return all detected LLM API calls.

    Parameters
    ----------
    path:
        Path to a plain-text logcat dump file.
    """
    calls: List[CapturedCall] = []
    state: Dict = {}
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result = parse_logcat_line(line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------

def load_jsonl(path: Path) -> List[CapturedCall]:
    """Load :class:`CapturedCall` objects from a JSONL file.

    Silently skips blank lines and malformed entries.

    Parameters
    ----------
    path:
        Path to a ``.jsonl`` captures file produced by this tool.
    """
    calls: List[CapturedCall] = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                calls.append(CapturedCall.from_dict(json.loads(line)))
            except (KeyError, TypeError, json.JSONDecodeError):
                pass
    return calls


# ---------------------------------------------------------------------------
# CaptureSession (live logcat)
# ---------------------------------------------------------------------------

class CaptureSession:
    """Manages a live logcat capture session via ``adb logcat``.

    Parameters
    ----------
    device_serial:
        ADB device serial number (the ``-s`` flag value).  Pass ``None`` to
        use the single connected device.
    tag_filter:
        Logcat tag to include (default ``"OkHttp"``).

    Examples
    --------
    ::

        session = CaptureSession(tag_filter="OkHttp")
        session.start()
        for call in session.stream():
            print(call.provider, call.url)
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
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )

    def stop(self) -> None:
        """Terminate the logcat subprocess."""
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """Yield :class:`CapturedCall` objects as they are detected.

        Raises :exc:`RuntimeError` if :meth:`start` has not been called.
        """
        if not self._proc:
            raise RuntimeError("Call start() before streaming.")
        state: Dict = {}
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            result = parse_logcat_line(line, state)
            if result:
                self.calls.append(result)
                yield result

    def export_jsonl(self, path: Path) -> None:
        """Write all captured calls to *path* in JSONL format.

        Parameters
        ----------
        path:
            Destination file path (created or overwritten).
        """
        with Path(path).open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        print(f"Exported {len(self.calls)} call(s) to {path}")

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        """Re-execute *call* against the live provider API.

        Injects the appropriate ``Authorization`` / ``x-api-key`` header for
        the call's provider.

        Parameters
        ----------
        call:
            A previously captured call with a non-empty request body.
        api_key:
            API key for the provider.

        Returns
        -------
        dict
            Parsed JSON response from the provider.

        Raises
        ------
        ValueError
            If the call has no request body.
        """
        if not call.request_body:
            raise ValueError("No request body to replay.")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if call.provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            # OpenAI-compatible bearer token for all other providers
            headers["Authorization"] = f"Bearer {api_key}"
        payload = json.dumps(call.request_body).encode()
        req = urllib.request.Request(
            call.url, data=payload, headers=headers, method=call.method
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def list_devices() -> List[str]:
    """Return serial strings for all currently connected (online) ADB devices."""
    try:
        out = subprocess.check_output(["adb", "devices"], timeout=10, text=True)
        lines = out.strip().splitlines()[1:]  # skip header
        return [
            ln.split()[0]
            for ln in lines
            if ln.strip() and "offline" not in ln and "unauthorized" not in ln
        ]
    except Exception:
        return []


def list_packages(device: Optional[str] = None) -> List[str]:
    """List installed package names on a connected Android device.

    Parameters
    ----------
    device:
        ADB device serial.  ``None`` uses the single connected device.
    """
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
    except Exception:
        return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="android-llm-capture",
        description="Capture and replay LLM API calls from Android devices via ADB.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")

    # live
    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None, help="ADB device serial.")
    live_p.add_argument("--tag", default="OkHttp", help="Logcat tag filter.")
    live_p.add_argument("--output", "-o", default="captures.jsonl",
                        help="Output JSONL file (default: captures.jsonl).")
    live_p.add_argument("--timeout", type=int, default=0,
                        help="Stop after N seconds (0 = run until Ctrl-C).")

    # file
    file_p = sub.add_parser("file", help="Parse a saved logcat dump file.")
    file_p.add_argument("logcat", help="Path to logcat dump.")
    file_p.add_argument("--output", "-o", default="captures.jsonl")
    file_p.add_argument("--json", action="store_true",
                        help="Write a JSON array instead of JSONL.")

    # replay
    replay_p = sub.add_parser("replay", help="Replay a captured call against the live API.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id", help="call_id to replay, or 'last'.")
    replay_p.add_argument("--api-key", required=True, help="API key for the provider.")

    # stats
    stats_p = sub.add_parser("stats", help="Print statistics for a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    # gui
    sub.add_parser("gui", help="Launch the graphical user interface.")

    return p.parse_args(argv)


def main(argv=None) -> int:
    """Entry-point for the ``android-llm-capture`` CLI."""
    args = _parse_args(argv)

    # ------------------------------------------------------------
    if args.command == "gui":
        try:
            from android_llm_capture_gui import main as gui_main
            return gui_main()
        except ImportError as exc:
            print(f"GUI unavailable: {exc}", file=sys.stderr)
            return 1

    # ------------------------------------------------------------
    if args.command == "live":
        session = CaptureSession(device_serial=args.serial, tag_filter=args.tag)
        print(f"Starting live capture (tag={args.tag}). Press Ctrl-C to stop.")
        try:
            session.start()
            start = time.time()
            for call in session.stream():
                ts = time.strftime("%H:%M:%S", time.localtime(call.timestamp))
                print(
                    f"[{ts}] {call.provider:<12} {call.method} "
                    f"{call.url[:60]}  status={call.response_status}"
                )
                if args.timeout and (time.time() - start) > args.timeout:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            session.stop()
        session.export_jsonl(Path(args.output))
        return 0

    # ------------------------------------------------------------
    if args.command == "file":
        path = Path(args.logcat)
        if not path.is_file():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1
        calls = parse_logcat_file(path)
        out = Path(args.output)
        with out.open("w", encoding="utf-8") as fh:
            if args.json:
                json.dump([c.to_dict() for c in calls], fh, indent=2, ensure_ascii=False)
            else:
                for c in calls:
                    fh.write(c.to_jsonl() + "\n")
        print(f"Found {len(calls)} LLM call(s) → {out}")
        return 0

    # ------------------------------------------------------------
    if args.command == "replay":
        try:
            calls = load_jsonl(Path(args.captures))
        except FileNotFoundError:
            print(f"Error: {args.captures} not found", file=sys.stderr)
            return 1
        if not calls:
            print("No calls found in captures file.", file=sys.stderr)
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

    # ------------------------------------------------------------
    if args.command == "stats":
        try:
            calls = load_jsonl(Path(args.captures))
        except FileNotFoundError:
            print(f"Error: {args.captures} not found", file=sys.stderr)
            return 1
        by_provider: Dict[str, int] = {}
        by_model: Dict[str, int] = {}
        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model = c.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1
        print(f"Total calls: {len(calls)}")
        print("\nBy provider:")
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("\nBy model:")
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    # ------------------------------------------------------------
    print("android-llm-capture: specify a subcommand (live, file, replay, stats, gui)")
    print("Use --help for usage.")
    return 1


# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------

LLMCapture = CaptureSession   # alias kept for downstream compatibility
_cli = main                   # setuptools console_scripts entry-point alias


if __name__ == "__main__":
    sys.exit(main())
