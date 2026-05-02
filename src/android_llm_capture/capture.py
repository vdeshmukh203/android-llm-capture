"""Core capture primitives — CapturedCall, logcat parsing, AndroidCapture."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .adb import ADBClient


# ---------------------------------------------------------------------------
# LLM provider URL patterns
# ---------------------------------------------------------------------------

LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":       re.compile(r'api\.openai\.com/v1/',                 re.IGNORECASE),
    "anthropic":    re.compile(r'api\.anthropic\.com/',                 re.IGNORECASE),
    "google":       re.compile(r'generativelanguage\.googleapis\.com/', re.IGNORECASE),
    "cohere":       re.compile(r'api\.cohere\.ai/',                     re.IGNORECASE),
    "mistral":      re.compile(r'api\.mistral\.ai/',                    re.IGNORECASE),
    "together":     re.compile(r'api\.together\.ai/',                   re.IGNORECASE),
    "huggingface":  re.compile(r'api-inference\.huggingface\.co/',      re.IGNORECASE),
    "groq":         re.compile(r'api\.groq\.com/',                      re.IGNORECASE),
    "azure_openai": re.compile(r'openai\.azure\.com/',                  re.IGNORECASE),
    "ollama":       re.compile(r'localhost:\d+/api/',                   re.IGNORECASE),
}

_OKHTTP_REQUEST  = re.compile(r'--> (?P<method>POST|GET|PUT|PATCH|DELETE) (?P<url>https?://\S+)')
_OKHTTP_BODY     = re.compile(r'(?P<body>\{.+\}|\[.+\])')
_OKHTTP_RESPONSE = re.compile(r'<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)')
_OKHTTP_END_RESP = re.compile(r'<-- END HTTP')
_CRONET_URL      = re.compile(r'(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)',
                               re.IGNORECASE)


def _detect_provider(url: str) -> Optional[str]:
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# ---------------------------------------------------------------------------
# CapturedCall
# ---------------------------------------------------------------------------

@dataclass
class CapturedCall:
    """One complete LLM API request/response pair captured from logcat."""

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

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "CapturedCall":
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

    @property
    def model(self) -> Optional[str]:
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough token estimate: ~1 token per 4 characters (OpenAI rule-of-thumb)."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "") if isinstance(m.get("content"), str) else ""
            for m in messages
            if isinstance(m, dict)
        )
        return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Logcat line parser
# ---------------------------------------------------------------------------

def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """
    Stateful single-line logcat parser.

    *state* is mutated across calls to accumulate partial request/response
    data.  Returns a :class:`CapturedCall` when a complete pair is detected.
    """
    line = line.strip()
    if not line:
        return None

    # ── OkHttp request start ───────────────────────────────────────────────
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
                resp_lines=[],
                phase="request",
            )
        return None

    # ── OkHttp response header ─────────────────────────────────────────────
    # Checked BEFORE the body-accumulation block: the body block returns None
    # for every line while phase=="request", so without this ordering the
    # "<-- 200 …" line would be swallowed and a response never finalised.
    m_resp = _OKHTTP_RESPONSE.search(line)
    if m_resp and state.get("url"):
        resp_url = m_resp.group("url")
        if _detect_provider(resp_url) or resp_url == state.get("url"):
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
            state.setdefault("resp_lines", [])
        return None

    # ── Request body accumulation ──────────────────────────────────────────
    if state.get("phase") == "request" and state.get("url"):
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["body_lines"].append(m_body.group("body"))
        return None

    # ── Response body accumulation ─────────────────────────────────────────
    if state.get("phase") == "response":
        if _OKHTTP_END_RESP.search(line):
            body = " ".join(state.get("resp_lines", [])) or None
            call = _build_call(state, body)
            state.clear()
            return call
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state.setdefault("resp_lines", []).append(m_body.group("body"))
        return None

    # ── Cronet URL detection ───────────────────────────────────────────────
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
                resp_lines=[],
                phase="request",
            )

    return None


def _build_call(state: Dict, response_body: Optional[str]) -> CapturedCall:
    body_json: Optional[Dict] = None
    if state.get("body_lines"):
        try:
            body_json = json.loads(" ".join(state["body_lines"]))
        except (json.JSONDecodeError, ValueError):
            body_json = None
    call_id = _sha256(f"{time.monotonic()}{state.get('url', '')}")[:16]
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
# File-based parser helpers
# ---------------------------------------------------------------------------

def parse_logcat_file(path: Path) -> List[CapturedCall]:
    """Parse a saved logcat dump file and return all detected LLM calls."""
    calls: List[CapturedCall] = []
    state: Dict = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            result = parse_logcat_line(raw_line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls


def load_jsonl(path: Path) -> List[CapturedCall]:
    """Load a previously exported JSONL captures file."""
    calls: List[CapturedCall] = []
    with path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if raw_line:
                calls.append(CapturedCall.from_dict(json.loads(raw_line)))
    return calls


# ---------------------------------------------------------------------------
# AndroidCapture — live capture session
# ---------------------------------------------------------------------------

class AndroidCapture:
    """Live capture session driven by ``adb logcat``.

    Parameters
    ----------
    device_serial:
        ADB device serial.  ``None`` uses the sole connected device.
    tag_filter:
        Logcat tag used to filter output (default ``"OkHttp"``).

    Examples
    --------
    >>> cap = AndroidCapture(device_serial="emulator-5554")
    >>> cap.start()
    >>> for call in cap.stream():
    ...     print(call.provider, call.url)
    >>> cap.stop()
    >>> cap.export_jsonl(Path("session.jsonl"))
    """

    def __init__(
        self,
        device_serial: Optional[str] = None,
        tag_filter: str = "OkHttp",
    ) -> None:
        self.adb = ADBClient(device_serial)
        self.tag_filter = tag_filter
        self.calls: List[CapturedCall] = []
        self._proc = None

    def start(self) -> None:
        """Launch the adb logcat subprocess."""
        self._proc = self.adb.logcat_popen(self.tag_filter)

    def stop(self) -> None:
        """Terminate the logcat subprocess."""
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """Yield :class:`CapturedCall` objects as they are detected."""
        if not self._proc:
            raise RuntimeError("Call start() before stream().")
        state: Dict = {}
        assert self._proc.stdout is not None
        for raw_line in self._proc.stdout:
            result = parse_logcat_line(raw_line, state)
            if result:
                self.calls.append(result)
                yield result

    def export_jsonl(self, path: Path) -> None:
        """Write all captured calls to *path* in JSONL format."""
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")

    @staticmethod
    def load_jsonl(path: Path) -> List[CapturedCall]:
        """Load a previously exported JSONL file."""
        return load_jsonl(path)
