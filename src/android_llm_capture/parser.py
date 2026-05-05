"""Logcat line parser for detecting LLM API calls.

This module is intentionally stateful — callers pass a plain ``dict`` across
successive calls to :func:`parse_logcat_line` so that multi-line request/
response pairs can be assembled without storing global state.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional

from .models import CapturedCall, _sha256

# ---------------------------------------------------------------------------
# Provider URL patterns
# ---------------------------------------------------------------------------

#: Mapping from provider name to a compiled URL-matching pattern.
LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":       re.compile(r"api\.openai\.com/v1/",                    re.IGNORECASE),
    "anthropic":    re.compile(r"api\.anthropic\.com/",                    re.IGNORECASE),
    "google":       re.compile(r"generativelanguage\.googleapis\.com/",    re.IGNORECASE),
    "cohere":       re.compile(r"api\.cohere\.ai/",                        re.IGNORECASE),
    "mistral":      re.compile(r"api\.mistral\.ai/",                       re.IGNORECASE),
    "together":     re.compile(r"api\.together\.ai/",                      re.IGNORECASE),
    "huggingface":  re.compile(r"api-inference\.huggingface\.co/",         re.IGNORECASE),
    "groq":         re.compile(r"api\.groq\.com/",                         re.IGNORECASE),
}

# ---------------------------------------------------------------------------
# Logcat regex patterns
# ---------------------------------------------------------------------------

# OkHttp HttpLoggingInterceptor request line: "--> POST https://..."
_OKHTTP_REQUEST = re.compile(
    r"--> (?P<method>POST|GET|PUT|PATCH|DELETE) (?P<url>https?://\S+)"
)
# Inline JSON object or array on any log line
_OKHTTP_BODY = re.compile(r"(?P<body>\{.*\}|\[.*\])")
# OkHttp response line: "<-- 200 OK https://... (Nms)"
_OKHTTP_RESPONSE = re.compile(r"<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)")
# Cronet URL mention
_CRONET_URL = re.compile(
    r"(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)",
    re.IGNORECASE,
)


def detect_provider(url: str) -> Optional[str]:
    """Return the provider name for a known LLM API URL, or ``None``."""
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _build_call(state: Dict) -> CapturedCall:
    """Construct a :class:`CapturedCall` from accumulated parser state."""
    body_json: Optional[Dict] = None
    if state.get("body_lines"):
        raw = " ".join(state["body_lines"])
        try:
            body_json = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            pass
    call_id = _sha256(f"{time.time()}{state.get('url', '')}")[:16]
    return CapturedCall(
        call_id=call_id,
        timestamp=time.time(),
        provider=state.get("provider", "unknown"),
        url=state.get("url", ""),
        method=state.get("method", "POST"),
        request_body=body_json,
        response_status=state.get("response_status"),
        response_body=state.get("response_body"),
        source="logcat",
    )


def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """Process one logcat line and update *state* in place.

    Returns a :class:`CapturedCall` when a complete request/response pair is
    assembled; otherwise returns ``None``.  *state* must be a plain ``dict``
    that the caller persists across successive invocations.

    Parameters
    ----------
    line:
        A single line of logcat output (newline need not be stripped).
    state:
        Mutable accumulator dict — pass the same object for every line in a
        session.

    Returns
    -------
    CapturedCall or None
    """
    line = line.strip()
    if not line:
        return None

    # OkHttp request start: "--> POST https://..."
    m = _OKHTTP_REQUEST.search(line)
    if m:
        url = m.group("url")
        provider = detect_provider(url)
        if provider:
            # Clear any partially assembled call before starting a new one.
            state.clear()
            state.update({
                "url": url,
                "method": m.group("method"),
                "provider": provider,
                "body_lines": [],
                "phase": "request",
            })
        return None

    # Lines received while assembling the request body.
    if state.get("phase") == "request" and state.get("url"):
        # Check for the OkHttp response line first so we don't miss the
        # transition.  (Bug in earlier versions: a bare `return None` here
        # prevented response lines from ever being processed.)
        m_resp = _OKHTTP_RESPONSE.search(line)
        if m_resp:
            resp_url = m_resp.group("url")
            if detect_provider(resp_url) or resp_url == state["url"]:
                state["response_status"] = int(m_resp.group("status"))
                state["phase"] = "response"
        else:
            m_body = _OKHTTP_BODY.search(line)
            if m_body:
                state["body_lines"].append(m_body.group("body"))
        return None

    # Lines received while assembling the response body.
    if state.get("phase") == "response" and state.get("url"):
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["response_body"] = m_body.group("body")
            call = _build_call(state)
            state.clear()
            return call
        # OkHttp end-of-response marker: "<-- END HTTP (N-byte body)"
        if line.startswith("<-- END") or line == "<--":
            call = _build_call(state)
            state.clear()
            return call

    # Cronet URL mention — treat as the start of a new request.
    m_cronet = _CRONET_URL.search(line)
    if m_cronet and not state.get("url"):
        url = m_cronet.group("url")
        provider = detect_provider(url)
        if provider:
            state.clear()
            state.update({
                "url": url,
                "method": "POST",
                "provider": provider,
                "body_lines": [],
                "phase": "request",
            })

    return None


def parse_logcat_file(path: Path) -> List[CapturedCall]:
    """Parse a saved logcat dump file and return all detected LLM calls.

    Parameters
    ----------
    path:
        Path to the logcat text file.

    Returns
    -------
    list of CapturedCall
    """
    calls: List[CapturedCall] = []
    state: Dict = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result = parse_logcat_line(line, state)
            if result is not None:
                result.source = "file"
                calls.append(result)
    return calls
