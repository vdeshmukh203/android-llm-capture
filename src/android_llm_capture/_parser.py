"""Stateful logcat line parser for OkHttp and Cronet LLM traffic."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Dict, Optional

from ._models import CapturedCall

# ---------------------------------------------------------------------------
# Provider URL patterns
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

_OKHTTP_REQUEST  = re.compile(r'--> (?P<method>POST|GET|PUT|PATCH) (?P<url>https?://\S+)')
_OKHTTP_RESPONSE = re.compile(r'<-- (?P<status>\d{3}) \S+ (?P<url>https?://\S+)')
_OKHTTP_END      = re.compile(r'<-- END HTTP')
_OKHTTP_BODY     = re.compile(r'(?P<body>\{.*\}|\[.*\])')
_CRONET_URL      = re.compile(
    r'(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)',
    re.IGNORECASE,
)


def _detect_provider(url: str) -> Optional[str]:
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _make_call_id() -> str:
    return secrets.token_hex(8)


def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """Stateful parser for a single logcat line; mutates *state*.

    Returns a :class:`CapturedCall` when a complete request+response pair is
    detected, otherwise returns ``None``.
    """
    line = line.strip()
    if not line:
        return None

    # OkHttp request start — always takes priority, resets state
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

    # OkHttp/Cronet response status line — check BEFORE request-body block so
    # that a response line is never silently swallowed while in request phase.
    m_resp = _OKHTTP_RESPONSE.search(line)
    if m_resp and state.get("url"):
        resp_url = m_resp.group("url")
        base_url = state["url"].split("?")[0]
        if _detect_provider(resp_url) or resp_url.startswith(base_url):
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
        return None

    # Request body accumulation
    if state.get("phase") == "request":
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["body_lines"].append(m_body.group("body"))
        return None

    # Response body / end-of-response
    if state.get("phase") == "response":
        if _OKHTTP_END.search(line):
            call = _finalise_call(state, None)
            state.clear()
            return call
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            call = _finalise_call(state, m_body.group("body"))
            state.clear()
            return call
        return None

    # Cronet URL detection (sets up request state)
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
    body_json = None
    if state.get("body_lines"):
        raw = " ".join(state["body_lines"])
        try:
            body_json = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            pass
    return CapturedCall(
        call_id=_make_call_id(),
        timestamp=time.time(),
        provider=state.get("provider", "unknown"),
        url=state.get("url", ""),
        method=state.get("method", "POST"),
        request_body=body_json,
        response_status=state.get("response_status"),
        response_body=response_body,
        source="logcat",
    )


def parse_logcat_file(path) -> list:
    """Parse a saved logcat dump file and return all detected LLM calls."""
    from pathlib import Path

    calls = []
    state: Dict = {}
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result = parse_logcat_line(line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls
