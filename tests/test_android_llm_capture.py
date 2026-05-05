"""Tests for android_llm_capture.

The test suite imports from the *installed* package (src/ layout).  When
running against an editable install (``pip install -e .``) or after
``pip install -e .[dev]``, the src/ package takes precedence automatically.
The path manipulation below ensures tests work without installation too.
"""
from __future__ import annotations

import json
import pathlib
import sys

# Allow running without installation: add src/ to the path.
_SRC = pathlib.Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import android_llm_capture as alc
from android_llm_capture.models import CapturedCall
from android_llm_capture.parser import detect_provider, parse_logcat_line

# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

def test_import_llmcapture():
    assert hasattr(alc, "LLMCapture")


def test_import_captured_call():
    assert hasattr(alc, "CapturedCall")


def test_list_devices_callable():
    assert callable(alc.list_devices)


def test_list_packages_callable():
    assert callable(alc.list_packages)


def test_adb_client_exposed():
    assert hasattr(alc, "ADBClient")
    assert callable(alc.ADBClient.list_devices)


def test_parse_logcat_file_exposed():
    assert callable(alc.parse_logcat_file)


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

def test_detect_openai():
    assert detect_provider("https://api.openai.com/v1/chat/completions") == "openai"


def test_detect_anthropic():
    assert detect_provider("https://api.anthropic.com/v1/messages") == "anthropic"


def test_detect_google():
    assert detect_provider(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    ) == "google"


def test_detect_groq():
    assert detect_provider("https://api.groq.com/openai/v1/chat/completions") == "groq"


def test_detect_unknown_returns_none():
    assert detect_provider("https://example.com/api/v1/generate") is None


def test_detect_case_insensitive():
    assert detect_provider("HTTPS://API.OPENAI.COM/v1/chat/completions") == "openai"


# ---------------------------------------------------------------------------
# Logcat parser — state machine
# ---------------------------------------------------------------------------

def _simulate(lines):
    """Run a sequence of logcat lines through the parser and collect results."""
    state: dict = {}
    results = []
    for line in lines:
        r = parse_logcat_line(line, state)
        if r is not None:
            results.append(r)
    return results


def test_parser_basic_call():
    calls = _simulate([
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model":"gpt-4","messages":[]}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (312ms)",
        '{"id":"x","choices":[]}',
    ])
    assert len(calls) == 1
    c = calls[0]
    assert c.provider == "openai"
    assert c.method == "POST"
    assert c.response_status == 200


def test_parser_response_detected_from_request_phase():
    """The response line must be processed even when state is still 'request'."""
    calls = _simulate([
        "--> POST https://api.openai.com/v1/chat/completions",
        # no body line — go straight to response
        "<-- 200 OK https://api.openai.com/v1/chat/completions (1ms)",
        '{"id":"y","choices":[]}',
    ])
    assert len(calls) == 1
    assert calls[0].response_status == 200


def test_parser_request_body_parsed():
    calls = _simulate([
        "--> POST https://api.anthropic.com/v1/messages",
        '{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}',
        "<-- 200 OK https://api.anthropic.com/v1/messages (800ms)",
        '{"id":"msg_01","content":[{"text":"hello"}]}',
    ])
    assert len(calls) == 1
    c = calls[0]
    assert c.provider == "anthropic"
    assert c.model == "claude-3-5-sonnet-20241022"
    assert c.prompt_tokens_estimate > 0


def test_parser_unknown_provider_ignored():
    state: dict = {}
    result = parse_logcat_line("--> POST https://example.com/api", state)
    assert result is None
    assert state == {}


def test_parser_empty_line_ignored():
    state: dict = {}
    assert parse_logcat_line("", state) is None
    assert parse_logcat_line("   \n", state) is None


def test_parser_two_sequential_calls():
    lines = [
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model":"gpt-3.5-turbo","messages":[]}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (100ms)",
        '{"id":"a","choices":[]}',
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model":"gpt-4","messages":[]}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (500ms)",
        '{"id":"b","choices":[]}',
    ]
    calls = _simulate(lines)
    assert len(calls) == 2
    assert calls[0].model == "gpt-3.5-turbo"
    assert calls[1].model == "gpt-4"


# ---------------------------------------------------------------------------
# CapturedCall dataclass
# ---------------------------------------------------------------------------

def _make_call(**kwargs) -> CapturedCall:
    defaults = dict(
        call_id="test0001",
        timestamp=1_700_000_000.0,
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body={"model": "gpt-4", "messages": []},
        response_status=200,
        response_body='{"id":"x","choices":[]}',
        source="file",
    )
    defaults.update(kwargs)
    return CapturedCall(**defaults)


def test_call_hashes_computed():
    c = _make_call()
    assert len(c.request_hash) == 64
    assert len(c.response_hash) == 64


def test_call_hashes_deterministic():
    c1 = _make_call()
    c2 = _make_call()
    assert c1.request_hash == c2.request_hash
    assert c1.response_hash == c2.response_hash


def test_call_hash_changes_with_body():
    c1 = _make_call(request_body={"model": "gpt-4", "messages": []})
    c2 = _make_call(request_body={"model": "gpt-3.5-turbo", "messages": []})
    assert c1.request_hash != c2.request_hash


def test_call_model_property():
    c = _make_call(request_body={"model": "gpt-4o", "messages": []})
    assert c.model == "gpt-4o"


def test_call_model_property_no_body():
    c = _make_call(request_body=None)
    assert c.model is None


def test_call_prompt_tokens_estimate():
    c = _make_call(
        request_body={"messages": [{"role": "user", "content": "hello world foo bar"}]}
    )
    assert c.prompt_tokens_estimate > 0


def test_call_roundtrip_dict():
    original = _make_call()
    restored = CapturedCall.from_dict(original.to_dict())
    assert restored.call_id == original.call_id
    assert restored.provider == original.provider
    assert restored.request_hash == original.request_hash
    assert restored.response_hash == original.response_hash


def test_call_to_jsonl_is_valid_json():
    c = _make_call()
    obj = json.loads(c.to_jsonl())
    assert obj["call_id"] == "test0001"
    assert obj["provider"] == "openai"


# ---------------------------------------------------------------------------
# parse_logcat_file
# ---------------------------------------------------------------------------

def test_parse_logcat_file_empty(tmp_path):
    f = tmp_path / "empty.log"
    f.write_text("", encoding="utf-8")
    assert alc.parse_logcat_file(f) == []


def test_parse_logcat_file_one_call(tmp_path):
    log = "\n".join([
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (400ms)",
        '{"id":"cmpl-abc","choices":[{"message":{"content":"hi"}}]}',
    ]) + "\n"
    f = tmp_path / "test.log"
    f.write_text(log, encoding="utf-8")
    calls = alc.parse_logcat_file(f)
    assert len(calls) == 1
    c = calls[0]
    assert c.source == "file"
    assert c.provider == "openai"
    assert c.model == "gpt-4"
    assert c.response_status == 200


def test_parse_logcat_file_ignores_non_llm_lines(tmp_path):
    log = "\n".join([
        "D/System: random log line",
        "I/OkHttp: --> POST https://maps.googleapis.com/maps/api/geocode/json",
        '{"address":"1 Main St"}',
        "<-- 200 OK https://maps.googleapis.com/maps/api/geocode/json (50ms)",
        '{"results":[]}',
        "W/ViewGroup: some warning",
    ]) + "\n"
    f = tmp_path / "noise.log"
    f.write_text(log, encoding="utf-8")
    calls = alc.parse_logcat_file(f)
    assert calls == []
