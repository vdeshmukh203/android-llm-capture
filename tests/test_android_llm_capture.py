"""
Tests for android_llm_capture.

Covers: provider detection, SHA-256 helper, CapturedCall data structure,
the stateful logcat line parser (including the response-before-body bug fix),
file parsing, and the public API surface expected by JOSS reviewers.
"""

import json
import sys
import time
import pathlib

# Make the project root importable when running pytest from any working dir.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import android_llm_capture as alc
from android_llm_capture import (
    CapturedCall,
    CaptureSession,
    LLMCapture,
    _detect_provider,
    _sha256,
    parse_logcat_line,
    parse_logcat_file,
    list_devices,
    list_packages,
)


# ---------------------------------------------------------------------------
# Smoke / API-surface tests
# ---------------------------------------------------------------------------

def test_import_llm_capture_alias():
    assert hasattr(alc, "LLMCapture")


def test_import_captured_call():
    assert hasattr(alc, "CapturedCall")


def test_list_devices_callable():
    assert callable(alc.list_devices)


def test_list_packages_callable():
    assert callable(alc.list_packages)


def test_cli_alias_defined():
    """_cli must exist so the pyproject.toml entry-point resolves."""
    assert hasattr(alc, "_cli")
    assert callable(alc._cli)


def test_llm_capture_is_capture_session():
    assert LLMCapture is CaptureSession


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

def test_detect_openai():
    assert _detect_provider("https://api.openai.com/v1/chat/completions") == "openai"


def test_detect_anthropic():
    assert _detect_provider("https://api.anthropic.com/v1/messages") == "anthropic"


def test_detect_google():
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    assert _detect_provider(url) == "google"


def test_detect_cohere():
    assert _detect_provider("https://api.cohere.ai/v1/generate") == "cohere"


def test_detect_mistral():
    assert _detect_provider("https://api.mistral.ai/v1/chat/completions") == "mistral"


def test_detect_together():
    assert _detect_provider("https://api.together.ai/v1/chat/completions") == "together"


def test_detect_huggingface():
    url = "https://api-inference.huggingface.co/models/gpt2"
    assert _detect_provider(url) == "huggingface"


def test_detect_groq():
    assert _detect_provider("https://api.groq.com/openai/v1/chat/completions") == "groq"


def test_detect_unknown_returns_none():
    assert _detect_provider("https://example.com/api/v1") is None


def test_detect_case_insensitive():
    assert _detect_provider("HTTPS://API.OPENAI.COM/V1/CHAT") == "openai"


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------

def test_sha256_length():
    assert len(_sha256("hello")) == 64


def test_sha256_deterministic():
    assert _sha256("hello") == _sha256("hello")


def test_sha256_different_inputs():
    assert _sha256("hello") != _sha256("world")


def test_sha256_empty_string():
    h = _sha256("")
    assert len(h) == 64


# ---------------------------------------------------------------------------
# CapturedCall data structure
# ---------------------------------------------------------------------------

def _make_call(**overrides) -> CapturedCall:
    defaults = dict(
        call_id="test0001",
        timestamp=time.time(),
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello, world!"}],
        },
        response_status=200,
        response_body='{"choices":[{"message":{"role":"assistant","content":"Hi!"}}]}',
        source="file",
    )
    defaults.update(overrides)
    return CapturedCall(**defaults)


def test_call_model_property():
    assert _make_call().model == "gpt-4"


def test_call_model_property_none():
    assert _make_call(request_body=None).model is None


def test_call_model_property_missing_key():
    assert _make_call(request_body={"messages": []}).model is None


def test_prompt_tokens_estimate_positive():
    assert _make_call().prompt_tokens_estimate > 0


def test_prompt_tokens_estimate_no_body():
    assert _make_call(request_body=None).prompt_tokens_estimate == 0


def test_request_hash_set():
    c = _make_call()
    assert len(c.request_hash) == 64


def test_response_hash_set():
    c = _make_call()
    assert len(c.response_hash) == 64


def test_hashes_change_with_content():
    c1 = _make_call()
    c2 = _make_call(response_body="different")
    assert c1.response_hash != c2.response_hash


def test_to_dict_contains_required_keys():
    d = _make_call().to_dict()
    for key in ("call_id", "provider", "url", "method", "request_body",
                "response_status", "response_body", "source",
                "request_hash", "response_hash"):
        assert key in d, f"missing key: {key}"


def test_to_jsonl_round_trip():
    c = _make_call()
    line = c.to_jsonl()
    parsed = json.loads(line)
    assert parsed["call_id"] == "test0001"
    assert parsed["provider"] == "openai"


def test_to_jsonl_is_single_line():
    line = _make_call().to_jsonl()
    assert "\n" not in line


# ---------------------------------------------------------------------------
# parse_logcat_line — stateful parser
# ---------------------------------------------------------------------------

def test_request_start_sets_state():
    state: dict = {}
    result = parse_logcat_line(
        "--> POST https://api.openai.com/v1/chat/completions", state
    )
    assert result is None
    assert state["provider"] == "openai"
    assert state["method"]   == "POST"
    assert state["phase"]    == "request"


def test_non_llm_url_ignored():
    state: dict = {}
    result = parse_logcat_line("--> POST https://example.com/api", state)
    assert result is None
    assert state == {}


def test_full_okhttp_cycle_returns_call():
    """The response-line-swallowing bug: response check must precede body block."""
    state: dict = {}
    parse_logcat_line(
        "--> POST https://api.openai.com/v1/chat/completions", state
    )
    parse_logcat_line(
        '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}', state
    )
    # This response line MUST NOT be swallowed by the request-body block.
    parse_logcat_line(
        "<-- 200 OK https://api.openai.com/v1/chat/completions (42ms)", state
    )
    assert state.get("phase") == "response", (
        "Response line was swallowed by the request-body accumulation block"
    )
    assert state.get("response_status") == 200

    result = parse_logcat_line(
        '{"choices":[{"message":{"content":"Hello"}}]}', state
    )
    assert result is not None
    assert isinstance(result, CapturedCall)
    assert result.provider        == "openai"
    assert result.response_status == 200
    assert result.method          == "POST"


def test_call_id_is_unique():
    """Each finalised call must have a distinct call_id (uuid4-based)."""
    state1: dict = {}
    state2: dict = {}
    for s in (state1, state2):
        parse_logcat_line("--> POST https://api.openai.com/v1/chat/completions", s)
        parse_logcat_line("<-- 200 OK https://api.openai.com/v1/chat/completions (1ms)", s)
    c1 = parse_logcat_line('{"choices":[]}', state1)
    c2 = parse_logcat_line('{"choices":[]}', state2)
    assert c1 is not None and c2 is not None
    assert c1.call_id != c2.call_id


def test_empty_line_returns_none():
    state: dict = {}
    assert parse_logcat_line("", state) is None
    assert parse_logcat_line("   ", state) is None


def test_irrelevant_line_returns_none():
    state: dict = {}
    assert parse_logcat_line("D/SomeTag: some random log line", state) is None


def test_cronet_url_sets_state():
    state: dict = {}
    parse_logcat_line(
        "CronetEngine request: https://api.openai.com/v1/chat/completions", state
    )
    assert state.get("provider") == "openai"
    assert state.get("phase")    == "request"
    assert state.get("method")   == "POST"


def test_request_state_cleared_on_new_request():
    """A new --> line should reset stale state from a previous call."""
    state: dict = {}
    parse_logcat_line("--> POST https://api.openai.com/v1/chat/completions", state)
    state["body_lines"] = ["stale data"]
    # Second request (e.g. a different provider) should wipe stale state.
    parse_logcat_line("--> POST https://api.anthropic.com/v1/messages", state)
    assert state["provider"]    == "anthropic"
    assert state["body_lines"]  == []


# ---------------------------------------------------------------------------
# parse_logcat_file — file-based parser
# ---------------------------------------------------------------------------

def test_parse_logcat_file_empty(tmp_path):
    f = tmp_path / "empty.log"
    f.write_text("", encoding="utf-8")
    assert parse_logcat_file(f) == []


def test_parse_logcat_file_no_llm_lines(tmp_path):
    f = tmp_path / "no_llm.log"
    f.write_text("D/Tag: something\nD/Tag: something else\n", encoding="utf-8")
    assert parse_logcat_file(f) == []


def test_parse_logcat_file_full_cycle(tmp_path):
    log = "\n".join([
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"test"}]}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (99ms)",
        '{"choices":[{"message":{"role":"assistant","content":"ok"}}]}',
    ])
    f = tmp_path / "sample.log"
    f.write_text(log, encoding="utf-8")
    calls = parse_logcat_file(f)
    assert len(calls) == 1
    assert calls[0].provider        == "openai"
    assert calls[0].response_status == 200
    assert calls[0].source          == "file"


def test_parse_logcat_file_multiple_calls(tmp_path):
    block = "\n".join([
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model":"gpt-4","messages":[{"role":"user","content":"q"}]}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (10ms)",
        '{"choices":[]}',
    ])
    f = tmp_path / "multi.log"
    f.write_text((block + "\n") * 3, encoding="utf-8")
    calls = parse_logcat_file(f)
    assert len(calls) == 3


# ---------------------------------------------------------------------------
# list_devices / list_packages — graceful degradation without ADB
# ---------------------------------------------------------------------------

def test_list_devices_returns_list():
    result = list_devices()
    assert isinstance(result, list)


def test_list_packages_returns_list():
    result = list_packages()
    assert isinstance(result, list)
