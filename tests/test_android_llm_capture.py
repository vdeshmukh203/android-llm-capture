"""
Test suite for android_llm_capture.

Covers: provider detection, JSON extraction, logcat state machine,
CapturedCall dataclass, file parser, JSONL load/save, and safe
behaviour of ADB helpers when no device is available.
"""
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import android_llm_capture as alc
from android_llm_capture import (
    CapturedCall,
    CaptureSession,
    _detect_provider,
    _extract_json_fragment,
    _sha256,
    list_devices,
    list_packages,
    load_jsonl,
    parse_logcat_file,
    parse_logcat_line,
)


# ---------------------------------------------------------------------------
# Smoke / import checks
# ---------------------------------------------------------------------------


def test_module_has_llmcapture_alias():
    assert hasattr(alc, "LLMCapture")


def test_module_has_captured_call():
    assert hasattr(alc, "CapturedCall")


def test_module_has_cli_alias():
    assert hasattr(alc, "_cli")
    assert alc._cli is alc.main


def test_list_devices_is_callable():
    assert callable(alc.list_devices)


def test_list_packages_is_callable():
    assert callable(alc.list_packages)


# ---------------------------------------------------------------------------
# _detect_provider
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("https://api.openai.com/v1/chat/completions",            "openai"),
    ("https://api.anthropic.com/v1/messages",                 "anthropic"),
    ("https://generativelanguage.googleapis.com/v1beta/models", "google"),
    ("https://api.cohere.ai/v1/generate",                     "cohere"),
    ("https://api.mistral.ai/v1/chat/completions",            "mistral"),
    ("https://api.together.ai/v1/completions",                "together"),
    ("https://api-inference.huggingface.co/models/gpt2",      "huggingface"),
    ("https://api.groq.com/openai/v1/chat/completions",       "groq"),
    ("https://example.com/api/v1",                            None),
    ("https://httpbin.org/post",                              None),
])
def test_detect_provider(url, expected):
    assert _detect_provider(url) == expected


def test_detect_provider_case_insensitive():
    assert _detect_provider("HTTPS://API.OPENAI.COM/V1/CHAT/COMPLETIONS") == "openai"


# ---------------------------------------------------------------------------
# _extract_json_fragment
# ---------------------------------------------------------------------------


def test_extract_simple_object():
    assert _extract_json_fragment('prefix {"key": "value"} suffix') == '{"key": "value"}'


def test_extract_nested_object():
    text = 'LOG: {"a": {"b": 1}} end'
    assert _extract_json_fragment(text) == '{"a": {"b": 1}}'


def test_extract_array():
    assert _extract_json_fragment("data: [1, 2, 3] end") == "[1, 2, 3]"


def test_extract_escaped_quotes_inside_string():
    text = '{"key": "val\\"ue"}'
    result = _extract_json_fragment(text)
    assert result == '{"key": "val\\"ue"}'


def test_extract_braces_inside_string_value():
    text = '{"key": "val{ue}"}'
    result = _extract_json_fragment(text)
    assert result == '{"key": "val{ue}"}'


def test_extract_returns_none_when_missing():
    assert _extract_json_fragment("no json here") is None


def test_extract_returns_none_for_empty_string():
    assert _extract_json_fragment("") is None


def test_extract_deeply_nested():
    text = '{"a": {"b": {"c": 42}}}'
    result = _extract_json_fragment(text)
    assert json.loads(result) == {"a": {"b": {"c": 42}}}


# ---------------------------------------------------------------------------
# parse_logcat_line — OkHttp state machine
# ---------------------------------------------------------------------------

_OKHTTP_SEQUENCE = [
    "D/OkHttp(1234): --> POST https://api.openai.com/v1/chat/completions http/1.1",
    'D/OkHttp(1234): {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}',
    "D/OkHttp(1234): <-- 200 OK https://api.openai.com/v1/chat/completions (123ms)",
    'D/OkHttp(1234): {"id": "chatcmpl-abc", "choices": [{"message": {"role": "assistant", "content": "Hi!"}}]}',
]


def test_parse_logcat_sequence_produces_one_call():
    state: dict = {}
    results = [r for line in _OKHTTP_SEQUENCE if (r := parse_logcat_line(line, state))]
    assert len(results) == 1


def test_parse_logcat_call_fields():
    state: dict = {}
    call = None
    for line in _OKHTTP_SEQUENCE:
        call = parse_logcat_line(line, state) or call
    assert call is not None
    assert call.provider == "openai"
    assert call.method == "POST"
    assert call.response_status == 200
    assert call.model == "gpt-4o"
    assert isinstance(call.request_body, dict)
    assert call.source == "logcat"


def test_parse_logcat_ignores_unknown_urls():
    state: dict = {}
    result = parse_logcat_line("D/OkHttp: --> POST https://example.com/api", state)
    assert result is None
    assert not state.get("url")


def test_parse_logcat_clears_state_on_new_request():
    state: dict = {}
    parse_logcat_line(
        "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions", state
    )
    assert state.get("provider") == "openai"
    # New request from a different provider should reset state
    parse_logcat_line(
        "D/OkHttp: --> POST https://api.anthropic.com/v1/messages", state
    )
    assert state.get("provider") == "anthropic"


def test_parse_logcat_empty_line_returns_none():
    state: dict = {}
    assert parse_logcat_line("", state) is None
    assert parse_logcat_line("   ", state) is None


# ---------------------------------------------------------------------------
# CapturedCall dataclass
# ---------------------------------------------------------------------------


def _make_call(**overrides) -> CapturedCall:
    defaults = dict(
        call_id="abcd1234efgh5678",
        timestamp=1_745_000_000.0,
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello world"}]},
        response_status=200,
        response_body='{"id": "x", "choices": []}',
        source="file",
    )
    defaults.update(overrides)
    return CapturedCall(**defaults)


def test_captured_call_request_hash_is_sha256():
    call = _make_call()
    assert len(call.request_hash) == 64
    assert all(c in "0123456789abcdef" for c in call.request_hash)


def test_captured_call_response_hash_is_sha256():
    call = _make_call()
    assert len(call.response_hash) == 64


def test_captured_call_hashes_differ_for_different_bodies():
    call1 = _make_call(request_body={"model": "gpt-4o", "messages": []})
    call2 = _make_call(request_body={"model": "gpt-4o-mini", "messages": []})
    assert call1.request_hash != call2.request_hash


def test_captured_call_model_property():
    call = _make_call()
    assert call.model == "gpt-4o"


def test_captured_call_model_none_when_absent():
    call = _make_call(request_body={"messages": []})
    assert call.model is None


def test_captured_call_model_none_when_no_body():
    call = _make_call(request_body=None)
    assert call.model is None


def test_captured_call_prompt_tokens_estimate_positive():
    call = _make_call()
    assert call.prompt_tokens_estimate >= 1


def test_captured_call_prompt_tokens_zero_when_no_body():
    call = _make_call(request_body=None)
    assert call.prompt_tokens_estimate == 0


def test_captured_call_to_dict_has_required_keys():
    call = _make_call()
    d = call.to_dict()
    for key in ("call_id", "timestamp", "provider", "url", "method",
                 "request_body", "response_status", "response_body",
                 "source", "request_hash", "response_hash"):
        assert key in d


def test_captured_call_to_jsonl_is_valid_json():
    call = _make_call()
    obj = json.loads(call.to_jsonl())
    assert obj["call_id"] == "abcd1234efgh5678"
    assert obj["provider"] == "openai"


# ---------------------------------------------------------------------------
# parse_logcat_file
# ---------------------------------------------------------------------------


def test_parse_logcat_file_returns_calls():
    log_content = "\n".join(_OKHTTP_SEQUENCE) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        f.write(log_content)
        tmp = Path(f.name)
    try:
        calls = parse_logcat_file(tmp)
        assert len(calls) == 1
        assert calls[0].source == "file"
        assert calls[0].provider == "openai"
    finally:
        tmp.unlink()


def test_parse_logcat_file_empty_file():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        tmp = Path(f.name)
    try:
        calls = parse_logcat_file(tmp)
        assert calls == []
    finally:
        tmp.unlink()


# ---------------------------------------------------------------------------
# load_jsonl / export round-trip
# ---------------------------------------------------------------------------


def test_load_jsonl_roundtrip():
    call = _make_call()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        f.write(call.to_jsonl() + "\n")
        tmp = Path(f.name)
    try:
        loaded = load_jsonl(tmp)
        assert len(loaded) == 1
        assert loaded[0].call_id == call.call_id
        assert loaded[0].provider == call.provider
        assert loaded[0].request_body == call.request_body
    finally:
        tmp.unlink()


def test_load_jsonl_multiple_calls():
    calls = [_make_call(call_id=f"id{i:04d}") for i in range(5)]
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        for c in calls:
            f.write(c.to_jsonl() + "\n")
        tmp = Path(f.name)
    try:
        loaded = load_jsonl(tmp)
        assert len(loaded) == 5
        assert [c.call_id for c in loaded] == [c.call_id for c in calls]
    finally:
        tmp.unlink()


def test_load_jsonl_skips_blank_lines():
    call = _make_call()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n" + call.to_jsonl() + "\n\n")
        tmp = Path(f.name)
    try:
        loaded = load_jsonl(tmp)
        assert len(loaded) == 1
    finally:
        tmp.unlink()


def test_load_jsonl_invalid_json_raises():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        f.write("not valid json\n")
        tmp = Path(f.name)
    try:
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_jsonl(tmp)
    finally:
        tmp.unlink()


# ---------------------------------------------------------------------------
# ADB helpers — safe when no device present
# ---------------------------------------------------------------------------


def test_list_devices_returns_list():
    result = list_devices()
    assert isinstance(result, list)


def test_list_packages_returns_list():
    result = list_packages()
    assert isinstance(result, list)


def test_list_packages_with_fake_device_returns_list():
    result = list_packages(device="no-such-device-xyz")
    assert isinstance(result, list)
