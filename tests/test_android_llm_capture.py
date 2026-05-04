"""Tests for android-llm-capture.

Run with:  pytest tests/ -v
"""
import json
import sys
import time
from pathlib import Path

# Support running tests without an editable install
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from android_llm_capture import (
    AndroidCapture,
    CapturedCall,
    LLMCapture,
    list_devices,
    list_packages,
    parse_logcat_file,
    parse_logcat_line,
)
from android_llm_capture._parser import _detect_provider, LLM_PATTERNS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_call(**kw) -> CapturedCall:
    defaults = dict(
        call_id="abc12345",
        timestamp=1_700_000_000.0,
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello, world!"}],
        },
        response_status=200,
        response_body='{"id":"chatcmpl-123","object":"chat.completion"}',
        source="logcat",
    )
    defaults.update(kw)
    return CapturedCall(**defaults)


def _parse_lines(lines):
    """Run a sequence of logcat lines through the stateful parser."""
    state = {}
    results = []
    for line in lines:
        r = parse_logcat_line(line, state)
        if r:
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

class TestProviderDetection:
    def test_openai(self):
        assert _detect_provider("https://api.openai.com/v1/chat/completions") == "openai"

    def test_anthropic(self):
        assert _detect_provider("https://api.anthropic.com/v1/messages") == "anthropic"

    def test_google(self):
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
        assert _detect_provider(url) == "google"

    def test_groq(self):
        assert _detect_provider("https://api.groq.com/openai/v1/chat/completions") == "groq"

    def test_mistral(self):
        assert _detect_provider("https://api.mistral.ai/v1/chat/completions") == "mistral"

    def test_unknown_returns_none(self):
        assert _detect_provider("https://example.com/api/v1/chat") is None

    def test_all_patterns_present(self):
        expected = {"openai", "anthropic", "google", "cohere", "mistral",
                    "together", "huggingface", "groq"}
        assert set(LLM_PATTERNS.keys()) == expected


# ---------------------------------------------------------------------------
# CapturedCall data model
# ---------------------------------------------------------------------------

class TestCapturedCall:
    def test_model_property(self):
        assert _make_call().model == "gpt-4"

    def test_model_none_when_no_body(self):
        assert _make_call(request_body=None).model is None

    def test_prompt_tokens_estimate_positive(self):
        assert _make_call().prompt_tokens_estimate > 0

    def test_prompt_tokens_zero_when_no_body(self):
        c = _make_call(request_body=None)
        assert c.prompt_tokens_estimate == 0

    def test_to_dict_keys(self):
        d = _make_call().to_dict()
        for key in ("call_id", "timestamp", "provider", "url", "method",
                    "request_body", "response_status", "response_body",
                    "source", "request_hash", "response_hash"):
            assert key in d, f"Missing key: {key}"

    def test_to_jsonl_roundtrip(self):
        c = _make_call()
        obj = json.loads(c.to_jsonl())
        assert obj["call_id"] == c.call_id
        assert obj["provider"] == c.provider
        assert obj["request_body"] == c.request_body

    def test_hashes_are_deterministic(self):
        c1 = _make_call()
        c2 = _make_call()
        assert c1.request_hash == c2.request_hash
        assert c1.response_hash == c2.response_hash

    def test_different_bodies_yield_different_hashes(self):
        c1 = _make_call(request_body={"model": "gpt-4", "messages": []})
        c2 = _make_call(request_body={"model": "gpt-3.5", "messages": []})
        assert c1.request_hash != c2.request_hash

    def test_hash_changes_with_response(self):
        c1 = _make_call(response_body='{"id":"a"}')
        c2 = _make_call(response_body='{"id":"b"}')
        assert c1.response_hash != c2.response_hash

    def test_none_body_yields_stable_hash(self):
        c1 = _make_call(request_body=None)
        c2 = _make_call(request_body=None)
        assert c1.request_hash == c2.request_hash


# ---------------------------------------------------------------------------
# Logcat parser
# ---------------------------------------------------------------------------

class TestLogcatParser:
    def test_complete_okhttp_request_response(self):
        lines = [
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1",
            'D/OkHttp: {"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}',
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (500ms)",
            'D/OkHttp: {"id":"chatcmpl-123","object":"chat.completion"}',
        ]
        results = _parse_lines(lines)
        assert len(results) == 1
        c = results[0]
        assert c.provider == "openai"
        assert c.method == "POST"
        assert c.response_status == 200
        assert c.request_body is not None
        assert c.request_body["model"] == "gpt-4"

    def test_non_llm_url_ignored(self):
        lines = [
            "D/OkHttp: --> GET https://example.com/api/data HTTP/1.1",
            "D/OkHttp: <-- 200 OK https://example.com/api/data (10ms)",
            'D/OkHttp: {"result":"ok"}',
        ]
        assert _parse_lines(lines) == []

    def test_sequential_calls_parsed_independently(self):
        lines = [
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1",
            '{"model":"gpt-4","messages":[]}',
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (100ms)",
            '{"id":"r1"}',
            "D/OkHttp: --> POST https://api.anthropic.com/v1/messages HTTP/1.1",
            '{"model":"claude-3-haiku-20240307","messages":[]}',
            "D/OkHttp: <-- 201 Created https://api.anthropic.com/v1/messages (200ms)",
            '{"id":"msg_001"}',
        ]
        results = _parse_lines(lines)
        assert len(results) == 2
        assert results[0].provider == "openai"
        assert results[1].provider == "anthropic"

    def test_malformed_json_body_yields_none_request_body(self):
        lines = [
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1",
            "{not valid json at all}",
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (100ms)",
            '{"id":"chatcmpl-123"}',
        ]
        results = _parse_lines(lines)
        assert len(results) == 1
        assert results[0].request_body is None

    def test_empty_line_is_a_noop(self):
        state = {}
        assert parse_logcat_line("", state) is None
        assert state == {}

    def test_whitespace_only_line_is_noop(self):
        state = {}
        assert parse_logcat_line("   \t  ", state) is None

    def test_response_detected_after_request_body(self):
        """Response line must NOT be swallowed while still in request phase."""
        lines = [
            "D/OkHttp: --> POST https://api.groq.com/openai/v1/chat/completions HTTP/1.1",
            '{"model":"llama3-8b-8192","messages":[{"role":"user","content":"test"}]}',
            "D/OkHttp: <-- 200 OK https://api.groq.com/openai/v1/chat/completions (300ms)",
            '{"id":"chatcmpl-abc","choices":[{"message":{"role":"assistant","content":"ok"}}]}',
        ]
        results = _parse_lines(lines)
        assert len(results) == 1
        assert results[0].response_status == 200

    def test_call_id_is_unique(self):
        lines = [
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1",
            '{"model":"gpt-4","messages":[]}',
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (100ms)",
            '{"id":"r1"}',
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1",
            '{"model":"gpt-4","messages":[]}',
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (100ms)",
            '{"id":"r2"}',
        ]
        results = _parse_lines(lines)
        assert len(results) == 2
        assert results[0].call_id != results[1].call_id

    def test_source_set_to_logcat(self):
        lines = [
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1",
            '{"model":"gpt-4","messages":[]}',
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (100ms)",
            '{"id":"r1"}',
        ]
        results = _parse_lines(lines)
        assert results[0].source == "logcat"


# ---------------------------------------------------------------------------
# File parser
# ---------------------------------------------------------------------------

class TestParseLogcatFile:
    def test_parse_empty_file(self, tmp_path):
        p = tmp_path / "empty.log"
        p.write_text("")
        assert parse_logcat_file(p) == []

    def test_parse_file_with_call(self, tmp_path):
        p = tmp_path / "test.log"
        p.write_text(
            "D/OkHttp: --> POST https://api.openai.com/v1/chat/completions HTTP/1.1\n"
            '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}\n'
            "D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (100ms)\n"
            '{"id":"chatcmpl-123"}\n'
        )
        calls = parse_logcat_file(p)
        assert len(calls) == 1
        assert calls[0].source == "file"
        assert calls[0].provider == "openai"

    def test_parse_file_with_no_llm_calls(self, tmp_path):
        p = tmp_path / "noise.log"
        p.write_text(
            "I/System: boot complete\n"
            "D/OkHttp: --> GET https://example.com/ping HTTP/1.1\n"
            "D/OkHttp: <-- 200 OK https://example.com/ping (1ms)\n"
        )
        assert parse_logcat_file(p) == []


# ---------------------------------------------------------------------------
# Backwards-compatibility imports
# ---------------------------------------------------------------------------

class TestBackwardsCompat:
    def test_llmcapture_alias(self):
        import android_llm_capture as alc
        assert hasattr(alc, "LLMCapture") or hasattr(alc, "AndroidCapture")

    def test_list_devices_callable(self):
        assert callable(list_devices)

    def test_list_packages_callable(self):
        assert callable(list_packages)

    def test_android_capture_is_same_as_capture_session(self):
        from android_llm_capture import AndroidCapture, CaptureSession
        assert AndroidCapture is CaptureSession

    def test_captured_call_importable(self):
        assert CapturedCall is not None

    def test_android_capture_instantiable(self):
        session = AndroidCapture(device_serial=None, tag_filter="OkHttp")
        assert session.tag_filter == "OkHttp"
        assert session.device_serial is None
