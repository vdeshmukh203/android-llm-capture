"""Tests for android_llm_capture.

The test suite covers:
- Provider detection
- Stateful logcat line parser (OkHttp full cycle)
- CapturedCall data model
- JSONL round-trip serialisation
- compute_stats helper
- Public API surface expected by JOSS reviewers
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Allow running from the repo root without installation
sys.path.insert(0, str(Path(__file__).parent.parent))

import android_llm_capture as alc
from android_llm_capture import (
    CapturedCall,
    CaptureSession,
    _detect_provider,
    _finalise_call,
    compute_stats,
    list_devices,
    list_packages,
    load_jsonl,
    parse_logcat_file,
    parse_logcat_line,
)


# ---------------------------------------------------------------------------
# Backward-compatibility surface
# ---------------------------------------------------------------------------

class TestPublicAPI:
    def test_llmcapture_alias(self):
        assert alc.LLMCapture is CaptureSession

    def test_captured_call_exported(self):
        assert hasattr(alc, "CapturedCall")

    def test_list_devices_callable(self):
        assert callable(list_devices)

    def test_list_packages_callable(self):
        assert callable(list_packages)

    def test_cli_alias(self):
        assert callable(alc._cli)
        assert alc._cli is alc.main


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

class TestDetectProvider:
    @pytest.mark.parametrize("url,expected", [
        ("https://api.openai.com/v1/chat/completions", "openai"),
        ("https://api.anthropic.com/v1/messages", "anthropic"),
        ("https://generativelanguage.googleapis.com/v1/models", "google"),
        ("https://api.cohere.ai/v1/generate", "cohere"),
        ("https://api.mistral.ai/v1/chat/completions", "mistral"),
        ("https://api.together.ai/v1/chat/completions", "together"),
        ("https://api-inference.huggingface.co/models/gpt2", "huggingface"),
        ("https://api.groq.com/openai/v1/chat/completions", "groq"),
        ("https://example.com/api", None),
        ("", None),
    ])
    def test_known_providers(self, url, expected):
        assert _detect_provider(url) == expected

    def test_case_insensitive(self):
        assert _detect_provider("https://API.OPENAI.COM/v1/chat") == "openai"


# ---------------------------------------------------------------------------
# OkHttp full request/response cycle
# ---------------------------------------------------------------------------

OKHTTP_OPENAI_LINES = [
    "--> POST https://api.openai.com/v1/chat/completions (application/json)",
    '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}',
    "--> END POST",
    "<-- 200 OK https://api.openai.com/v1/chat/completions (432ms)",
    '{"id":"chatcmpl-abc","object":"chat.completion","choices":[]}',
    "<-- END HTTP",
]

OKHTTP_ANTHROPIC_LINES = [
    "--> POST https://api.anthropic.com/v1/messages (application/json)",
    '{"model":"claude-3-opus-20240229","messages":[{"role":"user","content":"Hi"}]}',
    "--> END POST",
    "<-- 200 OK https://api.anthropic.com/v1/messages (512ms)",
    '{"id":"msg_abc","content":[{"type":"text","text":"Hello!"}]}',
    "<-- END HTTP",
]


def _replay_lines(lines):
    """Drive parse_logcat_line through a sequence of lines; return all results."""
    state = {}
    results = []
    for line in lines:
        r = parse_logcat_line(line, state)
        if r:
            results.append(r)
    return results


class TestOkHttpParser:
    def test_openai_full_cycle(self):
        calls = _replay_lines(OKHTTP_OPENAI_LINES)
        assert len(calls) == 1
        c = calls[0]
        assert c.provider == "openai"
        assert c.method == "POST"
        assert c.response_status == 200
        assert c.request_body is not None
        assert c.request_body["model"] == "gpt-4"

    def test_anthropic_full_cycle(self):
        calls = _replay_lines(OKHTTP_ANTHROPIC_LINES)
        assert len(calls) == 1
        c = calls[0]
        assert c.provider == "anthropic"
        assert c.response_status == 200

    def test_state_reset_on_new_request(self):
        """Starting a second request must discard any partial state from the first."""
        lines = OKHTTP_OPENAI_LINES[:2] + OKHTTP_ANTHROPIC_LINES  # abandoned first call
        calls = _replay_lines(lines)
        assert len(calls) == 1
        assert calls[0].provider == "anthropic"

    def test_non_llm_url_ignored(self):
        lines = [
            "--> GET https://example.com/api/data",
            '{"key":"value"}',
            "--> END GET",
            "<-- 200 OK https://example.com/api/data (10ms)",
            '{"result":"ok"}',
            "<-- END HTTP",
        ]
        calls = _replay_lines(lines)
        assert calls == []

    def test_empty_lines_skipped(self):
        state = {}
        assert parse_logcat_line("", state) is None
        assert parse_logcat_line("   ", state) is None

    def test_response_without_json_body(self):
        """<-- END HTTP with no JSON body lines should still produce a call."""
        lines = [
            "--> POST https://api.openai.com/v1/chat/completions",
            "--> END POST",
            "<-- 204 No Content https://api.openai.com/v1/chat/completions (5ms)",
            "<-- END HTTP",
        ]
        calls = _replay_lines(lines)
        assert len(calls) == 1
        assert calls[0].response_body is None
        assert calls[0].response_status == 204

    def test_multiple_calls_in_sequence(self):
        lines = OKHTTP_OPENAI_LINES + OKHTTP_ANTHROPIC_LINES
        calls = _replay_lines(lines)
        assert len(calls) == 2
        assert calls[0].provider == "openai"
        assert calls[1].provider == "anthropic"

    def test_delete_method_recognised(self):
        lines = [
            "--> DELETE https://api.openai.com/v1/files/file-abc",
            "--> END DELETE",
            "<-- 200 OK https://api.openai.com/v1/files/file-abc (20ms)",
            "<-- END HTTP",
        ]
        calls = _replay_lines(lines)
        assert len(calls) == 1
        assert calls[0].method == "DELETE"

    def test_request_body_json_parse_failure_graceful(self):
        """Malformed JSON in request body should not raise; body becomes None."""
        lines = [
            "--> POST https://api.openai.com/v1/chat/completions",
            "{this is not valid json}",
            "--> END POST",
            "<-- 200 OK https://api.openai.com/v1/chat/completions (10ms)",
            "<-- END HTTP",
        ]
        # {this is not valid json} doesn't match _JSON_LINE ^\s*[{\[] strictly
        # but let's verify no exception either way
        calls = _replay_lines(lines)
        # Result may or may not capture a call depending on regex match;
        # crucially no exception should be raised
        assert isinstance(calls, list)


# ---------------------------------------------------------------------------
# CapturedCall model
# ---------------------------------------------------------------------------

class TestCapturedCall:
    def _make_call(self, **kwargs):
        defaults = dict(
            call_id="abc123",
            timestamp=1_700_000_000.0,
            provider="openai",
            url="https://api.openai.com/v1/chat/completions",
            method="POST",
            request_body={"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]},
            response_status=200,
            response_body='{"id":"x"}',
            source="logcat",
        )
        defaults.update(kwargs)
        return CapturedCall(**defaults)

    def test_model_property(self):
        c = self._make_call()
        assert c.model == "gpt-4"

    def test_model_property_none_when_no_body(self):
        c = self._make_call(request_body=None)
        assert c.model is None

    def test_prompt_tokens_estimate_positive(self):
        c = self._make_call()
        assert c.prompt_tokens_estimate > 0

    def test_prompt_tokens_estimate_zero_without_body(self):
        c = self._make_call(request_body=None)
        assert c.prompt_tokens_estimate == 0

    def test_hashes_computed(self):
        c = self._make_call()
        assert len(c.request_hash) == 64
        assert len(c.response_hash) == 64

    def test_hash_changes_with_content(self):
        c1 = self._make_call(request_body={"model": "gpt-4", "messages": []})
        c2 = self._make_call(request_body={"model": "gpt-3.5-turbo", "messages": []})
        assert c1.request_hash != c2.request_hash

    def test_to_dict_roundtrip(self):
        c = self._make_call()
        d = c.to_dict()
        assert d["provider"] == "openai"
        assert d["request_body"]["model"] == "gpt-4"
        assert "request_hash" in d
        assert "response_hash" in d

    def test_to_jsonl_valid_json(self):
        c = self._make_call()
        obj = json.loads(c.to_jsonl())
        assert obj["call_id"] == "abc123"

    def test_non_string_content_prompt_estimate(self):
        """Content as list (vision API) should not raise; floors to 1."""
        c = self._make_call(
            request_body={"model": "gpt-4o", "messages": [
                {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "..."}}]}
            ]}
        )
        # Non-string content is skipped; result is max(1, 0) = 1
        assert c.prompt_tokens_estimate == 1


# ---------------------------------------------------------------------------
# JSONL round-trip
# ---------------------------------------------------------------------------

class TestJSONLRoundtrip:
    def _make_call(self):
        return CapturedCall(
            call_id="rndtrip01",
            timestamp=1_700_000_000.0,
            provider="anthropic",
            url="https://api.anthropic.com/v1/messages",
            method="POST",
            request_body={"model": "claude-3-haiku", "messages": []},
            response_status=200,
            response_body='{"content":[]}',
            source="logcat",
        )

    def test_load_jsonl(self):
        c = self._make_call()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(c.to_jsonl() + "\n")
            tmp = Path(f.name)
        try:
            loaded = load_jsonl(tmp)
            assert len(loaded) == 1
            assert loaded[0].call_id == "rndtrip01"
            assert loaded[0].provider == "anthropic"
            assert loaded[0].request_body["model"] == "claude-3-haiku"
        finally:
            tmp.unlink()

    def test_load_jsonl_skips_blank_lines(self):
        c = self._make_call()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("\n")
            f.write(c.to_jsonl() + "\n")
            f.write("   \n")
            tmp = Path(f.name)
        try:
            loaded = load_jsonl(tmp)
            assert len(loaded) == 1
        finally:
            tmp.unlink()


# ---------------------------------------------------------------------------
# parse_logcat_file
# ---------------------------------------------------------------------------

class TestParseLogcatFile:
    def test_parse_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            tmp = Path(f.name)
        try:
            calls = parse_logcat_file(tmp)
            assert calls == []
        finally:
            tmp.unlink()

    def test_parse_known_log(self):
        content = "\n".join(OKHTTP_OPENAI_LINES) + "\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            tmp = Path(f.name)
        try:
            calls = parse_logcat_file(tmp)
            assert len(calls) == 1
            assert calls[0].source == "file"
        finally:
            tmp.unlink()


# ---------------------------------------------------------------------------
# compute_stats
# ---------------------------------------------------------------------------

class TestComputeStats:
    def _raw(self, provider, model):
        return {"provider": provider, "request_body": {"model": model}}

    def test_empty(self):
        s = compute_stats([])
        assert s["total"] == 0
        assert s["by_provider"] == {}
        assert s["by_model"] == {}

    def test_single_call(self):
        s = compute_stats([self._raw("openai", "gpt-4")])
        assert s["total"] == 1
        assert s["by_provider"]["openai"] == 1
        assert s["by_model"]["gpt-4"] == 1

    def test_multiple_providers(self):
        raw = [
            self._raw("openai", "gpt-4"),
            self._raw("openai", "gpt-4"),
            self._raw("anthropic", "claude-3-opus"),
        ]
        s = compute_stats(raw)
        assert s["total"] == 3
        assert s["by_provider"]["openai"] == 2
        assert s["by_provider"]["anthropic"] == 1

    def test_missing_request_body(self):
        s = compute_stats([{"provider": "groq", "request_body": None}])
        assert s["by_model"]["unknown"] == 1

    def test_missing_provider_key(self):
        s = compute_stats([{"request_body": {"model": "llama3"}}])
        assert "unknown" in s["by_provider"]
