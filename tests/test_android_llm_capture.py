"""
Tests for android_llm_capture.

Run with:  pytest tests/ -v
"""

from __future__ import annotations

import json
import pathlib
import sys
import textwrap
import time
import unittest.mock as mock

import pytest

# Allow import from project root without installation
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import android_llm_capture as alc
from android_llm_capture import (
    CapturedCall,
    CaptureSession,
    LLM_PATTERNS,
    _detect_provider,
    _sha256,
    _finalise_call,
    parse_logcat_line,
    parse_logcat_file,
    load_jsonl,
    list_devices,
    list_packages,
    main,
)


# ---------------------------------------------------------------------------
# Sample logcat data
# ---------------------------------------------------------------------------

_OPENAI_LOG = textwrap.dedent("""\
    D/OkHttp: --> POST https://api.openai.com/v1/chat/completions (89-byte body)
    D/OkHttp: Content-Type: application/json; charset=UTF-8
    D/OkHttp: {"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}
    D/OkHttp: --> END POST (89-byte body)
    D/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions (732ms, -1-byte body)
    D/OkHttp: content-type: application/json
    D/OkHttp: {"id":"chatcmpl-abc","choices":[{"message":{"role":"assistant","content":"Hi!"}}]}
    D/OkHttp: <-- END HTTP (427-byte body)
""")

_ANTHROPIC_LOG = textwrap.dedent("""\
    D/OkHttp: --> POST https://api.anthropic.com/v1/messages (120-byte body)
    D/OkHttp: {"model":"claude-3-opus-20240229","max_tokens":100,"messages":[{"role":"user","content":"Hi"}]}
    D/OkHttp: --> END POST (120-byte body)
    D/OkHttp: <-- 200 OK https://api.anthropic.com/v1/messages (1200ms, -1-byte body)
    D/OkHttp: {"id":"msg_xxx","content":[{"text":"Hello!"}]}
    D/OkHttp: <-- END HTTP (80-byte body)
""")

_GROQ_LOG = textwrap.dedent("""\
    D/OkHttp: --> POST https://api.groq.com/openai/v1/chat/completions (50-byte body)
    D/OkHttp: {"model":"llama3-8b-8192","messages":[{"role":"user","content":"Test"}]}
    D/OkHttp: --> END POST (50-byte body)
    D/OkHttp: <-- 200 OK https://api.groq.com/openai/v1/chat/completions (400ms, -1-byte body)
    D/OkHttp: {"choices":[{"message":{"content":"Response"}}]}
    D/OkHttp: <-- END HTTP (60-byte body)
""")


# ---------------------------------------------------------------------------
# _detect_provider
# ---------------------------------------------------------------------------

class TestDetectProvider:
    def test_openai(self):
        assert _detect_provider("https://api.openai.com/v1/chat/completions") == "openai"

    def test_anthropic(self):
        assert _detect_provider("https://api.anthropic.com/v1/messages") == "anthropic"

    def test_google(self):
        assert _detect_provider("https://generativelanguage.googleapis.com/v1beta/models") == "google"

    def test_cohere(self):
        assert _detect_provider("https://api.cohere.ai/v1/chat") == "cohere"

    def test_mistral(self):
        assert _detect_provider("https://api.mistral.ai/v1/chat/completions") == "mistral"

    def test_together(self):
        assert _detect_provider("https://api.together.ai/inference") == "together"

    def test_huggingface(self):
        assert _detect_provider("https://api-inference.huggingface.co/models/gpt2") == "huggingface"

    def test_groq(self):
        assert _detect_provider("https://api.groq.com/openai/v1/chat/completions") == "groq"

    def test_unknown_returns_none(self):
        assert _detect_provider("https://example.com/api/chat") is None

    def test_case_insensitive(self):
        assert _detect_provider("https://API.OPENAI.COM/v1/") == "openai"

    def test_all_providers_covered(self):
        """Every key in LLM_PATTERNS must be detectable."""
        urls = {
            "openai":      "https://api.openai.com/v1/embeddings",
            "anthropic":   "https://api.anthropic.com/v1/messages",
            "google":      "https://generativelanguage.googleapis.com/v1/models",
            "cohere":      "https://api.cohere.ai/v1/generate",
            "mistral":     "https://api.mistral.ai/v1/chat/completions",
            "together":    "https://api.together.ai/v1/chat",
            "huggingface": "https://api-inference.huggingface.co/models/bert",
            "groq":        "https://api.groq.com/openai/v1/chat/completions",
        }
        for provider, url in urls.items():
            assert _detect_provider(url) == provider, f"Failed for {provider}"


# ---------------------------------------------------------------------------
# _sha256
# ---------------------------------------------------------------------------

class TestSha256:
    def test_deterministic(self):
        assert _sha256("hello") == _sha256("hello")

    def test_different_inputs_differ(self):
        assert _sha256("hello") != _sha256("world")

    def test_output_length(self):
        assert len(_sha256("test")) == 64

    def test_empty_string(self):
        result = _sha256("")
        assert isinstance(result, str) and len(result) == 64


# ---------------------------------------------------------------------------
# CapturedCall
# ---------------------------------------------------------------------------

def _make_call(**overrides) -> CapturedCall:
    defaults = dict(
        call_id="abc123def456",
        timestamp=1_700_000_000.0,
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello world"}],
        },
        response_status=200,
        response_body='{"id":"chatcmpl-xxx","choices":[]}',
        source="logcat",
    )
    defaults.update(overrides)
    return CapturedCall(**defaults)


class TestCapturedCall:
    def test_model_property(self):
        call = _make_call(request_body={"model": "gpt-4o", "messages": []})
        assert call.model == "gpt-4o"

    def test_model_none_when_no_body(self):
        assert _make_call(request_body=None).model is None

    def test_model_none_when_key_missing(self):
        assert _make_call(request_body={"messages": []}).model is None

    def test_prompt_tokens_positive(self):
        call = _make_call(
            request_body={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello world"}]}
        )
        assert call.prompt_tokens_estimate >= 1

    def test_prompt_tokens_zero_when_no_body(self):
        assert _make_call(request_body=None).prompt_tokens_estimate == 0

    def test_prompt_tokens_skip_non_string_content(self):
        call = _make_call(
            request_body={"messages": [{"role": "user", "content": ["part1", "part2"]}]}
        )
        assert call.prompt_tokens_estimate == 1  # falls through to max(1, 0)

    def test_to_dict_contains_required_keys(self):
        d = _make_call().to_dict()
        for key in ("call_id", "provider", "url", "method", "request_hash", "response_hash"):
            assert key in d

    def test_to_jsonl_is_valid_json(self):
        line = _make_call().to_jsonl()
        obj = json.loads(line)
        assert obj["call_id"] == "abc123def456"

    def test_from_dict_round_trip(self):
        original = _make_call()
        reconstructed = CapturedCall.from_dict(original.to_dict())
        assert reconstructed.call_id == original.call_id
        assert reconstructed.provider == original.provider
        assert reconstructed.model == original.model
        assert reconstructed.request_body == original.request_body

    def test_from_dict_defaults_source(self):
        d = _make_call().to_dict()
        del d["source"]
        call = CapturedCall.from_dict(d)
        assert call.source == "file"

    def test_request_hash_deterministic(self):
        body = {"model": "gpt-4", "messages": []}
        c1 = _make_call(request_body=body)
        c2 = _make_call(request_body=body)
        assert c1.request_hash == c2.request_hash

    def test_different_bodies_different_hashes(self):
        c1 = _make_call(request_body={"model": "gpt-4", "messages": []})
        c2 = _make_call(request_body={"model": "gpt-3.5", "messages": []})
        assert c1.request_hash != c2.request_hash

    def test_none_body_hash_stable(self):
        c1 = _make_call(request_body=None, response_body=None)
        c2 = _make_call(request_body=None, response_body=None)
        assert c1.request_hash == c2.request_hash
        assert c1.response_hash == c2.response_hash


# ---------------------------------------------------------------------------
# parse_logcat_line — state machine
# ---------------------------------------------------------------------------

def _parse_log(log_text: str) -> list[CapturedCall]:
    state: dict = {}
    calls = []
    for line in log_text.splitlines():
        result = parse_logcat_line(line, state)
        if result:
            calls.append(result)
    return calls


class TestParseLogcatLine:
    def test_detects_openai_call(self):
        calls = _parse_log(_OPENAI_LOG)
        assert len(calls) == 1
        assert calls[0].provider == "openai"

    def test_detects_anthropic_call(self):
        calls = _parse_log(_ANTHROPIC_LOG)
        assert len(calls) == 1
        assert calls[0].provider == "anthropic"

    def test_detects_groq_call(self):
        calls = _parse_log(_GROQ_LOG)
        assert len(calls) == 1
        assert calls[0].provider == "groq"

    def test_request_method(self):
        assert _parse_log(_OPENAI_LOG)[0].method == "POST"

    def test_request_url(self):
        assert "openai.com" in _parse_log(_OPENAI_LOG)[0].url

    def test_request_body_parsed(self):
        call = _parse_log(_OPENAI_LOG)[0]
        assert call.request_body is not None
        assert call.request_body.get("model") == "gpt-4"

    def test_response_status(self):
        assert _parse_log(_OPENAI_LOG)[0].response_status == 200

    def test_response_body_captured(self):
        body = _parse_log(_OPENAI_LOG)[0].response_body
        assert body is not None
        assert "chatcmpl" in body

    def test_sequential_calls_parsed(self):
        calls = _parse_log(_OPENAI_LOG + _ANTHROPIC_LOG)
        assert len(calls) == 2
        assert calls[0].provider == "openai"
        assert calls[1].provider == "anthropic"

    def test_empty_line_returns_none(self):
        assert parse_logcat_line("", {}) is None

    def test_whitespace_line_returns_none(self):
        assert parse_logcat_line("   \t  ", {}) is None

    def test_non_llm_url_ignored(self):
        state: dict = {}
        result = parse_logcat_line(
            "D/OkHttp: --> POST https://example.com/api/chat (10-byte body)", state
        )
        assert result is None
        assert state == {}

    def test_state_cleared_after_call(self):
        state: dict = {}
        for line in _OPENAI_LOG.splitlines():
            parse_logcat_line(line, state)
        assert state == {}

    def test_irrelevant_log_line_ignored(self):
        state: dict = {}
        assert parse_logcat_line("I/System: Boot completed", state) is None

    def test_source_is_logcat(self):
        assert _parse_log(_OPENAI_LOG)[0].source == "logcat"

    def test_three_providers_in_sequence(self):
        combined = _OPENAI_LOG + _ANTHROPIC_LOG + _GROQ_LOG
        calls = _parse_log(combined)
        assert len(calls) == 3
        providers = [c.provider for c in calls]
        assert providers == ["openai", "anthropic", "groq"]


# ---------------------------------------------------------------------------
# parse_logcat_file
# ---------------------------------------------------------------------------

class TestParseLogcatFile:
    def test_parse_single_call(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        calls = parse_logcat_file(log_file)
        assert len(calls) == 1
        assert calls[0].source == "file"

    def test_source_set_to_file(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        assert parse_logcat_file(log_file)[0].source == "file"

    def test_empty_file(self, tmp_path):
        log_file = tmp_path / "empty.txt"
        log_file.write_text("", encoding="utf-8")
        assert parse_logcat_file(log_file) == []

    def test_no_llm_calls(self, tmp_path):
        log_file = tmp_path / "noise.txt"
        log_file.write_text("D/System: boot\nI/ActivityManager: started\n", encoding="utf-8")
        assert parse_logcat_file(log_file) == []

    def test_multiple_calls(self, tmp_path):
        log_file = tmp_path / "multi.txt"
        log_file.write_text(_OPENAI_LOG + _ANTHROPIC_LOG, encoding="utf-8")
        calls = parse_logcat_file(log_file)
        assert len(calls) == 2

    def test_accepts_path_object(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        calls = parse_logcat_file(log_file)  # pathlib.Path
        assert len(calls) == 1

    def test_accepts_string_path(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        calls = parse_logcat_file(str(log_file))  # str
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# load_jsonl
# ---------------------------------------------------------------------------

class TestLoadJsonl:
    def test_round_trip(self, tmp_path):
        call = _make_call()
        jsonl = tmp_path / "caps.jsonl"
        jsonl.write_text(call.to_jsonl() + "\n", encoding="utf-8")
        loaded = load_jsonl(jsonl)
        assert len(loaded) == 1
        assert loaded[0].call_id == call.call_id

    def test_skips_blank_lines(self, tmp_path):
        call = _make_call()
        jsonl = tmp_path / "caps.jsonl"
        jsonl.write_text(f"\n{call.to_jsonl()}\n\n", encoding="utf-8")
        assert len(load_jsonl(jsonl)) == 1

    def test_skips_malformed_json(self, tmp_path):
        call = _make_call()
        jsonl = tmp_path / "caps.jsonl"
        jsonl.write_text(f"not-json\n{call.to_jsonl()}\n", encoding="utf-8")
        loaded = load_jsonl(jsonl)
        assert len(loaded) == 1  # malformed line skipped

    def test_multiple_calls(self, tmp_path):
        calls = [_make_call(call_id=f"id{i}") for i in range(3)]
        jsonl = tmp_path / "caps.jsonl"
        jsonl.write_text("\n".join(c.to_jsonl() for c in calls) + "\n", encoding="utf-8")
        loaded = load_jsonl(jsonl)
        assert len(loaded) == 3


# ---------------------------------------------------------------------------
# list_devices / list_packages
# ---------------------------------------------------------------------------

class TestListDevices:
    def test_returns_list_of_serials(self):
        with mock.patch("subprocess.check_output") as m:
            m.return_value = "List of devices attached\nabc123\tdevice\n"
            assert list_devices() == ["abc123"]

    def test_empty_when_no_devices(self):
        with mock.patch("subprocess.check_output") as m:
            m.return_value = "List of devices attached\n"
            assert list_devices() == []

    def test_skips_offline(self):
        with mock.patch("subprocess.check_output") as m:
            m.return_value = "List of devices attached\nabc123\toffline\nxyz456\tdevice\n"
            devices = list_devices()
            assert "abc123" not in devices
            assert "xyz456" in devices

    def test_skips_unauthorized(self):
        with mock.patch("subprocess.check_output") as m:
            m.return_value = "List of devices attached\nabc123\tunauthorized\nxyz456\tdevice\n"
            assert "abc123" not in list_devices()

    def test_returns_empty_when_adb_missing(self):
        with mock.patch("subprocess.check_output", side_effect=FileNotFoundError):
            assert list_devices() == []

    def test_returns_empty_on_timeout(self):
        with mock.patch("subprocess.check_output", side_effect=subprocess.TimeoutExpired("adb", 10)):
            assert list_devices() == []


class TestListPackages:
    def test_returns_package_names(self):
        with mock.patch("subprocess.check_output") as m:
            m.return_value = "package:com.example.app\npackage:com.another.app\n"
            pkgs = list_packages()
        assert "com.example.app" in pkgs
        assert "com.another.app" in pkgs

    def test_empty_on_error(self):
        with mock.patch("subprocess.check_output", side_effect=Exception):
            assert list_packages() == []

    def test_passes_device_serial(self):
        with mock.patch("subprocess.check_output") as m:
            m.return_value = ""
            list_packages(device="abc123")
            cmd = m.call_args[0][0]
        assert "-s" in cmd
        assert "abc123" in cmd


# ---------------------------------------------------------------------------
# CLI — main()
# ---------------------------------------------------------------------------

class TestCLI:
    def test_no_command_nonzero(self):
        assert main([]) != 0

    def test_version_exits_zero(self):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_file_command_produces_jsonl(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        out = tmp_path / "out.jsonl"
        rc = main(["file", str(log_file), "--output", str(out)])
        assert rc == 0
        loaded = load_jsonl(out)
        assert len(loaded) == 1
        assert loaded[0].provider == "openai"

    def test_file_command_json_flag(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        out = tmp_path / "out.json"
        rc = main(["file", str(log_file), "--output", str(out), "--json"])
        assert rc == 0
        obj = json.loads(out.read_text())
        assert isinstance(obj, list)
        assert len(obj) == 1

    def test_file_command_missing_file(self, tmp_path):
        rc = main(["file", str(tmp_path / "nonexistent.txt")])
        assert rc == 1

    def test_stats_command(self, tmp_path):
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG + _ANTHROPIC_LOG, encoding="utf-8")
        caps = tmp_path / "caps.jsonl"
        main(["file", str(log_file), "--output", str(caps)])
        rc = main(["stats", str(caps)])
        assert rc == 0

    def test_stats_missing_file(self, tmp_path):
        rc = main(["stats", str(tmp_path / "missing.jsonl")])
        assert rc == 1

    def test_replay_missing_file(self, tmp_path):
        rc = main(["replay", str(tmp_path / "missing.jsonl"), "last", "--api-key", "sk-test"])
        assert rc == 1

    def test_replay_bad_call_id(self, tmp_path):
        # Create a valid caps file then ask for a non-existent call_id
        log_file = tmp_path / "logcat.txt"
        log_file.write_text(_OPENAI_LOG, encoding="utf-8")
        caps = tmp_path / "caps.jsonl"
        main(["file", str(log_file), "--output", str(caps)])
        rc = main(["replay", str(caps), "nonexistent_id", "--api-key", "sk-test"])
        assert rc == 1

    def test_replay_empty_file(self, tmp_path):
        caps = tmp_path / "caps.jsonl"
        caps.write_text("", encoding="utf-8")
        rc = main(["replay", str(caps), "last", "--api-key", "sk-test"])
        assert rc == 1


# ---------------------------------------------------------------------------
# Module-level attributes
# ---------------------------------------------------------------------------

def test_version_attribute():
    assert hasattr(alc, "__version__")
    assert isinstance(alc.__version__, str)
    assert alc.__version__

def test_llmcapture_alias():
    assert alc.LLMCapture is alc.CaptureSession

def test_all_exports_exist():
    for name in alc.__all__:
        assert hasattr(alc, name), f"__all__ entry {name!r} missing from module"

def test_import_module_attributes():
    assert hasattr(alc, "LLM_PATTERNS")
    assert isinstance(alc.LLM_PATTERNS, dict)
    assert "openai" in alc.LLM_PATTERNS


# ---------------------------------------------------------------------------
# CaptureSession unit tests (no ADB required)
# ---------------------------------------------------------------------------

class TestCaptureSession:
    def test_start_raises_without_adb(self):
        session = CaptureSession()
        with mock.patch("subprocess.Popen", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="adb not found"):
                session.start()

    def test_stream_raises_before_start(self):
        session = CaptureSession()
        with pytest.raises(RuntimeError, match="start()"):
            list(session.stream())

    def test_stop_is_safe_before_start(self):
        session = CaptureSession()
        session.stop()  # should not raise

    def test_export_jsonl(self, tmp_path):
        session = CaptureSession()
        session.calls.append(_make_call())
        out = tmp_path / "export.jsonl"
        session.export_jsonl(out)
        loaded = load_jsonl(out)
        assert len(loaded) == 1

    def test_replay_raises_without_body(self):
        session = CaptureSession()
        call = _make_call(request_body=None)
        with pytest.raises(ValueError, match="No request body"):
            session.replay(call, api_key="sk-test")

    def test_replay_sets_anthropic_header(self, tmp_path):
        session = CaptureSession()
        call = _make_call(provider="anthropic", url="https://api.anthropic.com/v1/messages")
        captured_headers = {}

        def fake_urlopen(req, timeout=None):
            captured_headers.update(req.headers)
            raise OSError("network disabled in tests")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            try:
                session.replay(call, api_key="test-key")
            except OSError:
                pass
        assert "X-api-key" in captured_headers

    def test_replay_sets_bearer_for_openai(self, tmp_path):
        session = CaptureSession()
        call = _make_call(provider="openai")
        captured_headers = {}

        def fake_urlopen(req, timeout=None):
            captured_headers.update(req.headers)
            raise OSError("network disabled in tests")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            try:
                session.replay(call, api_key="sk-mykey")
            except OSError:
                pass
        assert "Authorization" in captured_headers
        assert "sk-mykey" in captured_headers["Authorization"]


import subprocess  # needed in TestListDevices for TimeoutExpired
