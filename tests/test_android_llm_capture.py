"""
Tests for android_llm_capture.

Covers public API imports, data structures, the logcat parser (both
individual-line and file-level), provider detection, token estimation,
and the CLI entry points — all without requiring a real ADB device.
"""

import json
import sys
import pathlib
import tempfile
import textwrap

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import android_llm_capture as alc


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

def test_import():
    assert hasattr(alc, "LLMCapture")


def test_captured_call_class():
    assert hasattr(alc, "CapturedCall")


def test_list_devices_callable():
    assert callable(alc.list_devices)


def test_list_packages_callable():
    assert callable(alc.list_packages)


def test_android_capture_alias():
    assert alc.AndroidCapture is alc.CaptureSession


def test_llm_capture_alias():
    assert alc.LLMCapture is alc.CaptureSession


def test_cli_alias():
    assert alc._cli is alc.main


# ---------------------------------------------------------------------------
# _detect_provider
# ---------------------------------------------------------------------------

def test_detect_openai():
    assert alc._detect_provider("https://api.openai.com/v1/chat/completions") == "openai"


def test_detect_anthropic():
    assert alc._detect_provider("https://api.anthropic.com/v1/messages") == "anthropic"


def test_detect_google():
    url = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent"
    assert alc._detect_provider(url) == "google"


def test_detect_unknown():
    assert alc._detect_provider("https://example.com/api") is None


def test_detect_case_insensitive():
    assert alc._detect_provider("https://API.OPENAI.COM/V1/chat") == "openai"


# ---------------------------------------------------------------------------
# CapturedCall construction and properties
# ---------------------------------------------------------------------------

def _make_call(**kwargs):
    defaults = dict(
        call_id="abc123",
        timestamp=1_700_000_000.0,
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
        response_status=200,
        response_body='{"id":"chatcmpl-123","choices":[]}',
        source="logcat",
    )
    defaults.update(kwargs)
    return alc.CapturedCall(**defaults)


def test_captured_call_model_property():
    call = _make_call()
    assert call.model == "gpt-4"


def test_captured_call_model_none_when_no_body():
    call = _make_call(request_body=None)
    assert call.model is None


def test_captured_call_hashes_computed():
    call = _make_call()
    assert len(call.request_hash) == 64
    assert len(call.response_hash) == 64


def test_captured_call_hashes_differ_with_different_body():
    c1 = _make_call(request_body={"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]})
    c2 = _make_call(request_body={"model": "gpt-4", "messages": [{"role": "user", "content": "Bye"}]})
    assert c1.request_hash != c2.request_hash


def test_captured_call_to_jsonl_roundtrip():
    call = _make_call()
    jsonl = call.to_jsonl()
    obj = json.loads(jsonl)
    assert obj["call_id"] == call.call_id
    assert obj["provider"] == "openai"
    assert obj["request_hash"] == call.request_hash
    assert obj["response_hash"] == call.response_hash


def test_captured_call_to_dict_has_all_fields():
    call = _make_call()
    d = call.to_dict()
    for key in ("call_id", "timestamp", "provider", "url", "method",
                 "request_body", "response_status", "response_body",
                 "source", "request_hash", "response_hash"):
        assert key in d, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# prompt_tokens_estimate
# ---------------------------------------------------------------------------

def test_prompt_tokens_string_content():
    call = _make_call(
        request_body={"messages": [{"role": "user", "content": "one two three four"}]}
    )
    # 4 words → max(1, 4 * 4 // 3) = 5
    assert call.prompt_tokens_estimate == 5


def test_prompt_tokens_multimodal_content():
    call = _make_call(
        request_body={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe this"},
                        {"type": "image_url", "image_url": {"url": "data:image/..."}},
                    ],
                }
            ]
        }
    )
    # "describe this" = 2 words → max(1, 2*4//3) = 2
    assert call.prompt_tokens_estimate == 2


def test_prompt_tokens_no_body():
    call = _make_call(request_body=None)
    assert call.prompt_tokens_estimate == 0


# ---------------------------------------------------------------------------
# parse_logcat_line — request → response pairing
# ---------------------------------------------------------------------------

_LOGCAT_LINES = [
    'I/OkHttp: --> POST https://api.openai.com/v1/chat/completions',
    'I/OkHttp: {"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}',
    'I/OkHttp: <-- 200 OK https://api.openai.com/v1/chat/completions',
    'I/OkHttp: {"id":"chatcmpl-9","choices":[{"message":{"content":"Hello!"}}]}',
]


def _run_parser(lines):
    state = {}
    results = []
    for line in lines:
        result = alc.parse_logcat_line(line, state)
        if result:
            results.append(result)
    return results


def test_parse_logcat_detects_call():
    calls = _run_parser(_LOGCAT_LINES)
    assert len(calls) == 1


def test_parse_logcat_provider():
    calls = _run_parser(_LOGCAT_LINES)
    assert calls[0].provider == "openai"


def test_parse_logcat_method():
    calls = _run_parser(_LOGCAT_LINES)
    assert calls[0].method == "POST"


def test_parse_logcat_response_status():
    calls = _run_parser(_LOGCAT_LINES)
    assert calls[0].response_status == 200


def test_parse_logcat_request_body_parsed():
    calls = _run_parser(_LOGCAT_LINES)
    assert calls[0].request_body is not None
    assert calls[0].request_body.get("model") == "gpt-4"


def test_parse_logcat_response_body_present():
    calls = _run_parser(_LOGCAT_LINES)
    assert "chatcmpl-9" in (calls[0].response_body or "")


def test_parse_logcat_empty_line_returns_none():
    state: dict = {}
    assert alc.parse_logcat_line("", state) is None


def test_parse_logcat_irrelevant_line_returns_none():
    state: dict = {}
    result = alc.parse_logcat_line("I/SomeOtherTag: random log message", state)
    assert result is None


def test_parse_logcat_unknown_provider_ignored():
    """Requests to non-LLM URLs should not create state."""
    state: dict = {}
    alc.parse_logcat_line(
        "I/OkHttp: --> POST https://example.com/api/data", state
    )
    assert "url" not in state


def test_parse_logcat_multiple_calls():
    lines = _LOGCAT_LINES + _LOGCAT_LINES
    calls = _run_parser(lines)
    assert len(calls) == 2


def test_parse_logcat_anthropic():
    lines = [
        "I/OkHttp: --> POST https://api.anthropic.com/v1/messages",
        'I/OkHttp: {"model":"claude-3-opus-20240229","messages":[{"role":"user","content":"Hi"}]}',
        "I/OkHttp: <-- 200 OK https://api.anthropic.com/v1/messages",
        'I/OkHttp: {"id":"msg_01","content":[{"type":"text","text":"Hello"}]}',
    ]
    calls = _run_parser(lines)
    assert len(calls) == 1
    assert calls[0].provider == "anthropic"
    assert calls[0].model == "claude-3-opus-20240229"


# ---------------------------------------------------------------------------
# parse_logcat_file
# ---------------------------------------------------------------------------

def test_parse_logcat_file():
    content = "\n".join(_LOGCAT_LINES)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        fname = f.name
    calls = alc.parse_logcat_file(pathlib.Path(fname))
    assert len(calls) == 1
    assert calls[0].source == "file"


def test_parse_logcat_file_empty():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("")
        fname = f.name
    calls = alc.parse_logcat_file(pathlib.Path(fname))
    assert calls == []


# ---------------------------------------------------------------------------
# CLI — stats subcommand
# ---------------------------------------------------------------------------

def test_cli_stats():
    call = _make_call()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False
    ) as f:
        f.write(call.to_jsonl() + "\n")
        fname = f.name
    rc = alc.main(["stats", fname])
    assert rc == 0


def test_cli_file_subcommand():
    content = "\n".join(_LOGCAT_LINES)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fin:
        fin.write(content)
        inname = fin.name
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as fout:
        outname = fout.name
    rc = alc.main(["file", inname, "-o", outname])
    assert rc == 0
    with open(outname, encoding="utf-8") as fh:
        lines = [l for l in fh if l.strip()]
    assert len(lines) == 1


def test_cli_file_missing():
    rc = alc.main(["file", "/nonexistent/path/logcat.log"])
    assert rc == 1


def test_cli_no_subcommand():
    rc = alc.main([])
    assert rc == 1
