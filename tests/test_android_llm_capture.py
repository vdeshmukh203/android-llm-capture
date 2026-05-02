"""Tests for android_llm_capture (root module) and src/android_llm_capture package."""
import sys
import pathlib
import json

# Ensure both the root module and the src package are importable without install.
_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))


# ---------------------------------------------------------------------------
# Root-module smoke tests (backwards-compat surface)
# ---------------------------------------------------------------------------

def test_import():
    import android_llm_capture as alc
    assert hasattr(alc, 'LLMCapture')

def test_captured_call():
    import android_llm_capture as alc
    assert hasattr(alc, 'CapturedCall')

def test_list_devices():
    import android_llm_capture as alc
    assert callable(alc.list_devices)

def test_list_packages():
    import android_llm_capture as alc
    assert callable(alc.list_packages)


# ---------------------------------------------------------------------------
# CapturedCall construction and properties
# ---------------------------------------------------------------------------

def _make_call(**kwargs):
    import android_llm_capture as alc
    defaults = dict(
        call_id="abc123",
        timestamp=1_700_000_000.0,
        provider="openai",
        url="https://api.openai.com/v1/chat/completions",
        method="POST",
        request_body=None,
        response_status=200,
        response_body=None,
        source="file",
    )
    defaults.update(kwargs)
    return alc.CapturedCall(**defaults)


def test_captured_call_hashes_computed():
    call = _make_call()
    assert isinstance(call.request_hash,  str) and len(call.request_hash)  == 64
    assert isinstance(call.response_hash, str) and len(call.response_hash) == 64


def test_captured_call_model_property():
    call = _make_call(request_body={"model": "gpt-4o", "messages": []})
    assert call.model == "gpt-4o"


def test_captured_call_model_none_when_no_body():
    call = _make_call(request_body=None)
    assert call.model is None


def test_prompt_tokens_estimate_chars_div_4():
    """Token estimate uses len(text) // 4 (OpenAI rule-of-thumb)."""
    msg = "A" * 100
    call = _make_call(request_body={"messages": [{"role": "user", "content": msg}]})
    assert call.prompt_tokens_estimate == 25   # 100 // 4


def test_prompt_tokens_estimate_no_body():
    call = _make_call(request_body=None)
    assert call.prompt_tokens_estimate == 0   # no request body → no tokens


def test_captured_call_to_dict_roundtrip():
    import android_llm_capture as alc
    original = _make_call(request_body={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    d = original.to_dict()
    restored = alc.CapturedCall.from_dict(d)
    assert restored.call_id   == original.call_id
    assert restored.provider  == original.provider
    assert restored.model     == original.model


def test_to_jsonl_is_valid_json():
    call = _make_call()
    line = call.to_jsonl()
    obj  = json.loads(line)
    assert obj["call_id"] == "abc123"


# ---------------------------------------------------------------------------
# Logcat parser — critical bug: response detection during request phase
# ---------------------------------------------------------------------------

def test_parser_detects_response_after_request():
    """
    Regression: the response <-- 200 line was previously unreachable because the
    body-accumulation block returned None for every line while phase=="request".
    """
    import android_llm_capture as alc

    lines = [
        "--> POST https://api.openai.com/v1/chat/completions (body)",
        '{"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}',
        "--> END POST (80-byte body)",
        "<-- 200 OK https://api.openai.com/v1/chat/completions (1234ms)",
        '{"id": "chatcmpl-123", "choices": [{"message": {"content": "hi"}}]}',
        "<-- END HTTP (250-byte body)",
    ]
    state: dict = {}
    result = None
    for line in lines:
        r = alc.parse_logcat_line(line, state)
        if r is not None:
            result = r

    assert result is not None, "Expected a CapturedCall but got None"
    assert result.provider == "openai"
    assert result.response_status == 200
    assert result.request_body is not None
    assert result.request_body.get("model") == "gpt-4o"


def test_parser_state_cleared_between_calls():
    """State from a previous call must not bleed into the next."""
    import android_llm_capture as alc

    block = [
        "--> POST https://api.openai.com/v1/chat/completions",
        '{"model": "gpt-4o", "messages": []}',
        "<-- 200 OK https://api.openai.com/v1/chat/completions (10ms)",
        '{"id": "1"}',
        "<-- END HTTP",
    ]
    state: dict = {}
    calls = []
    for line in block * 2:   # two identical call cycles
        r = alc.parse_logcat_line(line, state)
        if r is not None:
            calls.append(r)

    assert len(calls) == 2
    assert calls[0].call_id != calls[1].call_id


def test_parser_ignores_non_llm_urls():
    import android_llm_capture as alc
    state: dict = {}
    result = alc.parse_logcat_line(
        "--> POST https://example.com/api/not-llm", state
    )
    assert result is None
    assert state == {}


def test_parser_detects_anthropic():
    import android_llm_capture as alc
    state: dict = {}
    alc.parse_logcat_line(
        "--> POST https://api.anthropic.com/v1/messages", state
    )
    assert state.get("provider") == "anthropic"


# ---------------------------------------------------------------------------
# Package-level imports
# ---------------------------------------------------------------------------

def test_package_imports():
    from android_llm_capture.capture import AndroidCapture, CapturedCall
    from android_llm_capture.adb     import ADBClient
    assert AndroidCapture is not None
    assert CapturedCall   is not None
    assert ADBClient      is not None


def test_package_init_exports():
    import android_llm_capture.capture as pkg
    assert hasattr(pkg, "AndroidCapture")
    assert hasattr(pkg, "CapturedCall")
    assert hasattr(pkg, "LLM_PATTERNS")


def test_adb_list_devices_returns_list():
    from android_llm_capture.adb import ADBClient
    # adb may not be available in CI — just verify the return type.
    result = ADBClient.list_devices()
    assert isinstance(result, list)


def test_gui_module_importable():
    """GUI module must be importable even without a display."""
    import importlib
    # Import the module source without executing launch_gui().
    spec = importlib.util.find_spec("android_llm_capture.gui")
    assert spec is not None, "android_llm_capture.gui could not be found"
