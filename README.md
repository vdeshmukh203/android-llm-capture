# android-llm-capture

[![CI](https://github.com/vdeshmukh203/android-llm-capture/actions/workflows/ci.yml/badge.svg)](https://github.com/vdeshmukh203/android-llm-capture/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

**ADB-based tool for capturing, inspecting, and replaying LLM API calls made by Android applications.**

`android-llm-capture` uses the Android Debug Bridge (ADB) and `logcat` to intercept network traffic from LLM-powered Android apps (ChatGPT, Claude, Gemini, and others) without root access or device modification. Captured calls are stored as structured JSONL for offline analysis, reproducibility research, and regression testing.

---

## Features

- **Zero device modification** — requires only USB debugging (developer mode)
- **Supports 8+ LLM providers** — OpenAI, Anthropic, Google, Cohere, Mistral, Together AI, HuggingFace, Groq
- **OkHttp and Cronet detection** — covers the two most common Android HTTP stacks
- **JSONL output** — each call is a single JSON line with timestamps, hashes, and token estimates
- **Replay** — re-issue a captured call against the live API with your own key
- **Graphical UI** — tkinter-based GUI for browsing, filtering, and exporting calls
- **Stdlib-only** — no external Python dependencies

---

## Requirements

- Python 3.8 or later
- [Android SDK Platform-Tools](https://developer.android.com/studio/releases/platform-tools) (`adb` on `PATH`)
- A device or emulator with **USB debugging** enabled

---

## Installation

```bash
pip install android-llm-capture
```

Or install from source:

```bash
git clone https://github.com/vdeshmukh203/android-llm-capture.git
cd android-llm-capture
pip install -e .
```

---

## Quick start

### Live capture (device connected via USB or ADB-over-TCP)

```bash
android-llm-capture live --output session.jsonl
```

Press **Ctrl-C** to stop. Use `--serial <serial>` to target a specific device
(list serials with `adb devices`).

### Parse a saved logcat dump

```bash
# Save a logcat dump first:
adb logcat -v brief OkHttp:V *:S > dump.log

# Then parse it:
android-llm-capture file dump.log --output captures.jsonl
```

### View statistics

```bash
android-llm-capture stats captures.jsonl
```

### Replay a call

```bash
android-llm-capture replay captures.jsonl last --api-key sk-...
```

### Graphical user interface

```bash
android-llm-capture gui
# or directly:
android-llm-capture-gui
```

The GUI lets you:
- Select a connected device from a dropdown and start/stop live capture
- Open logcat dump files (`.log`, `.txt`) or existing captures (`.jsonl`)
- Browse all captured calls in a colour-coded table (by provider)
- Inspect request JSON, response JSON, and metadata in a tabbed detail panel
- Export captures to JSONL and view per-provider / per-model statistics

---

## Python API

```python
import android_llm_capture as alc

# List connected devices
devices = alc.list_devices()

# Live capture session
session = alc.CaptureSession(device_serial=devices[0], tag_filter="OkHttp")
session.start()
for call in session.stream():
    print(call.provider, call.model, call.response_status)
session.stop()
session.export_jsonl("captures.jsonl")

# Parse a saved logcat file
calls = alc.parse_logcat_file("dump.log")

# Replay a call
result = session.replay(calls[0], api_key="sk-...")
```

### `CapturedCall` fields

| Field | Type | Description |
|-------|------|-------------|
| `call_id` | `str` | 16-character SHA-256 prefix |
| `timestamp` | `float` | Unix timestamp of capture |
| `provider` | `str` | LLM provider name |
| `url` | `str` | Full request URL |
| `method` | `str` | HTTP method (`POST`, `GET`, …) |
| `request_body` | `dict \| None` | Parsed JSON request payload |
| `response_status` | `int \| None` | HTTP response status code |
| `response_body` | `str \| None` | Raw response body string |
| `source` | `str` | `"logcat"` or `"file"` |
| `request_hash` | `str` | SHA-256 of the request body |
| `response_hash` | `str` | SHA-256 of the response body |
| `.model` | `str \| None` | Property: `request_body["model"]` |
| `.prompt_tokens_estimate` | `int` | Property: rough token count |

---

## Supported providers

| Provider | URL pattern matched |
|----------|-------------------|
| OpenAI | `api.openai.com/v1/` |
| Anthropic | `api.anthropic.com/` |
| Google | `generativelanguage.googleapis.com/` |
| Cohere | `api.cohere.ai/` |
| Mistral | `api.mistral.ai/` |
| Together AI | `api.together.ai/` |
| HuggingFace | `api-inference.huggingface.co/` |
| Groq | `api.groq.com/` |

Additional providers can be added by extending `LLM_PATTERNS` in `android_llm_capture.py`.

---

## How it works

Android apps commonly use **OkHttp** (or Google's **Cronet**) for HTTP requests.
When the app has `HttpLoggingInterceptor` enabled (common in debug builds), request
and response bodies appear in `logcat`. `android-llm-capture` streams `logcat` via
ADB and applies a stateful line-by-line parser to reconstruct complete
request/response pairs for any recognised LLM API endpoint.

No proxy, VPN, or SSL pinning bypass is required. This approach works on any
app that logs its HTTP traffic — typical for debug and staging builds, and
sometimes for release builds as well.

---

## Contributing

Pull requests and issue reports are welcome. Please run the test suite before
submitting:

```bash
pip install pytest
pytest tests/ -v
```

---

## Citation

If you use `android-llm-capture` in research, please cite:

```bibtex
@article{deshmukh2026android,
  title   = {android-llm-capture: ADB-based screen capture and interaction
             logging for Android LLM applications},
  author  = {Deshmukh, Vaibhav},
  journal = {Journal of Open Source Software},
  year    = {2026},
}
```

See also `CITATION.cff`.

---

## License

MIT — see [LICENSE](LICENSE).
