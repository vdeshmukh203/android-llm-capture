# android-llm-capture

[![CI](https://github.com/vdeshmukh203/android-llm-capture/actions/workflows/ci.yml/badge.svg)](https://github.com/vdeshmukh203/android-llm-capture/actions)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**android-llm-capture** uses the Android Debug Bridge (ADB) to non-invasively capture, log, and replay LLM API calls made by Android applications. It parses OkHttp and Cronet network-interceptor output from `adb logcat` to reconstruct structured request/response pairs — no device root, no app modification, and no external Python dependencies required.

**Supported providers:** OpenAI · Anthropic · Google Gemini · Cohere · Mistral · Together AI · Hugging Face Inference API · Groq

## Installation

```bash
pip install android-llm-capture
```

Or from source:

```bash
git clone https://github.com/vdeshmukh203/android-llm-capture.git
cd android-llm-capture
pip install -e .
```

**Requirements:** Python ≥ 3.8 (stdlib only — no `pip` dependencies). Android SDK [platform-tools](https://developer.android.com/tools/releases/platform-tools) (`adb`) must be on `PATH`. Developer Mode and USB debugging must be enabled on the target device.

## Quick start

### Command-line interface

**Live capture** — stream logcat and write a JSONL file as calls are detected:

```bash
android-llm-capture live --output session.jsonl
# specify device: --serial emulator-5554
# stop after 60 s: --timeout 60
```

**Parse a saved logcat dump:**

```bash
adb logcat -v brief OkHttp:V *:S > dump.log
android-llm-capture file dump.log --output calls.jsonl
```

**View statistics:**

```bash
android-llm-capture stats calls.jsonl
```

```
Total calls :  42
By provider :
  openai              38
  anthropic            4
By model    :
  gpt-4o              30
  gpt-4o-mini          8
  claude-3-5-sonnet    4
```

**Replay a captured call against the live API:**

```bash
android-llm-capture replay calls.jsonl last --api-key sk-...
android-llm-capture replay calls.jsonl a1b2c3d4 --api-key sk-...
```

### Desktop GUI

```bash
android-llm-capture-gui
```

A four-tab desktop GUI (Live Capture, File Parser, Replay, Statistics) is included. It uses Python's built-in `tkinter` — no additional dependencies.

![GUI screenshot placeholder](https://raw.githubusercontent.com/vdeshmukh203/android-llm-capture/main/docs/screenshot.png)

### Python API

```python
from android_llm_capture import CaptureSession, parse_logcat_file, load_jsonl
from pathlib import Path

# --- Parse a saved logcat dump ---
calls = parse_logcat_file(Path("dump.log"))
for call in calls:
    print(call.provider, call.model, call.response_status)
    print(call.to_jsonl())

# --- Live capture ---
session = CaptureSession(device_serial="emulator-5554", tag_filter="OkHttp")
session.start()
for call in session.stream():   # yields CapturedCall objects as detected
    print(f"[{call.provider}] {call.method} {call.url}")
session.export_jsonl(Path("out.jsonl"))

# --- Load a saved captures file ---
calls = load_jsonl(Path("out.jsonl"))

# --- Replay a call ---
result = session.replay(calls[-1], api_key="sk-...")
```

## Output format (JSONL)

Each captured call is serialised as a single-line JSON object:

```json
{
  "call_id":         "a1b2c3d4e5f60011",
  "timestamp":       1745000000.123,
  "provider":        "openai",
  "url":             "https://api.openai.com/v1/chat/completions",
  "method":          "POST",
  "request_body":    {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}]},
  "response_status": 200,
  "response_body":   "{\"id\": \"chatcmpl-...\", \"choices\": [...]}",
  "source":          "logcat",
  "request_hash":    "sha256hex...",
  "response_hash":   "sha256hex..."
}
```

## Enabling OkHttp logging on your device

Most Android LLM clients use [OkHttp](https://square.github.io/okhttp/) with its `HttpLoggingInterceptor`. Enable verbose logcat output with:

```bash
adb logcat OkHttp:V *:S
```

Some apps use different tag names (e.g. `HttpClient`, `Retrofit`). Use `--tag <NAME>` to match them. For apps using Cronet (Google's network stack), `android-llm-capture` detects `CronetEngine` log lines automatically.

## API reference

| Symbol | Description |
|--------|-------------|
| `CapturedCall` | Dataclass: `call_id`, `timestamp`, `provider`, `url`, `method`, `request_body`, `response_status`, `response_body`, `source`, `request_hash`, `response_hash`, `.model`, `.prompt_tokens_estimate` |
| `CaptureSession(device_serial, tag_filter)` | Live ADB logcat capture. Methods: `.start()`, `.stop()`, `.stream()` → iterator, `.export_jsonl(path)`, `.replay(call, api_key)` |
| `parse_logcat_line(line, state)` | Parse a single logcat line (stateful). |
| `parse_logcat_file(path)` | Parse an entire logcat dump file. Returns `List[CapturedCall]`. |
| `load_jsonl(path)` | Load a JSONL captures file. Returns `List[CapturedCall]`. |
| `list_devices()` | Return connected ADB device serials. |
| `list_packages(device)` | Return installed package names on a device. |
| `LLM_PATTERNS` | Dict of provider name → compiled URL regex. |

## Contributing

Bug reports and pull requests are welcome at <https://github.com/vdeshmukh203/android-llm-capture>.

```bash
pip install -e .
pytest
```

## Citation

If you use this software in academic work, please cite:

```bibtex
@article{Deshmukh2026,
  author  = {Deshmukh, Vaibhav},
  title   = {android-llm-capture: ADB-based screen capture and interaction
             logging for Android LLM applications},
  journal = {Journal of Open Source Software},
  year    = {2026},
  url     = {https://github.com/vdeshmukh203/android-llm-capture}
}
```

## License

MIT — see [LICENSE](LICENSE).
