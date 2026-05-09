# android-llm-capture

[![CI](https://github.com/vdeshmukh203/android-llm-capture/actions/workflows/ci.yml/badge.svg)](https://github.com/vdeshmukh203/android-llm-capture/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**android-llm-capture** is a Python tool that uses the Android Debug Bridge (ADB) to capture, log, and replay interactions with large language model (LLM) applications running on Android devices or emulators.

It parses logcat output from OkHttp and Cronet interceptors — no root access, no device modification required.

---

## Features

- **Live capture** — streams `adb logcat` in real time and writes JSONL output
- **File parsing** — post-process saved logcat dumps
- **Replay** — re-send any captured call against the real API with your own key
- **Stats** — provider/model frequency counts from a captures file
- **GUI** — built-in tkinter interface (stdlib only, no extra dependencies)
- **Zero dependencies** — pure Python 3.8+, stdlib only

Supported providers: OpenAI, Anthropic, Google Gemini, Cohere, Mistral, Together AI, Hugging Face Inference, Groq.

---

## Requirements

- Python ≥ 3.8
- Android SDK **platform-tools** (`adb`) on `PATH`
- Android device or emulator with **Developer Options → USB Debugging** enabled
- App built with `OkHttpClient` + `HttpLoggingInterceptor` (or Cronet)

---

## Installation

```bash
pip install android-llm-capture
```

Or from source:

```bash
git clone https://github.com/vdeshmukh203/android-llm-capture.git
cd android-llm-capture
pip install .
```

---

## CLI usage

```bash
# Live capture (Ctrl-C to stop)
android-llm-capture live --serial emulator-5554 --output session.jsonl

# Parse a saved logcat dump
android-llm-capture file dump.txt --output captures.jsonl

# Replay the last captured call
android-llm-capture replay captures.jsonl last --api-key sk-...

# Statistics
android-llm-capture stats captures.jsonl

# Launch GUI
android-llm-capture gui
```

---

## Python API

```python
from android_llm_capture import CaptureSession, parse_logcat_file, load_jsonl

# Live capture
session = CaptureSession(device_serial="emulator-5554")
session.start()
for call in session.stream():
    print(call.provider, call.model, call.response_status)
session.stop()
session.export_jsonl("session.jsonl")

# Parse a file
calls = parse_logcat_file("dump.txt")

# Load existing JSONL
calls = load_jsonl("session.jsonl")
```

---

## Graphical interface

```bash
android-llm-capture gui
# or directly:
python android_llm_capture.py gui
```

The GUI provides four tabs:

| Tab | Description |
|-----|-------------|
| **Live Capture** | Device selector, tag filter, start/stop, live call log |
| **Parse File** | Browse logcat dump, parse to JSONL |
| **Call Viewer** | Table of captured calls with request/response detail pane |
| **Stats** | Provider and model frequency chart |

---

## Output format (JSONL)

Each line is a JSON object:

```json
{
  "call_id": "a1b2c3d4e5f6a7b8",
  "timestamp": 1700000000.123,
  "provider": "openai",
  "url": "https://api.openai.com/v1/chat/completions",
  "method": "POST",
  "request_body": {"model": "gpt-4", "messages": [...]},
  "response_status": 200,
  "response_body": "{\"id\":\"chatcmpl-...\"}",
  "source": "logcat",
  "request_hash": "sha256...",
  "response_hash": "sha256..."
}
```

---

## Running tests

```bash
pip install pytest
pytest
```

---

## Contributing

Issues and pull requests are welcome.  Please open an issue before submitting large changes.

---

## Citation

If you use this software in research, please cite using the metadata in [`CITATION.cff`](CITATION.cff).

---

## License

MIT — see [LICENSE](LICENSE).
