# android-llm-capture

> ADB-based tool for capturing, logging, and replaying LLM API interactions from Android devices and emulators.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.8-blue)](https://python.org)

## Overview

`android-llm-capture` uses the [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb) to intercept and record LLM API calls made by Android apps. It parses OkHttp and Cronet network logging from `adb logcat`, producing structured JSONL logs for offline analysis, regression testing, and reproducibility research.

**Supported providers:** OpenAI, Anthropic, Google, Cohere, Mistral, Together AI, HuggingFace Inference, Groq.

**Zero external dependencies** — pure Python standard library only.

## Requirements

- Python ≥ 3.8
- Android SDK Platform-Tools (`adb` on PATH)
- Android device or emulator with **Developer Options** and **USB Debugging** enabled

## Installation

```bash
pip install android-llm-capture
```

Or from source (editable install):

```bash
git clone https://github.com/vdeshmukh203/android-llm-capture
cd android-llm-capture
pip install -e .
```

## Quick Start

### Live capture from a connected device

```bash
android-llm-capture live --tag OkHttp --output session.jsonl
```

Press `Ctrl-C` to stop. Calls are saved to `session.jsonl`.

### Parse a saved logcat file

```bash
adb logcat -v brief OkHttp:V *:S > dump.log
android-llm-capture file dump.log --output captures.jsonl
```

### Replay a captured call

```bash
android-llm-capture replay captures.jsonl last --api-key sk-...
```

Use `last` to replay the most recent call, or supply a specific `call_id`.

### View statistics

```bash
android-llm-capture stats captures.jsonl
```

### Graphical user interface

```bash
android-llm-capture gui
# or
android-llm-capture-gui
```

The GUI provides:
- Device selection and live capture controls
- Scrollable table of all captured calls (colour-coded by HTTP status)
- Request body, response body, and metadata detail panels
- File open / export and statistics tab

## Python API

```python
from android_llm_capture import AndroidCapture, parse_logcat_file
from pathlib import Path

# Live capture
session = AndroidCapture(device_serial="emulator-5554", tag_filter="OkHttp")
session.start()
for call in session.stream():
    print(call.provider, call.model, call.response_status)
session.stop()
session.export_jsonl(Path("output.jsonl"))

# Parse a saved logcat dump
calls = parse_logcat_file(Path("dump.log"))
for call in calls:
    print(call.to_jsonl())
```

## JSONL Output Format

Each line is a JSON object with the following fields:

| Field | Type | Description |
|---|---|---|
| `call_id` | str | 16-hex unique identifier |
| `timestamp` | float | Unix epoch (UTC) |
| `provider` | str | Detected LLM provider name |
| `url` | str | Full request URL |
| `method` | str | HTTP method (`POST`, `GET`, …) |
| `request_body` | object\|null | Parsed JSON request body |
| `response_status` | int\|null | HTTP response status code |
| `response_body` | str\|null | Raw response body string |
| `source` | str | `"logcat"` or `"file"` |
| `request_hash` | str | SHA-256 of the request body |
| `response_hash` | str | SHA-256 of the response body |

## Enabling OkHttp Logging on Android

`android-llm-capture` reads OkHttp and Cronet debug logs. Enable **Developer Options** on the device, connect via USB, then verify:

```bash
adb logcat OkHttp:V *:S
```

You should see lines beginning with `--> POST https://api.openai.com/...` when the target app makes LLM requests.

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Citation

If you use this software in research, please cite it:

```bibtex
@software{deshmukh2026alc,
  author  = {Deshmukh, Vaibhav},
  title   = {android-llm-capture: ADB-based capture of LLM API interactions},
  year    = {2026},
  url     = {https://github.com/vdeshmukh203/android-llm-capture}
}
```

Or use the metadata in [`CITATION.cff`](CITATION.cff).

## Contributing

Issues and pull requests are welcome. Please open an issue before submitting large changes.

## License

MIT © Vaibhav Deshmukh
