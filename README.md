# android-llm-capture

ADB-based Python tool for **capturing, logging, and replaying LLM API interactions** from Android devices or emulators.

## Features

- **Live capture** — stream `adb logcat` to intercept OkHttp/Cronet LLM API traffic in real time
- **File parsing** — parse saved logcat dumps offline
- **Replay** — re-send captured requests against the live provider API with your own key
- **Statistics** — summarise captured calls by provider, model, and HTTP status
- **GUI** — Tkinter-based graphical interface (no extra dependencies)

Supported providers: OpenAI, Anthropic, Google (Gemini), Cohere, Mistral, Together AI, Hugging Face Inference API, Groq.

## Requirements

- Python ≥ 3.8 (standard library only — no pip dependencies)
- [Android SDK Platform-Tools](https://developer.android.com/studio/releases/platform-tools) (`adb` on PATH)
- Android device or emulator with **USB Debugging** enabled and the app's HTTP traffic logged via OkHttp or Cronet

## Installation

```bash
pip install android-llm-capture
```

Or run the self-contained single-file script directly (no installation needed):

```bash
python android_llm_capture.py --help
```

## Usage

### Command-line interface

```bash
# Live capture from a connected device (Ctrl-C to stop)
android-llm-capture live --tag OkHttp --output captures.jsonl

# Specify a device when multiple are connected
android-llm-capture live --serial emulator-5554 --timeout 60

# Parse a saved logcat dump
android-llm-capture file dump.txt --output captures.jsonl

# Show a summary of a captures file
android-llm-capture stats captures.jsonl

# Replay the last captured call
android-llm-capture replay captures.jsonl last --api-key sk-...

# Launch the graphical user interface
android-llm-capture gui
```

### Python API

```python
from android_llm_capture import (
    ADBClient,
    CaptureSession,
    CapturedCall,
    parse_logcat_file,
)

# List connected devices
devices = ADBClient.list_devices()

# Live capture
session = CaptureSession(device_serial=devices[0], tag_filter="OkHttp")
session.start()
for call in session.stream():
    print(call.provider, call.url, call.response_status)
session.stop()
session.export_jsonl("captures.jsonl")

# Parse a saved file
calls = parse_logcat_file("dump.txt")
for c in calls:
    print(c.model, c.prompt_tokens_estimate, "tokens (est.)")
```

## How it works

`android-llm-capture` reads `adb logcat` output produced by the [OkHttp HttpLoggingInterceptor](https://square.github.io/okhttp/features/interceptors/) or the Cronet network stack.  It recognises request (`--> POST …`) and response (`<-- 200 …`) lines, assembles them into `CapturedCall` objects, and writes them to JSONL for downstream analysis.

No root access is required — only a USB-debugging-enabled device.

## Output format

Each line in the JSONL output is a JSON object:

```json
{
  "call_id": "a3f9c1e2b8d04f1a",
  "timestamp": 1700000000.123,
  "provider": "openai",
  "url": "https://api.openai.com/v1/chat/completions",
  "method": "POST",
  "request_body": {"model": "gpt-4", "messages": [...]},
  "response_status": 200,
  "response_body": "{\"id\":\"chatcmpl-...\",\"choices\":[...]}",
  "source": "logcat",
  "request_hash": "sha256-of-request-body",
  "response_hash": "sha256-of-response-body"
}
```

## License

MIT — see [LICENSE](LICENSE).
