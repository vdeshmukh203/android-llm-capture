"""
android_llm_capture: ADB-based Android LLM interaction capture tool.

Uses the Android Debug Bridge (ADB) to intercept and record LLM API calls
from Android devices and emulators via logcat (OkHttp / Cronet).

Quick start
-----------
>>> from android_llm_capture import AndroidCapture
>>> cap = AndroidCapture(device_serial="emulator-5554")
>>> cap.start()
>>> for call in cap.stream():
...     print(call.provider, call.url, call.response_status)
>>> cap.stop()
>>> cap.export_jsonl(Path("session.jsonl"))
"""

__version__ = "0.1.0"
__author__  = "Vaibhav Deshmukh"
__license__ = "MIT"

from .adb     import ADBClient
from .capture import (
    AndroidCapture,
    CapturedCall,
    LLM_PATTERNS,
    parse_logcat_line,
    parse_logcat_file,
    load_jsonl,
)

# Backwards-compatible aliases
LLMCapture = AndroidCapture


def list_devices():
    """Return serials of all connected, online ADB devices."""
    return ADBClient.list_devices()


def list_packages(device=None):
    """List installed packages on a connected Android device."""
    return ADBClient(device).list_packages()


__all__ = [
    "AndroidCapture",
    "ADBClient",
    "CapturedCall",
    "LLM_PATTERNS",
    "LLMCapture",
    "list_devices",
    "list_packages",
    "parse_logcat_line",
    "parse_logcat_file",
    "load_jsonl",
]
