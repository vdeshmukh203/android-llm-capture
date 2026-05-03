"""
android_llm_capture: ADB-based Android LLM interaction capture tool.

The canonical implementation is the top-level ``android_llm_capture.py``
module, installed as a py-module by setuptools (see ``pyproject.toml``).
Import from ``android_llm_capture`` in all production code.

Public API summary
------------------
CapturedCall      — dataclass representing one request/response pair
CaptureSession    — live ADB logcat capture manager
parse_logcat_line — parse a single logcat line (stateful)
parse_logcat_file — parse an entire saved logcat dump
load_jsonl        — load a JSONL captures file
list_devices      — list connected ADB devices
list_packages     — list installed packages on a device
main              — CLI entry point
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

__all__ = [
    "CapturedCall",
    "CaptureSession",
    "LLMCapture",
    "parse_logcat_line",
    "parse_logcat_file",
    "load_jsonl",
    "list_devices",
    "list_packages",
    "main",
]
