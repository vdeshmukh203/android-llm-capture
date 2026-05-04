"""
android_llm_capture — ADB-based capture of LLM API interactions from Android.

Uses Android Debug Bridge (ADB) to intercept OkHttp / Cronet network traffic
from Android devices and emulators, producing structured JSONL logs for offline
analysis and replay.

Supported providers: OpenAI, Anthropic, Google, Cohere, Mistral, Together AI,
HuggingFace Inference, Groq.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from ._models import CapturedCall
from ._parser import LLM_PATTERNS, parse_logcat_file, parse_logcat_line
from .adb import ADBClient, list_devices, list_packages
from .capture import AndroidCapture, CaptureSession, LLMCapture
from .cli import main

_cli = main

__all__ = [
    "AndroidCapture",
    "CaptureSession",
    "LLMCapture",
    "CapturedCall",
    "ADBClient",
    "LLM_PATTERNS",
    "parse_logcat_line",
    "parse_logcat_file",
    "list_devices",
    "list_packages",
    "main",
    "_cli",
]
