"""
android_llm_capture: ADB-based Android LLM interaction capture tool.

Uses the Android Debug Bridge (ADB) to intercept and record LLM application
interactions on Android devices. Captures screen content, clipboard events,
and accessibility tree snapshots to reconstruct prompt/response pairs from
on-device LLM apps for reproducible research documentation.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

# Re-export the public surface from the flat root module so that both
# ``import android_llm_capture`` and ``from android_llm_capture import ...``
# work regardless of whether the package is installed from the src/ layout
# or imported directly from the project root.
from android_llm_capture import (  # noqa: F401
    CapturedCall,
    CaptureSession,
    LLMCapture,
    parse_logcat_line,
    parse_logcat_file,
    list_devices,
    list_packages,
    main,
    _cli,
)
from android_llm_capture.capture import AndroidCapture  # noqa: F401
from android_llm_capture.adb import ADBClient            # noqa: F401

__all__ = [
    "AndroidCapture",
    "ADBClient",
    "CapturedCall",
    "CaptureSession",
    "LLMCapture",
    "parse_logcat_line",
    "parse_logcat_file",
    "list_devices",
    "list_packages",
    "main",
]
