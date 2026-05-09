"""
android_llm_capture — ADB-based Android LLM interaction capture tool.

Uses the Android Debug Bridge (ADB) to intercept and record LLM application
interactions on Android devices.  Captures network traffic logged by OkHttp or
Cronet interceptors to reconstruct prompt/response pairs for reproducible
research documentation.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from .capture import AndroidCapture, CaptureSession, CapturedCall
from .adb import ADBClient, list_devices, list_packages

__all__ = [
    "AndroidCapture",
    "CaptureSession",
    "CapturedCall",
    "ADBClient",
    "list_devices",
    "list_packages",
]
