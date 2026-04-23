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

from .capture import AndroidCapture
from .adb import ADBClient

__all__ = ["AndroidCapture", "ADBClient"]
