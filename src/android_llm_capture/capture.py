"""Capture submodule — thin wrapper that re-exports CaptureSession as AndroidCapture."""

from android_llm_capture import CaptureSession

#: Public alias expected by the package __init__
AndroidCapture = CaptureSession

__all__ = ["AndroidCapture"]
