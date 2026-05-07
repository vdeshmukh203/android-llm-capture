"""
android_llm_capture — ADB-based Android LLM interaction capture tool.

Uses the Android Debug Bridge (ADB) to intercept and record LLM API calls
made by Android apps, producing structured JSONL logs for offline analysis
and reproducibility research.
"""

__version__ = "0.1.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

# Re-export the public API from the top-level module so that both
# ``import android_llm_capture`` and ``from android_llm_capture import …``
# work regardless of whether the package or the module is on sys.path.
from android_llm_capture import (  # noqa: F401
    CapturedCall,
    CaptureSession,
    LLMCapture,
    AndroidCapture,
    parse_logcat_line,
    parse_logcat_file,
    list_devices,
    list_packages,
    main,
    _cli,
    LLM_PATTERNS,
)

# Legacy aliases kept for the ADBClient / AndroidCapture names mentioned
# in the CHANGELOG and paper.
ADBClient = None  # placeholder — full ADB client not yet implemented

__all__ = [
    "CapturedCall",
    "CaptureSession",
    "LLMCapture",
    "AndroidCapture",
    "ADBClient",
    "parse_logcat_line",
    "parse_logcat_file",
    "list_devices",
    "list_packages",
    "main",
    "LLM_PATTERNS",
]
