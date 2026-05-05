"""
android_llm_capture — ADB-based Android LLM interaction capture tool.

Uses the Android Debug Bridge (ADB) to intercept and record LLM API
interactions (network traffic) on Android devices or emulators.  Produces
structured JSONL logs that can be replayed and analysed offline.

Public API
----------
- :class:`CapturedCall`      — dataclass for a single captured request/response pair
- :class:`CaptureSession`    — live logcat capture session manager
- :class:`ADBClient`         — thin wrapper around the ``adb`` CLI
- :func:`detect_provider`    — identify the LLM provider from a URL
- :func:`parse_logcat_line`  — stateful single-line logcat parser
- :func:`parse_logcat_file`  — parse a saved logcat dump file
- :data:`LLM_PATTERNS`       — compiled URL patterns for each supported provider
- :func:`list_devices`       — convenience wrapper for :meth:`ADBClient.list_devices`
- :func:`list_packages`      — convenience wrapper for :meth:`ADBClient.list_packages`
"""

from __future__ import annotations

__version__ = "0.2.0"
__author__ = "Vaibhav Deshmukh"
__license__ = "MIT"

from .adb import ADBClient
from .capture import CaptureSession, LLMCapture
from .models import CapturedCall
from .parser import LLM_PATTERNS, detect_provider, parse_logcat_file, parse_logcat_line

__all__ = [
    "ADBClient",
    "CapturedCall",
    "CaptureSession",
    "LLMCapture",
    "LLM_PATTERNS",
    "detect_provider",
    "list_devices",
    "list_packages",
    "parse_logcat_file",
    "parse_logcat_line",
]


# ---------------------------------------------------------------------------
# Module-level convenience wrappers (backwards compatible)
# ---------------------------------------------------------------------------

def list_devices() -> list:
    """Return serial numbers of connected ADB devices.

    Equivalent to :meth:`ADBClient.list_devices`.
    """
    return ADBClient.list_devices()


def list_packages(device: str = None) -> list:
    """Return package names installed on *device* (or the only connected device).

    Equivalent to ``ADBClient(device).list_packages()``.
    """
    return ADBClient(device).list_packages()
