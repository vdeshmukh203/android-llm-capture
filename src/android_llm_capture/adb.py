"""ADB device utilities re-exported from the top-level module."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from android_llm_capture import list_devices, list_packages  # noqa: E402


class ADBClient:
    """Thin wrapper around ADB helper functions."""

    @staticmethod
    def list_devices() -> List[str]:
        """Return serial strings for all connected (non-offline) ADB devices."""
        return list_devices()

    @staticmethod
    def list_packages(device: Optional[str] = None) -> List[str]:
        """Return installed package names on the given Android device."""
        return list_packages(device)


__all__ = ["ADBClient", "list_devices", "list_packages"]
