"""ADB submodule — provides the ADBClient helper class."""

from android_llm_capture import list_devices, list_packages
from typing import List, Optional


class ADBClient:
    """High-level wrapper around the ADB helper functions."""

    @staticmethod
    def list_devices() -> List[str]:
        """Return serial strings for all online ADB devices."""
        return list_devices()

    @staticmethod
    def list_packages(device: Optional[str] = None) -> List[str]:
        """Return installed package names for *device* (or the default device)."""
        return list_packages(device)


__all__ = ["ADBClient"]
