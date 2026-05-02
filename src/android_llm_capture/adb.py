"""Low-level ADB client wrapper."""

from __future__ import annotations

import subprocess
from typing import List, Optional


class ADBClient:
    """Thin wrapper around the ``adb`` command-line tool.

    Parameters
    ----------
    serial:
        Device serial passed to ``adb -s``.  ``None`` selects the sole
        connected device (adb default behaviour).
    """

    def __init__(self, serial: Optional[str] = None) -> None:
        self.serial = serial

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cmd(self, *args: str) -> List[str]:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd + list(args)

    def run(self, *args: str, timeout: int = 30) -> str:
        """Run an adb command synchronously and return stdout."""
        try:
            return subprocess.check_output(
                self._cmd(*args),
                timeout=timeout,
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"adb command failed: {exc}") from exc

    def popen(self, *args: str) -> subprocess.Popen:
        """Start an adb subprocess and return the :class:`subprocess.Popen` object."""
        return subprocess.Popen(
            self._cmd(*args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    # ------------------------------------------------------------------
    # Device operations
    # ------------------------------------------------------------------

    @staticmethod
    def list_devices() -> List[str]:
        """Return serials of all connected, online ADB devices."""
        try:
            out = subprocess.check_output(
                ["adb", "devices"],
                timeout=10,
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return []
        return [
            parts[0]
            for line in out.strip().splitlines()[1:]
            for parts in (line.split(),)
            if len(parts) >= 2 and parts[1] == "device"
        ]

    def get_device_info(self) -> dict:
        """Return model, brand, and Android version for the selected device."""
        props = {
            "model":           "ro.product.model",
            "brand":           "ro.product.brand",
            "android_version": "ro.build.version.release",
        }
        info: dict = {}
        for key, prop in props.items():
            try:
                info[key] = self.run("shell", "getprop", prop).strip()
            except Exception:
                info[key] = "unknown"
        return info

    def list_packages(self) -> List[str]:
        """Return package names of all installed apps."""
        out = self.run("shell", "pm", "list", "packages")
        return [
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]

    def logcat_popen(self, tag_filter: str = "OkHttp") -> subprocess.Popen:
        """Start a logcat subprocess filtered to *tag_filter*."""
        return self.popen("logcat", "-v", "brief", f"{tag_filter}:V", "*:S")
