"""Thin wrapper around the ``adb`` command-line tool."""
from __future__ import annotations

import subprocess
from typing import List, Optional


class ADBClient:
    """Wrapper around the Android Debug Bridge (ADB) command-line tool.

    Parameters
    ----------
    device_serial:
        Target device serial number as shown by ``adb devices``.
        Pass ``None`` to let ADB select the only connected device.
    """

    def __init__(self, device_serial: Optional[str] = None) -> None:
        self.device_serial = device_serial

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_cmd(self) -> List[str]:
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        return cmd

    # ------------------------------------------------------------------
    # Static / class-level queries
    # ------------------------------------------------------------------

    @staticmethod
    def list_devices() -> List[str]:
        """Return serial numbers of all *online* ADB devices.

        Returns an empty list when ``adb`` is not on PATH or no device is
        connected; never raises.
        """
        try:
            out = subprocess.check_output(["adb", "devices"], timeout=10, text=True)
        except (FileNotFoundError, subprocess.SubprocessError):
            return []
        serials: List[str] = []
        for line in out.splitlines()[1:]:  # skip "List of devices attached"
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials

    # ------------------------------------------------------------------
    # Instance-level device queries
    # ------------------------------------------------------------------

    def list_packages(self) -> List[str]:
        """Return package names installed on the target device.

        Returns an empty list on failure; never raises.
        """
        cmd = self._base_cmd() + ["shell", "pm", "list", "packages"]
        try:
            out = subprocess.check_output(cmd, timeout=30, text=True)
        except (FileNotFoundError, subprocess.SubprocessError):
            return []
        return [
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]

    def logcat_process(self, tag_filter: str = "OkHttp") -> subprocess.Popen:
        """Spawn an ``adb logcat`` subprocess and return the :class:`Popen` handle.

        Parameters
        ----------
        tag_filter:
            Logcat tag whose verbose output should be included.  All other
            tags are suppressed (``*:S``).

        Raises
        ------
        RuntimeError
            If ``adb`` is not found on PATH.
        """
        cmd = self._base_cmd() + ["logcat", "-v", "brief", f"{tag_filter}:V", "*:S"]
        try:
            return subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )
