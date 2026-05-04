"""ADB device and package enumeration utilities."""
from __future__ import annotations

import subprocess
from typing import List, Optional


class ADBClient:
    """Thin wrapper around ADB for device and package enumeration.

    Parameters
    ----------
    device_serial:
        Target device serial. ``None`` uses the ADB default device.
    """

    def __init__(self, device_serial: Optional[str] = None) -> None:
        self.device_serial = device_serial

    def _run(self, *args: str, timeout: int = 30) -> str:
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += list(args)
        try:
            return subprocess.check_output(
                cmd, timeout=timeout, text=True, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"adb command failed (exit {exc.returncode})") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"adb command timed out after {timeout}s") from exc

    def list_devices(self) -> List[str]:
        """Return serial numbers of all connected, non-offline ADB devices."""
        try:
            out = subprocess.check_output(
                ["adb", "devices"], timeout=10, text=True, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )
        except subprocess.TimeoutExpired:
            return []
        devices = []
        for line in out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    def list_packages(self) -> List[str]:
        """Return package names of all installed apps on the target device."""
        out = self._run("shell", "pm", "list", "packages")
        return [
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]

    def shell(self, *cmd: str) -> str:
        """Run an arbitrary ``adb shell`` command and return stdout."""
        return self._run("shell", *cmd)


# ---------------------------------------------------------------------------
# Module-level convenience functions (backwards-compatible)
# ---------------------------------------------------------------------------

def list_devices() -> List[str]:
    """Return serial numbers of connected ADB devices."""
    return ADBClient().list_devices()


def list_packages(device: Optional[str] = None) -> List[str]:
    """Return package names installed on *device* (or the default device)."""
    return ADBClient(device_serial=device).list_packages()
