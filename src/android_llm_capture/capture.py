"""Live ADB logcat capture session."""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from ._models import CapturedCall
from ._parser import parse_logcat_line


class AndroidCapture:
    """Live ADB logcat capture session for LLM API traffic.

    Parameters
    ----------
    device_serial:
        ADB device serial (``adb -s``). ``None`` uses the default device.
    tag_filter:
        Logcat tag to filter on. Defaults to ``OkHttp``.
    """

    def __init__(
        self,
        device_serial: Optional[str] = None,
        tag_filter: str = "OkHttp",
    ) -> None:
        self.device_serial = device_serial
        self.tag_filter = tag_filter
        self.calls: List[CapturedCall] = []
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        """Launch ``adb logcat`` as a background subprocess."""
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += ["logcat", "-v", "brief", f"{self.tag_filter}:V", "*:S"]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "adb not found — ensure Android SDK platform-tools is on PATH."
            )

    def stop(self) -> None:
        """Terminate the logcat subprocess."""
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """Yield :class:`~._models.CapturedCall` objects from the live logcat."""
        if self._proc is None or self._proc.stdout is None:
            raise RuntimeError("Call start() before streaming.")
        state: Dict = {}
        for line in self._proc.stdout:
            result = parse_logcat_line(line, state)
            if result:
                self.calls.append(result)
                yield result

    def export_jsonl(self, path: Path) -> None:
        """Write all captured calls to a JSONL file."""
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")

    def replay(self, call: CapturedCall, api_key: str) -> Dict:
        """Re-send *call* to the real API endpoint using *api_key*.

        Raises
        ------
        ValueError
            If the captured call has no request body.
        RuntimeError
            On HTTP errors or network failures.
        """
        if not call.request_body:
            raise ValueError("No request body to replay.")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if call.provider == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
        elif call.provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = json.dumps(call.request_body).encode()
        req = urllib.request.Request(
            call.url, data=payload, headers=headers, method=call.method
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"HTTP {exc.code} from {call.provider}: {body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Network error replaying call: {exc.reason}"
            ) from exc


# Backwards-compatible aliases
CaptureSession = AndroidCapture
LLMCapture = AndroidCapture
