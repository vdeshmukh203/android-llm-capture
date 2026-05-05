"""Live logcat capture session."""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .adb import ADBClient
from .models import CapturedCall
from .parser import parse_logcat_line


class CaptureSession:
    """Manages a live ``adb logcat`` capture session.

    Typical usage::

        session = CaptureSession(device_serial="emulator-5554")
        session.start()
        try:
            for call in session.stream():
                print(call.provider, call.response_status)
        except KeyboardInterrupt:
            pass
        finally:
            session.stop()
        session.export_jsonl(Path("captures.jsonl"))

    Parameters
    ----------
    device_serial:
        Android device serial as reported by ``adb devices``.
        ``None`` selects the only connected device.
    tag_filter:
        Logcat tag to include verbosely (default ``"OkHttp"``).
    """

    def __init__(
        self,
        device_serial: Optional[str] = None,
        tag_filter: str = "OkHttp",
    ) -> None:
        self.device_serial = device_serial
        self.tag_filter = tag_filter
        self.calls: List[CapturedCall] = []
        self._adb = ADBClient(device_serial)
        self._proc: Optional[subprocess.Popen] = None

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Launch ``adb logcat`` as a background subprocess.

        Raises
        ------
        RuntimeError
            If ``adb`` is not found on PATH.
        """
        self._proc = self._adb.logcat_process(self.tag_filter)

    def stop(self) -> None:
        """Terminate the logcat subprocess gracefully."""
        if self._proc is not None:
            self._proc.terminate()
            self._proc = None

    # ------------------------------------------------------------------
    # Streaming
    # ------------------------------------------------------------------

    def stream(self) -> Iterator[CapturedCall]:
        """Yield :class:`CapturedCall` objects as they are detected.

        Must call :meth:`start` first.

        Raises
        ------
        RuntimeError
            If the session has not been started.
        """
        if self._proc is None:
            raise RuntimeError("Call start() before streaming.")
        assert self._proc.stdout is not None
        state: Dict = {}
        for line in self._proc.stdout:
            result = parse_logcat_line(line, state)
            if result is not None:
                self.calls.append(result)
                yield result

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_jsonl(self, path: Path) -> int:
        """Write captured calls to *path* as JSONL.

        Parameters
        ----------
        path:
            Destination file.  Created or overwritten.

        Returns
        -------
        int
            Number of calls written.
        """
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        return len(self.calls)

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        """Re-send a captured request to the real provider API.

        The appropriate authentication header is injected automatically based
        on ``call.provider``.

        Parameters
        ----------
        call:
            The :class:`CapturedCall` to replay.
        api_key:
            Provider API key.

        Returns
        -------
        dict
            Parsed JSON response body.

        Raises
        ------
        ValueError
            If *call* has no request body.
        urllib.error.HTTPError
            On non-2xx HTTP responses.
        """
        if not call.request_body:
            raise ValueError("Cannot replay a call with no request body.")

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
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# Backwards-compatible alias
LLMCapture = CaptureSession
