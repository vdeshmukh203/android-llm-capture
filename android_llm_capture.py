#!/usr/bin/env python3
"""
android_llm_capture.py — Android LLM Network Traffic Capture
Parses Android logcat output to intercept and replay LLM API calls.
Stdlib-only. No external dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


# ---------------------------------------------------------------------------
# LLM provider URL patterns
# ---------------------------------------------------------------------------

LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":       re.compile(r'api\.openai\.com/v1/',                 re.IGNORECASE),
    "anthropic":    re.compile(r'api\.anthropic\.com/',                 re.IGNORECASE),
    "google":       re.compile(r'generativelanguage\.googleapis\.com/', re.IGNORECASE),
    "cohere":       re.compile(r'api\.cohere\.ai/',                     re.IGNORECASE),
    "mistral":      re.compile(r'api\.mistral\.ai/',                    re.IGNORECASE),
    "together":     re.compile(r'api\.together\.ai/',                   re.IGNORECASE),
    "huggingface":  re.compile(r'api-inference\.huggingface\.co/',      re.IGNORECASE),
    "groq":         re.compile(r'api\.groq\.com/',                      re.IGNORECASE),
    "azure_openai": re.compile(r'openai\.azure\.com/',                  re.IGNORECASE),
    "ollama":       re.compile(r'localhost:\d+/api/',                   re.IGNORECASE),
}

# Logcat patterns (OkHttp / Cronet interceptor output)
_OKHTTP_REQUEST  = re.compile(r'--> (?P<method>POST|GET|PUT|PATCH|DELETE) (?P<url>https?://\S+)')
_OKHTTP_BODY     = re.compile(r'(?P<body>\{.+\}|\[.+\])')
_OKHTTP_RESPONSE = re.compile(r'<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)')
_OKHTTP_END_RESP = re.compile(r'<-- END HTTP')
_CRONET_URL      = re.compile(r'(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)', re.IGNORECASE)


def _detect_provider(url: str) -> Optional[str]:
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CapturedCall:
    """One complete LLM API request/response pair captured from logcat."""

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str   # "logcat" or "file"
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str  = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        resp_str = self.response_body or ""
        self.request_hash  = _sha256(req_str)
        self.response_hash = _sha256(resp_str)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "CapturedCall":
        return cls(
            call_id=d["call_id"],
            timestamp=d["timestamp"],
            provider=d["provider"],
            url=d["url"],
            method=d["method"],
            request_body=d.get("request_body"),
            response_status=d.get("response_status"),
            response_body=d.get("response_body"),
            source=d.get("source", "file"),
        )

    @property
    def model(self) -> Optional[str]:
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough token count: ~1 token per 4 characters (OpenAI rule-of-thumb)."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "") if isinstance(m.get("content"), str) else ""
            for m in messages
            if isinstance(m, dict)
        )
        return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Logcat line parser
# ---------------------------------------------------------------------------

def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """
    Stateful parser for a single logcat line.

    ``state`` is mutated across calls to accumulate partial call info.
    Returns a :class:`CapturedCall` when a complete request+response pair
    is detected, otherwise ``None``.
    """
    line = line.strip()
    if not line:
        return None

    # ── OkHttp request start ───────────────────────────────────────────────
    m = _OKHTTP_REQUEST.search(line)
    if m:
        url = m.group("url")
        provider = _detect_provider(url)
        if provider:
            # Clear any previous partial state before starting a new call.
            state.clear()
            state.update(
                url=url,
                method=m.group("method"),
                provider=provider,
                body_lines=[],
                resp_lines=[],
                phase="request",
            )
        return None

    # ── OkHttp response header ─────────────────────────────────────────────
    # IMPORTANT: this check must come BEFORE the body-accumulation block
    # because the body-accumulation block returns None for every line while
    # phase=="request", which would prevent the <-- 200 line from ever being
    # seen.  Moving the response check here lets us transition from "request"
    # to "response" when the response header arrives.
    m_resp = _OKHTTP_RESPONSE.search(line)
    if m_resp and state.get("url"):
        resp_url = m_resp.group("url")
        if _detect_provider(resp_url) or resp_url == state.get("url"):
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
            state.setdefault("resp_lines", [])
        return None

    # ── Request body accumulation ──────────────────────────────────────────
    if state.get("phase") == "request" and state.get("url"):
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state["body_lines"].append(m_body.group("body"))
        return None

    # ── Response body accumulation ─────────────────────────────────────────
    if state.get("phase") == "response":
        # Finalise on the OkHttp end-of-response marker.
        if _OKHTTP_END_RESP.search(line):
            resp_body = " ".join(state.get("resp_lines", [])) or None
            call = _finalise_call(state, resp_body)
            state.clear()
            return call
        m_body = _OKHTTP_BODY.search(line)
        if m_body:
            state.setdefault("resp_lines", []).append(m_body.group("body"))
        return None

    # ── Cronet URL detection ───────────────────────────────────────────────
    m_cronet = _CRONET_URL.search(line)
    if m_cronet:
        url = m_cronet.group("url")
        provider = _detect_provider(url)
        if provider:
            state.clear()
            state.update(
                url=url,
                method="POST",
                provider=provider,
                body_lines=[],
                resp_lines=[],
                phase="request",
            )

    return None


def _finalise_call(state: Dict, response_body: Optional[str]) -> CapturedCall:
    body_json: Optional[Dict] = None
    if state.get("body_lines"):
        try:
            body_json = json.loads(" ".join(state["body_lines"]))
        except (json.JSONDecodeError, ValueError):
            body_json = None
    # Use monotonic clock so rapid back-to-back calls get distinct IDs.
    call_id = _sha256(f"{time.monotonic()}{state.get('url', '')}")[:16]
    return CapturedCall(
        call_id=call_id,
        timestamp=time.time(),
        provider=state.get("provider", "unknown"),
        url=state.get("url", ""),
        method=state.get("method", "POST"),
        request_body=body_json,
        response_status=state.get("response_status"),
        response_body=response_body,
        source="logcat",
    )


# ---------------------------------------------------------------------------
# File-based parser
# ---------------------------------------------------------------------------

def parse_logcat_file(path: Path) -> List[CapturedCall]:
    """Parse a saved logcat dump file and return all detected LLM calls."""
    calls: List[CapturedCall] = []
    state: Dict = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            result = parse_logcat_line(raw_line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls


def load_jsonl(path: Path) -> List[CapturedCall]:
    """Load previously exported JSONL capture file."""
    calls: List[CapturedCall] = []
    with path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if raw_line:
                calls.append(CapturedCall.from_dict(json.loads(raw_line)))
    return calls


# ---------------------------------------------------------------------------
# CaptureSession (live logcat)
# ---------------------------------------------------------------------------

class CaptureSession:
    """Live capture session driven by ``adb logcat``."""

    def __init__(self, device_serial: Optional[str] = None, tag_filter: str = "OkHttp") -> None:
        self.device_serial = device_serial
        self.tag_filter = tag_filter
        self.calls: List[CapturedCall] = []
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        """Launch adb logcat as a subprocess."""
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += ["logcat", "-v", "brief", f"{self.tag_filter}:V", "*:S"]
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except FileNotFoundError:
            raise RuntimeError("adb not found — ensure Android SDK platform-tools is on PATH.")

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """Yield CapturedCall objects as they are detected from the running logcat."""
        if not self._proc:
            raise RuntimeError("Call start() before streaming.")
        state: Dict = {}
        assert self._proc.stdout is not None
        for raw_line in self._proc.stdout:
            result = parse_logcat_line(raw_line, state)
            if result:
                self.calls.append(result)
                yield result

    def export_jsonl(self, path: Path) -> None:
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        print(f"Exported {len(self.calls)} calls to {path}")

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        """Replay a captured call against the real API (injects auth header)."""
        if not call.request_body:
            raise ValueError("No request body to replay.")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if call.provider == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
        elif call.provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        elif call.provider in ("google", "azure_openai"):
            headers["Authorization"] = f"Bearer {api_key}"
        else:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = json.dumps(call.request_body).encode()
        req = urllib.request.Request(call.url, data=payload, headers=headers, method=call.method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Backwards-compatible aliases
# ---------------------------------------------------------------------------

LLMCapture = CaptureSession


def list_devices() -> List[str]:
    """Return serials of all connected, online ADB devices."""
    try:
        out = subprocess.check_output(["adb", "devices"], timeout=10, text=True,
                                      stderr=subprocess.DEVNULL)
        return [
            line.split()[0]
            for line in out.strip().splitlines()[1:]
            if line.strip() and len(line.split()) >= 2 and line.split()[1] == "device"
        ]
    except Exception:
        return []


def list_packages(device: Optional[str] = None) -> List[str]:
    """List installed packages on a connected Android device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages"]
    try:
        out = subprocess.check_output(cmd, timeout=30, text=True, stderr=subprocess.DEVNULL)
        return [line.replace("package:", "").strip()
                for line in out.splitlines() if line.startswith("package:")]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="android_llm_capture",
        description="Capture and replay Android LLM API calls.",
    )
    sub = p.add_subparsers(dest="command")

    # live
    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None, help="Android device serial (adb -s).")
    live_p.add_argument("--tag", default="OkHttp", help="Logcat tag to filter.")
    live_p.add_argument("--output", "-o", default="captures.jsonl")
    live_p.add_argument("--timeout", type=int, default=0,
                        help="Stop after N seconds (0 = run until Ctrl-C).")

    # file
    file_p = sub.add_parser("file", help="Parse a saved logcat file.")
    file_p.add_argument("logcat", help="Logcat dump file.")
    file_p.add_argument("--output", "-o", default="captures.jsonl")
    file_p.add_argument("--json", action="store_true", help="Output JSON array instead of JSONL.")

    # replay
    replay_p = sub.add_parser("replay", help="Replay a captured call.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id", help="call_id to replay (or 'last').")
    replay_p.add_argument("--api-key", required=True, help="API key for the provider.")

    # stats
    stats_p = sub.add_parser("stats", help="Show statistics about a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    # gui
    sub.add_parser("gui", help="Launch the graphical user interface.")

    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.command == "live":
        session = CaptureSession(device_serial=args.serial, tag_filter=args.tag)
        print(f"Starting live capture (tag={args.tag}). Press Ctrl-C to stop.")
        try:
            session.start()
            start = time.time()
            for call in session.stream():
                print(f"[{call.provider}] {call.method} {call.url[:60]} status={call.response_status}")
                if args.timeout and (time.time() - start) > args.timeout:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            session.stop()
        session.export_jsonl(Path(args.output))
        return 0

    if args.command == "file":
        path = Path(args.logcat)
        if not path.is_file():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1
        calls = parse_logcat_file(path)
        out = Path(args.output)
        with out.open("w", encoding="utf-8") as fh:
            if args.json:
                fh.write(json.dumps([c.to_dict() for c in calls], indent=2, ensure_ascii=False))
            else:
                for c in calls:
                    fh.write(c.to_jsonl() + "\n")
        print(f"Found {len(calls)} LLM calls → {out}")
        return 0

    if args.command == "replay":
        calls = load_jsonl(Path(args.captures))
        if not calls:
            print("No calls found.", file=sys.stderr)
            return 1
        target = (calls[-1] if args.call_id == "last"
                  else next((c for c in calls if c.call_id == args.call_id), None))
        if not target:
            print(f"call_id {args.call_id!r} not found.", file=sys.stderr)
            return 1
        session = CaptureSession()
        result = session.replay(target, api_key=args.api_key)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if args.command == "stats":
        calls = load_jsonl(Path(args.captures))
        by_provider: Dict[str, int] = {}
        by_model: Dict[str, int] = {}
        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model = c.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1
        print(f"Total calls: {len(calls)}")
        print("By provider:")
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("By model:")
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    if args.command == "gui":
        launch_gui()
        return 0

    print("android_llm_capture: specify a subcommand (live, file, replay, stats, gui)")
    print("Use --help for usage.")
    return 1


def launch_gui() -> None:
    """Launch the Tkinter GUI. Falls back to package GUI if available."""
    try:
        # Prefer the package GUI (richer feature set) when the package is installed.
        from android_llm_capture.gui import launch_gui as _pkg_gui  # type: ignore
        _pkg_gui()
    except ImportError:
        # Inline minimal GUI using only stdlib tkinter.
        _run_builtin_gui()


# ---------------------------------------------------------------------------
# Built-in minimal GUI (stdlib tkinter, no extra deps)
# ---------------------------------------------------------------------------

def _run_builtin_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, filedialog, messagebox
    except ImportError:
        print("tkinter is not available. Install it or use the CLI interface.", file=sys.stderr)
        return

    import queue
    import threading
    import datetime

    class _App(tk.Tk):
        def __init__(self) -> None:
            super().__init__()
            self.title("android-llm-capture")
            self.geometry("1100x680")
            self.minsize(800, 500)
            self._session: Optional[CaptureSession] = None
            self._thread: Optional[threading.Thread] = None
            self._queue: queue.Queue = queue.Queue()
            self._calls: List[CapturedCall] = []
            self._running = False
            self._build_ui()
            self._refresh_devices()
            self._poll()

        # ── UI construction ────────────────────────────────────────────────

        def _build_ui(self) -> None:
            self._build_menu()
            self._build_toolbar()
            self._build_body()
            self._build_statusbar()

        def _build_menu(self) -> None:
            mb = tk.Menu(self)
            fm = tk.Menu(mb, tearoff=0)
            fm.add_command(label="Open logcat / JSONL…", command=self._open_file, accelerator="Ctrl+O")
            fm.add_command(label="Export JSONL…", command=self._export, accelerator="Ctrl+S")
            fm.add_separator()
            fm.add_command(label="Quit", command=self.quit)
            mb.add_cascade(label="File", menu=fm)
            cm = tk.Menu(mb, tearoff=0)
            cm.add_command(label="Start capture", command=self._start)
            cm.add_command(label="Stop capture",  command=self._stop)
            cm.add_separator()
            cm.add_command(label="Clear calls", command=self._clear)
            mb.add_cascade(label="Capture", menu=cm)
            hm = tk.Menu(mb, tearoff=0)
            hm.add_command(label="About", command=self._about)
            mb.add_cascade(label="Help", menu=hm)
            self.config(menu=mb)
            self.bind("<Control-o>", lambda _: self._open_file())
            self.bind("<Control-s>", lambda _: self._export())

        def _build_toolbar(self) -> None:
            bar = ttk.Frame(self, padding=(4, 3))
            bar.pack(side=tk.TOP, fill=tk.X)
            ttk.Label(bar, text="Device:").pack(side=tk.LEFT, padx=(0, 2))
            self._dev_var = tk.StringVar(value="(none)")
            self._dev_cb  = ttk.Combobox(bar, textvariable=self._dev_var, width=24, state="readonly")
            self._dev_cb.pack(side=tk.LEFT, padx=(0, 4))
            ttk.Button(bar, text="⟳", command=self._refresh_devices, width=3).pack(side=tk.LEFT, padx=(0, 8))
            ttk.Label(bar, text="Tag:").pack(side=tk.LEFT, padx=(0, 2))
            self._tag_var = tk.StringVar(value="OkHttp")
            ttk.Entry(bar, textvariable=self._tag_var, width=12).pack(side=tk.LEFT, padx=(0, 8))
            ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)
            self._btn_start = ttk.Button(bar, text="▶ Start", command=self._start, width=10)
            self._btn_start.pack(side=tk.LEFT, padx=2)
            self._btn_stop  = ttk.Button(bar, text="■ Stop",  command=self._stop,  width=10, state=tk.DISABLED)
            self._btn_stop.pack(side=tk.LEFT, padx=2)
            ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)
            ttk.Button(bar, text="Open File…", command=self._open_file, width=11).pack(side=tk.LEFT, padx=2)
            ttk.Button(bar, text="Export…",    command=self._export,    width=9).pack(side=tk.LEFT, padx=2)
            ttk.Button(bar, text="Clear",      command=self._clear,     width=7).pack(side=tk.LEFT, padx=2)

        def _build_body(self) -> None:
            pw = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
            pw.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

            # ── left: calls list ───────────────────────────────────────
            lf = ttk.Frame(pw)
            pw.add(lf, weight=1)
            ttk.Label(lf, text="Captured Calls", font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W, padx=4, pady=(4, 0))
            tf = ttk.Frame(lf)
            tf.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
            cols = ("provider", "method", "model", "status", "tokens", "time")
            self._tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
            hdefs = [("provider","Provider",90), ("method","Method",58), ("model","Model",120),
                     ("status","Status",52), ("tokens","~Tokens",65), ("time","Time",70)]
            for c, h, w in hdefs:
                self._tree.heading(c, text=h, command=lambda _c=c: self._sort(_c))
                self._tree.column(c, width=w, anchor=tk.CENTER)
            vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self._tree.yview)
            self._tree.configure(yscrollcommand=vsb.set)
            self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            vsb.pack(side=tk.RIGHT, fill=tk.Y)
            self._tree.bind("<<TreeviewSelect>>", self._on_select)

            # ── right: detail notebook ─────────────────────────────────
            rf = ttk.Frame(pw)
            pw.add(rf, weight=2)
            nb = ttk.Notebook(rf)
            nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

            # Request tab
            rqf = ttk.Frame(nb); nb.add(rqf, text="Request")
            ttk.Label(rqf, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=4, pady=2)
            self._url_var = tk.StringVar()
            ttk.Entry(rqf, textvariable=self._url_var, state="readonly", width=55).grid(row=0, column=1, sticky=tk.EW, padx=4, pady=2)
            rqf.columnconfigure(1, weight=1)
            ttk.Label(rqf, text="Body:").grid(row=1, column=0, sticky=tk.NW, padx=4, pady=2)
            self._req_txt = scrolledtext.ScrolledText(rqf, wrap=tk.WORD, height=18, font=("Courier", 9))
            self._req_txt.grid(row=1, column=1, sticky=tk.NSEW, padx=4, pady=2)
            rqf.rowconfigure(1, weight=1)

            # Response tab
            rsf = ttk.Frame(nb); nb.add(rsf, text="Response")
            ttk.Label(rsf, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=4, pady=2)
            self._st_var = tk.StringVar()
            ttk.Entry(rsf, textvariable=self._st_var, state="readonly", width=8).grid(row=0, column=1, sticky=tk.W, padx=4, pady=2)
            rsf.columnconfigure(1, weight=1)
            ttk.Label(rsf, text="Body:").grid(row=1, column=0, sticky=tk.NW, padx=4, pady=2)
            self._resp_txt = scrolledtext.ScrolledText(rsf, wrap=tk.WORD, height=18, font=("Courier", 9))
            self._resp_txt.grid(row=1, column=1, sticky=tk.NSEW, padx=4, pady=2)
            rsf.rowconfigure(1, weight=1)

            # Stats tab
            stf = ttk.Frame(nb); nb.add(stf, text="Stats")
            self._stats_txt = scrolledtext.ScrolledText(stf, wrap=tk.WORD, font=("Courier", 10))
            self._stats_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        def _build_statusbar(self) -> None:
            self._status_var = tk.StringVar(value="Ready.")
            ttk.Label(self, textvariable=self._status_var, relief=tk.SUNKEN, anchor=tk.W).pack(
                side=tk.BOTTOM, fill=tk.X, padx=2, pady=1)

        # ── Device ────────────────────────────────────────────────────────

        def _refresh_devices(self) -> None:
            devs = list_devices()
            self._dev_cb["values"] = devs or ["(none)"]
            if devs:
                self._dev_cb.set(devs[0])
                self._set_status(f"{len(devs)} device(s) found.")
            else:
                self._dev_cb.set("(none)")
                self._set_status("No ADB devices found. Connect a device or start an emulator.")

        # ── Capture ───────────────────────────────────────────────────────

        def _start(self) -> None:
            if self._running:
                return
            serial = self._dev_var.get()
            if serial == "(none)":
                messagebox.showwarning("No device", "Connect a device or emulator first, then click ⟳.")
                return
            tag = self._tag_var.get().strip() or "OkHttp"
            self._session = CaptureSession(device_serial=serial, tag_filter=tag)
            try:
                self._session.start()
            except RuntimeError as exc:
                messagebox.showerror("ADB error", str(exc))
                return
            self._running = True
            self._btn_start.config(state=tk.DISABLED)
            self._btn_stop.config(state=tk.NORMAL)
            self._set_status(f"Capturing from {serial} (tag={tag})…")
            self._thread = threading.Thread(target=self._worker, daemon=True)
            self._thread.start()

        def _worker(self) -> None:
            assert self._session is not None
            try:
                for call in self._session.stream():
                    self._queue.put(call)
            except Exception:
                pass

        def _stop(self) -> None:
            if not self._running:
                return
            self._running = False
            if self._session:
                self._session.stop()
            self._btn_start.config(state=tk.NORMAL)
            self._btn_stop.config(state=tk.DISABLED)
            self._set_status(f"Capture stopped. {len(self._calls)} call(s) captured.")

        # ── Queue polling ─────────────────────────────────────────────────

        def _poll(self) -> None:
            try:
                while True:
                    call = self._queue.get_nowait()
                    self._add_call(call)
            except queue.Empty:
                pass
            finally:
                self.after(200, self._poll)

        # ── Calls ─────────────────────────────────────────────────────────

        def _add_call(self, call: CapturedCall) -> None:
            self._calls.append(call)
            ts = datetime.datetime.fromtimestamp(call.timestamp).strftime("%H:%M:%S")
            self._tree.insert("", tk.END, iid=call.call_id, values=(
                call.provider, call.method, call.model or "—",
                str(call.response_status or "?"),
                call.prompt_tokens_estimate, ts,
            ))
            self._tree.see(call.call_id)
            self._update_stats()

        def _clear(self) -> None:
            self._calls.clear()
            if self._session:
                self._session.calls.clear()
            for item in self._tree.get_children():
                self._tree.delete(item)
            self._clear_detail()
            self._update_stats()
            self._set_status("Cleared.")

        def _on_select(self, _evt) -> None:
            sel = self._tree.selection()
            if not sel:
                return
            call = next((c for c in self._calls if c.call_id == sel[0]), None)
            if call:
                self._show_detail(call)

        def _show_detail(self, call: CapturedCall) -> None:
            self._url_var.set(call.url)
            self._st_var.set(str(call.response_status or ""))
            for txt, content in (
                (self._req_txt,  json.dumps(call.request_body, indent=2, ensure_ascii=False) if call.request_body else ""),
                (self._resp_txt, self._fmt_body(call.response_body)),
            ):
                txt.config(state=tk.NORMAL)
                txt.delete("1.0", tk.END)
                txt.insert(tk.END, content)
                txt.config(state=tk.DISABLED)

        def _fmt_body(self, body: Optional[str]) -> str:
            if not body:
                return ""
            try:
                return json.dumps(json.loads(body), indent=2, ensure_ascii=False)
            except (json.JSONDecodeError, TypeError):
                return body

        def _clear_detail(self) -> None:
            self._url_var.set("")
            self._st_var.set("")
            for txt in (self._req_txt, self._resp_txt):
                txt.config(state=tk.NORMAL)
                txt.delete("1.0", tk.END)
                txt.config(state=tk.DISABLED)

        def _update_stats(self) -> None:
            by_p: Dict[str, int] = {}
            by_m: Dict[str, int] = {}
            total_tok = 0
            for c in self._calls:
                by_p[c.provider] = by_p.get(c.provider, 0) + 1
                by_m[c.model or "unknown"] = by_m.get(c.model or "unknown", 0) + 1
                total_tok += c.prompt_tokens_estimate
            lines = [
                f"Total calls : {len(self._calls)}",
                f"Est. tokens : {total_tok:,}",
                "",
                "By provider:",
                *[f"  {k:<22} {v}" for k, v in sorted(by_p.items(), key=lambda x: -x[1])],
                "",
                "By model:",
                *[f"  {k:<30} {v}" for k, v in sorted(by_m.items(), key=lambda x: -x[1])],
            ]
            self._stats_txt.config(state=tk.NORMAL)
            self._stats_txt.delete("1.0", tk.END)
            self._stats_txt.insert(tk.END, "\n".join(lines))
            self._stats_txt.config(state=tk.DISABLED)

        # ── Sorting ───────────────────────────────────────────────────────

        def _sort(self, col: str) -> None:
            rows = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
            rows.sort()
            for i, (_, k) in enumerate(rows):
                self._tree.move(k, "", i)

        # ── File I/O ──────────────────────────────────────────────────────

        def _open_file(self) -> None:
            path = filedialog.askopenfilename(
                title="Open logcat / JSONL file",
                filetypes=[("Logcat / JSONL", "*.log *.txt *.jsonl"), ("All files", "*.*")],
            )
            if not path:
                return
            p = Path(path)
            try:
                calls = load_jsonl(p) if p.suffix == ".jsonl" else parse_logcat_file(p)
            except Exception as exc:
                messagebox.showerror("Error", f"Failed to parse:\n{exc}")
                return
            for call in calls:
                self._add_call(call)
            self._set_status(f"Loaded {len(calls)} call(s) from {p.name}")

        def _export(self) -> None:
            if not self._calls:
                messagebox.showinfo("Nothing to export", "No captured calls yet.")
                return
            path = filedialog.asksaveasfilename(
                title="Export captures",
                defaultextension=".jsonl",
                filetypes=[("JSONL", "*.jsonl"), ("JSON", "*.json"), ("All files", "*.*")],
            )
            if not path:
                return
            p = Path(path)
            with p.open("w", encoding="utf-8") as fh:
                for call in self._calls:
                    fh.write(call.to_jsonl() + "\n")
            self._set_status(f"Exported {len(self._calls)} call(s) to {p.name}")

        # ── Misc ──────────────────────────────────────────────────────────

        def _set_status(self, msg: str) -> None:
            self._status_var.set(msg)

        def _about(self) -> None:
            messagebox.showinfo(
                "About android-llm-capture",
                "android-llm-capture v0.1.0\n\n"
                "ADB-based tool for capturing LLM API interactions\n"
                "from Android devices and emulators.\n\n"
                "Author: Vaibhav Deshmukh\n"
                "License: MIT\n\n"
                "Subcommands: live · file · replay · stats · gui",
            )

    _App().mainloop()


# ---------------------------------------------------------------------------
# Entry-point aliases
# ---------------------------------------------------------------------------

_cli = main   # referenced by older pyproject.toml configs


if __name__ == "__main__":
    sys.exit(main())
