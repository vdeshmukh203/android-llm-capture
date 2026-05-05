"""Tkinter graphical interface for android-llm-capture.

Launch via ``android-llm-capture gui`` or ``python -m android_llm_capture.gui``.
No external dependencies beyond the Python standard library.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import tkinter.ttk as ttk
from pathlib import Path
from typing import List, Optional

from .adb import ADBClient
from .capture import CaptureSession
from .models import CapturedCall
from .parser import parse_logcat_file


# ---------------------------------------------------------------------------
# Live Capture tab
# ---------------------------------------------------------------------------

class _LiveTab(ttk.Frame):
    """Tab for streaming live logcat capture."""

    _POLL_MS = 200  # queue poll interval

    def __init__(self, parent: ttk.Notebook, status_var: tk.StringVar) -> None:
        super().__init__(parent, padding=8)
        self._status = status_var
        self._session: Optional[CaptureSession] = None
        self._thread: Optional[threading.Thread] = None
        self._queue: queue.Queue = queue.Queue()
        self._running = False
        self._calls: List[CapturedCall] = []
        self._build()

    def _build(self) -> None:
        # ── Settings ────────────────────────────────────────────────
        ctrl = ttk.LabelFrame(self, text="Capture Settings", padding=6)
        ctrl.pack(fill=tk.X, pady=(0, 6))
        ctrl.columnconfigure(1, weight=1)

        ttk.Label(ctrl, text="Device:").grid(row=0, column=0, sticky=tk.W, padx=(0, 4))
        self._device_var = tk.StringVar(value="(auto)")
        self._device_cb = ttk.Combobox(ctrl, textvariable=self._device_var, width=30)
        self._device_cb.grid(row=0, column=1, sticky=tk.W)
        ttk.Button(ctrl, text="Refresh", command=self._refresh_devices, width=8).grid(
            row=0, column=2, padx=(4, 0)
        )

        ttk.Label(ctrl, text="Tag filter:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self._tag_var = tk.StringVar(value="OkHttp")
        ttk.Entry(ctrl, textvariable=self._tag_var, width=20).grid(row=1, column=1, sticky=tk.W)

        ttk.Label(ctrl, text="Timeout (s, 0=∞):").grid(row=2, column=0, sticky=tk.W)
        self._timeout_var = tk.StringVar(value="0")
        ttk.Entry(ctrl, textvariable=self._timeout_var, width=8).grid(row=2, column=1, sticky=tk.W)

        ttk.Label(ctrl, text="Output file:").grid(row=3, column=0, sticky=tk.W, pady=4)
        self._output_var = tk.StringVar(value="captures.jsonl")
        ttk.Entry(ctrl, textvariable=self._output_var, width=36).grid(row=3, column=1, sticky=tk.EW)
        ttk.Button(ctrl, text="Browse…", command=self._browse_output, width=8).grid(
            row=3, column=2, padx=(4, 0)
        )

        # ── Buttons ─────────────────────────────────────────────────
        btn = ttk.Frame(self)
        btn.pack(fill=tk.X, pady=(0, 6))
        self._start_btn = ttk.Button(btn, text="▶  Start Capture", command=self._start)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 6))
        self._stop_btn = ttk.Button(
            btn, text="■  Stop & Export", command=self._stop, state=tk.DISABLED
        )
        self._stop_btn.pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn, text="Clear", command=self._clear).pack(side=tk.LEFT)

        # ── Call list ────────────────────────────────────────────────
        log_frame = ttk.LabelFrame(self, text="Captured Calls", padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("time", "provider", "method", "url", "status", "model")
        self._tree = ttk.Treeview(
            log_frame, columns=cols, show="headings", selectmode="browse"
        )
        for col, hdr, w in [
            ("time",     "Time",     68),
            ("provider", "Provider", 90),
            ("method",   "Method",   58),
            ("url",      "URL",      300),
            ("status",   "Status",   56),
            ("model",    "Model",    120),
        ]:
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w, anchor=tk.W, stretch=(col == "url"))

        vsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self._tree.yview)
        hsb = ttk.Scrollbar(log_frame, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self._refresh_devices()
        self.after(self._POLL_MS, self._poll_queue)

    # ── Helpers ─────────────────────────────────────────────────────

    def _refresh_devices(self) -> None:
        devices = ADBClient.list_devices()
        values = ["(auto)"] + devices
        self._device_cb["values"] = values
        if self._device_var.get() not in values:
            self._device_var.set("(auto)")
        self._status.set(
            f"Found {len(devices)} device(s)." if devices else "No ADB devices found."
        )

    def _browse_output(self) -> None:
        p = fd.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")],
            title="Save captures as…",
        )
        if p:
            self._output_var.set(p)

    # ── Capture lifecycle ────────────────────────────────────────────

    def _start(self) -> None:
        raw_serial = self._device_var.get()
        serial = None if raw_serial == "(auto)" else raw_serial
        tag = self._tag_var.get().strip() or "OkHttp"
        try:
            timeout = int(self._timeout_var.get())
        except ValueError:
            mb.showerror("Invalid input", "Timeout must be an integer (seconds).")
            return

        self._session = CaptureSession(device_serial=serial, tag_filter=tag)
        self._calls.clear()
        try:
            self._session.start()
        except RuntimeError as exc:
            mb.showerror("ADB Error", str(exc))
            self._session = None
            return

        self._running = True
        self._start_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)
        self._status.set("Capturing…")
        self._thread = threading.Thread(
            target=self._worker, args=(timeout,), daemon=True
        )
        self._thread.start()

    def _worker(self, timeout: int) -> None:
        deadline = time.monotonic() + timeout if timeout else None
        try:
            assert self._session is not None
            for call in self._session.stream():
                if not self._running:
                    break
                self._queue.put(call)
                if deadline and time.monotonic() > deadline:
                    self._queue.put("TIMEOUT")
                    break
        except Exception as exc:  # noqa: BLE001
            self._queue.put(exc)

    def _stop(self) -> None:
        self._running = False
        if self._session:
            self._session.stop()
        n = len(self._calls)
        out = Path(self._output_var.get())
        if n and self._session:
            try:
                self._session.export_jsonl(out)
                self._status.set(f"Exported {n} call(s) to {out.name!r}.")
            except OSError as exc:
                mb.showerror("Export Error", str(exc))
                self._status.set("Export failed.")
        else:
            self._status.set("Capture stopped — no calls captured.")
        self._start_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)

    def _clear(self) -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._calls.clear()

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self._queue.get_nowait()
                if isinstance(item, Exception):
                    mb.showerror("Capture Error", str(item))
                    self._stop()
                elif item == "TIMEOUT":
                    self._status.set("Timeout reached.")
                    self._stop()
                elif isinstance(item, CapturedCall):
                    self._calls.append(item)
                    ts = time.strftime("%H:%M:%S", time.localtime(item.timestamp))
                    self._tree.insert(
                        "",
                        tk.END,
                        values=(
                            ts,
                            item.provider,
                            item.method,
                            item.url,
                            item.response_status or "?",
                            item.model or "—",
                        ),
                    )
                    self._tree.yview_moveto(1.0)
                    self._status.set(f"Captured {len(self._calls)} call(s).")
        except queue.Empty:
            pass
        self.after(self._POLL_MS, self._poll_queue)


# ---------------------------------------------------------------------------
# Parse File tab
# ---------------------------------------------------------------------------

class _FileTab(ttk.Frame):
    """Tab for parsing saved logcat dump files."""

    def __init__(self, parent: ttk.Notebook, status_var: tk.StringVar) -> None:
        super().__init__(parent, padding=8)
        self._status = status_var
        self._calls: List[CapturedCall] = []
        self._build()

    def _build(self) -> None:
        ctrl = ttk.LabelFrame(self, text="Parse Settings", padding=6)
        ctrl.pack(fill=tk.X, pady=(0, 6))
        ctrl.columnconfigure(1, weight=1)

        ttk.Label(ctrl, text="Logcat file:").grid(row=0, column=0, sticky=tk.W, padx=(0, 4))
        self._input_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._input_var, width=44).grid(
            row=0, column=1, sticky=tk.EW
        )
        ttk.Button(ctrl, text="Browse…", command=self._browse_input, width=8).grid(
            row=0, column=2, padx=(4, 0)
        )

        ttk.Label(ctrl, text="Output file:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self._output_var = tk.StringVar(value="captures.jsonl")
        ttk.Entry(ctrl, textvariable=self._output_var, width=44).grid(
            row=1, column=1, sticky=tk.EW
        )
        ttk.Button(ctrl, text="Browse…", command=self._browse_output, width=8).grid(
            row=1, column=2, padx=(4, 0)
        )

        self._json_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            ctrl,
            text="Write pretty-printed JSON array (instead of JSONL)",
            variable=self._json_var,
        ).grid(row=2, column=1, sticky=tk.W, pady=(0, 4))

        ttk.Button(self, text="Parse File", command=self._parse).pack(pady=(0, 8))

        res = ttk.LabelFrame(self, text="Results", padding=4)
        res.pack(fill=tk.BOTH, expand=True)

        cols = ("call_id", "provider", "method", "url", "status", "model")
        self._tree = ttk.Treeview(res, columns=cols, show="headings", selectmode="browse")
        for col, hdr, w in [
            ("call_id",  "Call ID",  110),
            ("provider", "Provider",  86),
            ("method",   "Method",    58),
            ("url",      "URL",       280),
            ("status",   "Status",    56),
            ("model",    "Model",     120),
        ]:
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w, anchor=tk.W, stretch=(col == "url"))

        vsb = ttk.Scrollbar(res, orient=tk.VERTICAL, command=self._tree.yview)
        hsb = ttk.Scrollbar(res, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)
        res.rowconfigure(0, weight=1)
        res.columnconfigure(0, weight=1)

    def _browse_input(self) -> None:
        p = fd.askopenfilename(
            filetypes=[("Text / Log", "*.txt *.log"), ("All files", "*")],
            title="Select logcat dump file",
        )
        if p:
            self._input_var.set(p)

    def _browse_output(self) -> None:
        p = fd.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("JSON", "*.json"), ("All files", "*")],
            title="Save captures as…",
        )
        if p:
            self._output_var.set(p)

    def _parse(self) -> None:
        src = self._input_var.get().strip()
        if not src:
            mb.showerror("Input required", "Select a logcat file to parse.")
            return
        path = Path(src)
        if not path.is_file():
            mb.showerror("File not found", f"{path}")
            return

        for item in self._tree.get_children():
            self._tree.delete(item)

        calls = parse_logcat_file(path)
        self._calls = calls
        out = Path(self._output_var.get())
        try:
            with out.open("w", encoding="utf-8") as fh:
                if self._json_var.get():
                    json.dump([c.to_dict() for c in calls], fh, indent=2, ensure_ascii=False)
                else:
                    for c in calls:
                        fh.write(c.to_jsonl() + "\n")
        except OSError as exc:
            mb.showerror("Write error", str(exc))
            return

        for c in calls:
            self._tree.insert(
                "",
                tk.END,
                values=(
                    c.call_id[:14],
                    c.provider,
                    c.method,
                    c.url,
                    c.response_status or "?",
                    c.model or "—",
                ),
            )
        self._status.set(
            f"Parsed {len(calls)} call(s) from {path.name!r} → {out.name!r}."
        )


# ---------------------------------------------------------------------------
# Statistics tab
# ---------------------------------------------------------------------------

class _StatsTab(ttk.Frame):
    """Tab for summary statistics over a captures file."""

    def __init__(self, parent: ttk.Notebook, status_var: tk.StringVar) -> None:
        super().__init__(parent, padding=8)
        self._status = status_var
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(top, text="Captures file:").pack(side=tk.LEFT, padx=(0, 4))
        self._file_var = tk.StringVar()
        ttk.Entry(top, textvariable=self._file_var, width=42).pack(side=tk.LEFT)
        ttk.Button(top, text="Browse…", command=self._browse).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Load", command=self._load).pack(side=tk.LEFT)

        self._text = tk.Text(
            self,
            state=tk.DISABLED,
            font=("Courier", 11),
            relief=tk.FLAT,
            background="#f5f5f5",
            wrap=tk.NONE,
        )
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._text.yview)
        self._text.configure(yscrollcommand=vsb.set)
        self._text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _browse(self) -> None:
        p = fd.askopenfilename(
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")],
            title="Open captures file",
        )
        if p:
            self._file_var.set(p)

    def _load(self) -> None:
        path_str = self._file_var.get().strip()
        if not path_str:
            mb.showerror("Input required", "Select a captures file.")
            return
        path = Path(path_str)
        if not path.is_file():
            mb.showerror("File not found", f"{path}")
            return

        raw: list = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        raw.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        by_provider: dict = {}
        by_model: dict = {}
        by_status: dict = {}
        total_tokens = 0

        for c in raw:
            prov = c.get("provider", "unknown")
            by_provider[prov] = by_provider.get(prov, 0) + 1
            model = (c.get("request_body") or {}).get("model", "unknown")
            by_model[model] = by_model.get(model, 0) + 1
            status = str(c.get("response_status", "?"))
            by_status[status] = by_status.get(status, 0) + 1
            msgs = (c.get("request_body") or {}).get("messages", [])
            text = " ".join(m.get("content", "") for m in msgs if isinstance(m, dict))
            total_tokens += max(1, len(text.split()) * 4 // 3) if text else 0

        col = 26
        lines = [
            f"File              : {path}",
            f"Total calls       : {len(raw)}",
            f"Est. prompt tokens: {total_tokens}",
            "",
            "By Provider:",
            *[f"  {k:<{col}} {v}" for k, v in sorted(by_provider.items(), key=lambda x: -x[1])],
            "",
            "By Model:",
            *[f"  {k:<{col}} {v}" for k, v in sorted(by_model.items(), key=lambda x: -x[1])],
            "",
            "By HTTP Status:",
            *[f"  {k:<{col}} {v}" for k, v in sorted(by_status.items(), key=lambda x: -x[1])],
        ]
        content = "\n".join(lines)

        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.insert(tk.END, content)
        self._text.configure(state=tk.DISABLED)
        self._status.set(f"Statistics loaded from {path.name!r}.")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class AndroidLLMCaptureGUI(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Android LLM Capture")
        self.geometry("960x620")
        self.minsize(720, 460)
        self._build()

    def _build(self) -> None:
        self._status_var = tk.StringVar(value="Ready.")

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        nb.add(_LiveTab(nb, self._status_var), text="  Live Capture  ")
        nb.add(_FileTab(nb, self._status_var), text="  Parse File  ")
        nb.add(_StatsTab(nb, self._status_var), text="  Statistics  ")

        ttk.Label(
            self, textvariable=self._status_var, relief=tk.SUNKEN, anchor=tk.W
        ).pack(fill=tk.X, side=tk.BOTTOM, padx=4, pady=(0, 2))

        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About…", command=self._about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menubar)

    def _about(self) -> None:
        mb.showinfo(
            "About android-llm-capture",
            "android-llm-capture\n\n"
            "ADB-based tool for capturing LLM API interactions\n"
            "from Android devices.\n\n"
            "© Vaibhav Deshmukh — MIT License",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def launch_gui() -> None:
    """Create and run the GUI event loop."""
    app = AndroidLLMCaptureGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
