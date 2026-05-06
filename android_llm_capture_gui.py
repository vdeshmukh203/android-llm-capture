#!/usr/bin/env python3
"""
android_llm_capture_gui.py — Tkinter GUI for Android LLM Capture.

Provides a five-tab interface: Devices, Live Capture, Parse File,
View Captures, and Statistics.  Requires only the stdlib (tkinter + the
android_llm_capture module shipped alongside this file).
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

# The root android_llm_capture.py must be importable (either installed or on
# sys.path).  The tests already insert the project root, so this works in both
# development and installed scenarios.
from android_llm_capture import (
    CaptureSession,
    CapturedCall,
    parse_logcat_file,
    list_devices,
)


# ---------------------------------------------------------------------------
# Colour palette (dark Catppuccin-ish theme)
# ---------------------------------------------------------------------------

_BG     = "#1e1e2e"
_FG     = "#cdd6f4"
_ENTRY  = "#313244"
_ACCENT = "#89b4fa"
_GREEN  = "#a6e3a1"
_RED    = "#f38ba8"
_BORDER = "#45475a"
_MUTED  = "#6c7086"


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class App(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Android LLM Capture  v0.1.0")
        self.geometry("1020x720")
        self.minsize(820, 560)
        self.configure(bg=_BG)
        self._apply_style()
        self._build_notebook()

    # ── theme ────────────────────────────────────────────────────────────────

    def _apply_style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(
            ".",
            background=_BG, foreground=_FG,
            fieldbackground=_ENTRY, troughcolor=_ENTRY,
            bordercolor=_BORDER, focuscolor=_ACCENT,
        )
        s.configure("TNotebook", background=_BG, borderwidth=0)
        s.configure(
            "TNotebook.Tab",
            background=_ENTRY, foreground=_FG,
            padding=[14, 5], borderwidth=0,
        )
        s.map(
            "TNotebook.Tab",
            background=[("selected", _ACCENT)],
            foreground=[("selected", _BG)],
        )
        s.configure("TFrame",  background=_BG)
        s.configure("TLabel",  background=_BG, foreground=_FG)
        s.configure("TSeparator", background=_BORDER)
        s.configure(
            "TButton",
            background=_ENTRY, foreground=_FG,
            borderwidth=1, focusthickness=0, padding=[8, 4],
        )
        s.map("TButton",
              background=[("active", _ACCENT)],
              foreground=[("active", _BG)])
        s.configure(
            "TEntry",
            fieldbackground=_ENTRY, foreground=_FG,
            insertcolor=_FG, borderwidth=1,
        )
        s.configure(
            "TSpinbox",
            fieldbackground=_ENTRY, foreground=_FG, arrowcolor=_FG,
        )
        s.configure(
            "Treeview",
            background=_ENTRY, foreground=_FG,
            fieldbackground=_ENTRY, borderwidth=0, rowheight=22,
        )
        s.configure(
            "Treeview.Heading",
            background=_BG, foreground=_ACCENT,
            borderwidth=0, relief="flat",
        )
        s.map("Treeview",
              background=[("selected", _ACCENT)],
              foreground=[("selected", _BG)])
        s.configure(
            "TScrollbar",
            background=_ENTRY, troughcolor=_BG, borderwidth=0, arrowcolor=_FG,
        )
        s.configure("TRadiobutton", background=_BG, foreground=_FG)
        # Coloured action buttons
        s.configure("Green.TButton",
                    background="#2d4a35", foreground=_GREEN, borderwidth=1)
        s.configure("Red.TButton",
                    background="#4a2d2d", foreground=_RED,   borderwidth=1)
        s.map("Green.TButton",
              background=[("active", _GREEN)], foreground=[("active", _BG)])
        s.map("Red.TButton",
              background=[("active", _RED)],   foreground=[("active", _BG)])

    # ── notebook ─────────────────────────────────────────────────────────────

    def _build_notebook(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self._tab_devices = DevicesTab(nb)
        self._tab_capture = CaptureTab(nb, self._tab_devices)
        self._tab_file    = FileParseTab(nb)
        self._tab_viewer  = ViewerTab(nb)
        self._tab_stats   = StatsTab(nb)

        nb.add(self._tab_devices, text="  Devices  ")
        nb.add(self._tab_capture, text="  Live Capture  ")
        nb.add(self._tab_file,    text="  Parse File  ")
        nb.add(self._tab_viewer,  text="  View Captures  ")
        nb.add(self._tab_stats,   text="  Statistics  ")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _lbl(parent, text: str = "", **kw) -> ttk.Label:
    return ttk.Label(parent, text=text, **kw)


def _btn(parent, text: str, cmd, style: Optional[str] = None, **kw) -> ttk.Button:
    if style:
        kw["style"] = style
    return ttk.Button(parent, text=text, command=cmd, **kw)


def _entry(parent, var: tk.Variable, width: int = 30) -> ttk.Entry:
    return ttk.Entry(parent, textvariable=var, width=width)


def _scrolled_text(parent, **kw) -> scrolledtext.ScrolledText:
    defaults = dict(
        state="disabled",
        bg=_ENTRY, fg=_FG,
        font=("Courier", 9),
        relief=tk.FLAT,
        insertbackground=_FG,
    )
    defaults.update(kw)
    return scrolledtext.ScrolledText(parent, **defaults)


def _text_set(widget: scrolledtext.ScrolledText, content: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", tk.END)
    widget.insert("1.0", content)
    widget.configure(state="disabled")


def _text_append(widget: scrolledtext.ScrolledText, content: str) -> None:
    widget.configure(state="normal")
    widget.insert(tk.END, content)
    widget.see(tk.END)
    widget.configure(state="disabled")


# ---------------------------------------------------------------------------
# Devices tab
# ---------------------------------------------------------------------------

class DevicesTab(ttk.Frame):
    """Lists all ADB devices currently visible to the host machine."""

    def __init__(self, parent) -> None:
        super().__init__(parent)
        self._build()
        self.refresh()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=12, pady=8)
        _lbl(top, "Connected ADB Devices").pack(side=tk.LEFT)
        _btn(top, "Refresh", self.refresh).pack(side=tk.RIGHT)

        cols = ("serial", "status")
        self._tree = ttk.Treeview(
            self, columns=cols, show="headings", selectmode="browse",
        )
        self._tree.heading("serial", text="Device Serial")
        self._tree.heading("status", text="Status")
        self._tree.column("serial", width=320)
        self._tree.column("status", width=100)

        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 4), side=tk.LEFT)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=(0, 4))

        self._status_var = tk.StringVar(value="")
        _lbl(self, textvariable=self._status_var).pack(pady=4)

    def refresh(self) -> None:
        for row in self._tree.get_children():
            self._tree.delete(row)
        devs = list_devices()
        if devs:
            for d in devs:
                self._tree.insert("", tk.END, values=(d, "online"))
            self._status_var.set(f"{len(devs)} device(s) found")
        else:
            self._tree.insert("", tk.END, values=("(no devices connected)", ""))
            self._status_var.set(
                "No ADB devices found — connect a device or start an emulator"
            )

    def selected_serial(self) -> Optional[str]:
        sel = self._tree.selection()
        if not sel:
            return None
        val = self._tree.item(sel[0], "values")[0]
        return None if val.startswith("(") else val


# ---------------------------------------------------------------------------
# Live Capture tab
# ---------------------------------------------------------------------------

class CaptureTab(ttk.Frame):
    """Controls for starting / stopping a live ADB logcat capture session."""

    def __init__(self, parent, devices_tab: DevicesTab) -> None:
        super().__init__(parent)
        self._devices   = devices_tab
        self._session: Optional[CaptureSession] = None
        self._q: queue.Queue = queue.Queue()
        self._running   = False
        self._call_count = 0
        self._outpath   = "captures.jsonl"
        self._build()

    def _build(self) -> None:
        cfg = ttk.Frame(self)
        cfg.pack(fill=tk.X, padx=12, pady=8)

        # ── configuration grid ──────────────────────────────────────────────
        rows = [
            ("Device serial:",        "_serial_var", None),
            ("Logcat tag:",           "_tag_var",    "OkHttp"),
            ("Output file:",          "_out_var",    "captures.jsonl"),
            ("Timeout (sec, 0 = ∞):", None,          None),
        ]
        for r, (label, attr, default) in enumerate(rows):
            _lbl(cfg, label).grid(row=r, column=0, sticky=tk.W, pady=3)
            if attr:
                var = tk.StringVar(value=default or "")
                setattr(self, attr, var)
                _entry(cfg, var, 28).grid(row=r, column=1, sticky=tk.W, padx=4)

        # "Use selected" button next to serial
        _btn(cfg, "Use selected", self._use_selected).grid(
            row=0, column=2, padx=4,
        )
        # Browse button next to output file
        _btn(cfg, "Browse…", self._browse_out).grid(row=2, column=2, padx=4)

        # Timeout spinbox
        self._timeout_var = tk.IntVar(value=0)
        ttk.Spinbox(
            cfg, from_=0, to=3600, textvariable=self._timeout_var, width=8,
        ).grid(row=3, column=1, sticky=tk.W, padx=4)

        # ── action buttons ──────────────────────────────────────────────────
        btn_row = ttk.Frame(cfg)
        btn_row.grid(row=4, column=0, columnspan=3, pady=10, sticky=tk.W)

        self._start_btn = _btn(
            btn_row, "▶  Start Capture", self._start, style="Green.TButton",
        )
        self._start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._stop_btn = _btn(
            btn_row, "■  Stop", self._stop, style="Red.TButton",
        )
        self._stop_btn.pack(side=tk.LEFT)
        self._stop_btn.state(["disabled"])

        self._status_var = tk.StringVar(value="Ready")
        _lbl(cfg, textvariable=self._status_var).grid(
            row=4, column=1, columnspan=2, sticky=tk.W,
        )

        # ── live log ────────────────────────────────────────────────────────
        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=2)

        hdr = ttk.Frame(self)
        hdr.pack(fill=tk.X, padx=12)
        _lbl(hdr, "Captured calls:").pack(side=tk.LEFT)
        self._count_var = tk.StringVar(value="0 calls")
        _lbl(hdr, textvariable=self._count_var, foreground=_ACCENT).pack(
            side=tk.RIGHT,
        )

        self._log = _scrolled_text(self, wrap=tk.NONE)
        self._log.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 10))

    # ── event handlers ───────────────────────────────────────────────────────

    def _use_selected(self) -> None:
        serial = self._devices.selected_serial()
        if serial:
            self._serial_var.set(serial)

    def _browse_out(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")],
        )
        if path:
            self._out_var.set(path)

    def _start(self) -> None:
        serial  = self._serial_var.get().strip() or None
        tag     = self._tag_var.get().strip() or "OkHttp"
        outpath = self._out_var.get().strip() or "captures.jsonl"
        timeout = int(self._timeout_var.get())

        self._session = CaptureSession(device_serial=serial, tag_filter=tag)
        try:
            self._session.start()
        except RuntimeError as exc:
            messagebox.showerror("ADB Error", str(exc))
            self._session = None
            return

        self._running    = True
        self._call_count = 0
        self._outpath    = outpath
        _text_set(self._log, "")
        self._status_var.set(f"Capturing…  tag={tag}")
        self._start_btn.state(["disabled"])
        self._stop_btn.state(["!disabled"])

        threading.Thread(
            target=self._worker, args=(timeout,), daemon=True,
        ).start()
        self._poll()

    def _worker(self, timeout: int) -> None:
        import time
        start = time.time()
        try:
            for call in self._session.stream():
                self._q.put(call)
                if timeout and (time.time() - start) > timeout:
                    break
        except Exception as exc:
            self._q.put(exc)
        finally:
            self._q.put(None)  # sentinel — signals the poll loop to stop

    def _poll(self) -> None:
        try:
            while True:
                item = self._q.get_nowait()
                if item is None:
                    self._on_done()
                    return
                if isinstance(item, Exception):
                    messagebox.showerror("Capture error", str(item))
                    self._on_done()
                    return
                self._call_count += 1
                self._count_var.set(f"{self._call_count} call(s)")
                _text_append(
                    self._log,
                    f"[{item.provider.upper():12s}] {item.method}  "
                    f"{item.url[:58]}  →  {item.response_status}\n",
                )
        except queue.Empty:
            pass
        if self._running:
            self.after(150, self._poll)

    def _on_done(self) -> None:
        self._running = False
        if self._session:
            self._session.stop()
            self._session.export_jsonl(Path(self._outpath))
        self._status_var.set(
            f"Done — {self._call_count} call(s) saved to {self._outpath}"
        )
        self._start_btn.state(["!disabled"])
        self._stop_btn.state(["disabled"])

    def _stop(self) -> None:
        self._running = False
        if self._session:
            self._session.stop()


# ---------------------------------------------------------------------------
# Parse File tab
# ---------------------------------------------------------------------------

class FileParseTab(ttk.Frame):
    """Parse a saved logcat dump file and export the detected LLM calls."""

    def __init__(self, parent) -> None:
        super().__init__(parent)
        self._calls: list = []
        self._build()

    def _build(self) -> None:
        cfg = ttk.Frame(self)
        cfg.pack(fill=tk.X, padx=12, pady=8)
        cfg.columnconfigure(1, weight=1)

        _lbl(cfg, "Logcat file:").grid(row=0, column=0, sticky=tk.W)
        self._file_var = tk.StringVar()
        _entry(cfg, self._file_var, 42).grid(row=0, column=1, padx=4, sticky=tk.EW)
        _btn(cfg, "Browse…", self._browse_in).grid(row=0, column=2, padx=4)

        _lbl(cfg, "Output file:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self._out_var = tk.StringVar(value="captures.jsonl")
        _entry(cfg, self._out_var, 42).grid(row=1, column=1, padx=4, sticky=tk.EW)
        _btn(cfg, "Browse…", self._browse_out).grid(row=1, column=2, padx=4)

        fmt_row = ttk.Frame(cfg)
        fmt_row.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=4)
        _lbl(fmt_row, "Format:").pack(side=tk.LEFT)
        self._fmt_var = tk.StringVar(value="jsonl")
        ttk.Radiobutton(
            fmt_row, text="JSONL", variable=self._fmt_var, value="jsonl",
        ).pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(
            fmt_row, text="JSON array", variable=self._fmt_var, value="json",
        ).pack(side=tk.LEFT)

        action_row = ttk.Frame(cfg)
        action_row.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=4)
        _btn(action_row, "Parse File", self._parse).pack(side=tk.LEFT, padx=(0, 8))
        _btn(action_row, "Save Output", self._save).pack(side=tk.LEFT)

        self._status_var = tk.StringVar(value="")
        _lbl(cfg, textvariable=self._status_var, foreground=_ACCENT).grid(
            row=4, column=0, columnspan=3, sticky=tk.W,
        )

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=4)

        cols = ("call_id", "provider", "method", "url", "status")
        self._tree = ttk.Treeview(self, columns=cols, show="headings")
        for col, width in zip(cols, (120, 90, 60, 370, 60)):
            self._tree.heading(col, text=col.replace("_", " ").title())
            self._tree.column(col, width=width, minwidth=40)
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL,   command=self._tree.yview)
        hsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.pack(fill=tk.BOTH, expand=True, padx=12, side=tk.LEFT)
        vsb.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))

    def _browse_in(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Log files", "*.txt *.log"), ("All files", "*")],
        )
        if path:
            self._file_var.set(path)

    def _browse_out(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("JSON", "*.json"), ("All files", "*")],
        )
        if path:
            self._out_var.set(path)

    def _parse(self) -> None:
        path = Path(self._file_var.get().strip())
        if not path.is_file():
            messagebox.showerror("Error", f"File not found:\n{path}")
            return
        try:
            self._calls = parse_logcat_file(path)
        except Exception as exc:
            messagebox.showerror("Parse error", str(exc))
            return
        for row in self._tree.get_children():
            self._tree.delete(row)
        for c in self._calls:
            self._tree.insert(
                "", tk.END,
                values=(
                    c.call_id[:14], c.provider, c.method,
                    c.url[:72], c.response_status or "—",
                ),
            )
        self._status_var.set(f"Found {len(self._calls)} LLM call(s)")

    def _save(self) -> None:
        if not self._calls:
            messagebox.showwarning("Nothing to save", "Parse a file first.")
            return
        out = Path(self._out_var.get().strip())
        try:
            with out.open("w", encoding="utf-8") as fh:
                if self._fmt_var.get() == "json":
                    fh.write(
                        json.dumps(
                            [c.to_dict() for c in self._calls],
                            indent=2, ensure_ascii=False,
                        )
                    )
                else:
                    for c in self._calls:
                        fh.write(c.to_jsonl() + "\n")
            messagebox.showinfo("Saved", f"Saved {len(self._calls)} call(s) to:\n{out}")
        except Exception as exc:
            messagebox.showerror("Save error", str(exc))


# ---------------------------------------------------------------------------
# View Captures tab
# ---------------------------------------------------------------------------

class ViewerTab(ttk.Frame):
    """Browse captured calls from a JSONL file with a detail pane."""

    def __init__(self, parent) -> None:
        super().__init__(parent)
        self._calls: list = []
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=12, pady=8)
        _lbl(top, "Captures file (.jsonl):").pack(side=tk.LEFT)
        self._file_var = tk.StringVar()
        _entry(top, self._file_var, 38).pack(side=tk.LEFT, padx=4)
        _btn(top, "Browse…", self._browse).pack(side=tk.LEFT)
        _btn(top, "Load", self._load).pack(side=tk.LEFT, padx=(8, 0))
        self._count_var = tk.StringVar(value="")
        _lbl(top, textvariable=self._count_var, foreground=_MUTED).pack(
            side=tk.RIGHT, padx=8,
        )

        pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        # ── call table ───────────────────────────────────────────────────────
        left = ttk.Frame(pane)
        cols = ("call_id", "provider", "method", "url", "status", "model")
        self._tree = ttk.Treeview(
            left, columns=cols, show="headings", selectmode="browse",
        )
        for col, width in zip(cols, (120, 88, 58, 260, 54, 120)):
            self._tree.heading(col, text=col.replace("_", " ").title())
            self._tree.column(col, width=width, minwidth=36)
        vsb = ttk.Scrollbar(left, orient=tk.VERTICAL,   command=self._tree.yview)
        hsb = ttk.Scrollbar(left, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        pane.add(left, weight=3)

        # ── detail pane ──────────────────────────────────────────────────────
        right = ttk.Frame(pane)
        _lbl(right, "Call detail:").pack(anchor=tk.W, pady=(0, 4))
        self._detail = _scrolled_text(right, wrap=tk.WORD)
        self._detail.pack(fill=tk.BOTH, expand=True)
        pane.add(right, weight=2)

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")],
        )
        if path:
            self._file_var.set(path)

    def _load(self) -> None:
        path = Path(self._file_var.get().strip())
        if not path.is_file():
            messagebox.showerror("Error", f"File not found:\n{path}")
            return
        self._calls = []
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._calls.append(json.loads(line))
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))
            return
        for row in self._tree.get_children():
            self._tree.delete(row)
        for c in self._calls:
            model = (c.get("request_body") or {}).get("model", "")
            self._tree.insert(
                "", tk.END, iid=c["call_id"],
                values=(
                    c["call_id"][:14], c.get("provider", "?"),
                    c.get("method", "?"), c.get("url", "")[:68],
                    c.get("response_status", "—"), model,
                ),
            )
        self._count_var.set(f"{len(self._calls)} call(s)")

    def _on_select(self, _event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        prefix = self._tree.item(sel[0], "values")[0]
        call = next(
            (c for c in self._calls if c.get("call_id", "").startswith(prefix)),
            None,
        )
        if call:
            _text_set(self._detail, json.dumps(call, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Statistics tab
# ---------------------------------------------------------------------------

class StatsTab(ttk.Frame):
    """Shows aggregate statistics for a JSONL captures file."""

    def __init__(self, parent) -> None:
        super().__init__(parent)
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=12, pady=8)
        _lbl(top, "Captures file (.jsonl):").pack(side=tk.LEFT)
        self._file_var = tk.StringVar()
        _entry(top, self._file_var, 38).pack(side=tk.LEFT, padx=4)
        _btn(top, "Browse…", self._browse).pack(side=tk.LEFT)
        _btn(top, "Load Stats", self._load).pack(side=tk.LEFT, padx=(8, 0))

        self._text = _scrolled_text(self, font=("Courier", 10))
        self._text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")],
        )
        if path:
            self._file_var.set(path)

    def _load(self) -> None:
        path = Path(self._file_var.get().strip())
        if not path.is_file():
            messagebox.showerror("Error", f"File not found:\n{path}")
            return
        calls = []
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        calls.append(json.loads(line))
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))
            return

        by_provider: dict = {}
        by_model:    dict = {}
        by_status:   dict = {}
        for c in calls:
            prov   = c.get("provider", "unknown")
            model  = (c.get("request_body") or {}).get("model", "unknown")
            status = str(c.get("response_status") or "N/A")
            by_provider[prov]   = by_provider.get(prov,   0) + 1
            by_model[model]     = by_model.get(model,     0) + 1
            by_status[status]   = by_status.get(status,   0) + 1

        BAR_MAX = 36
        total   = len(calls)

        lines = [
            f"  File : {path}",
            f"  {'─' * 54}",
            f"  Total calls : {total}",
            "",
            "  By provider:",
        ]
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            bar = "█" * int(BAR_MAX * v / max(total, 1))
            lines.append(f"    {k:<18} {v:>4}  {bar}")

        lines += ["", "  By model:"]
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            lines.append(f"    {k:<34} {v:>4}")

        lines += ["", "  By HTTP status:"]
        for k, v in sorted(by_status.items()):
            lines.append(f"    {k:<10} {v:>4}")

        _text_set(self._text, "\n".join(lines))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Launch the Android LLM Capture GUI."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
