#!/usr/bin/env python3
"""
android_llm_capture_gui — Desktop GUI for android-llm-capture.

Provides four tabs:
  Live Capture  — stream adb logcat and display calls in real-time
  File Parser   — parse a saved logcat dump file
  Replay        — replay a captured call against the live API
  Statistics    — summarise a JSONL captures file

Launch via the CLI entry point:
    android-llm-capture-gui

Or directly:
    python android_llm_capture_gui.py
"""

from __future__ import annotations

import datetime
import json
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import List, Optional

import android_llm_capture as alc


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _fmt_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _truncate(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Call detail popup
# ---------------------------------------------------------------------------


class _CallDetailWindow(tk.Toplevel):
    """Non-modal window showing the full details of a single CapturedCall."""

    def __init__(self, parent: tk.Widget, call: alc.CapturedCall) -> None:
        super().__init__(parent)
        self.title(f"Call {call.call_id}  —  {call.provider}")
        self.geometry("720x520")
        self.resizable(True, True)

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        metadata = {
            "call_id":               call.call_id,
            "timestamp":             _fmt_ts(call.timestamp),
            "provider":              call.provider,
            "url":                   call.url,
            "method":                call.method,
            "response_status":       call.response_status,
            "source":                call.source,
            "model":                 call.model,
            "prompt_tokens_est":     call.prompt_tokens_estimate,
            "request_hash":          call.request_hash,
            "response_hash":         call.response_hash,
        }

        for label, content in (
            ("Request",  json.dumps(call.request_body, indent=2, ensure_ascii=False)
                         if call.request_body else "(none)"),
            ("Response", call.response_body or "(none)"),
            ("Metadata", json.dumps(metadata, indent=2)),
        ):
            tab = ttk.Frame(nb)
            nb.add(tab, text=label)
            st = scrolledtext.ScrolledText(tab, wrap=tk.NONE, font=("Courier", 10))
            st.pack(fill=tk.BOTH, expand=True)
            st.insert(tk.END, content)
            st.config(state=tk.DISABLED)

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 6))


# ---------------------------------------------------------------------------
# Shared call-list widget builder
# ---------------------------------------------------------------------------

_CALL_COLS = ("time", "provider", "method", "url", "status", "model")
_CALL_COL_SPEC = [
    # (column, width, anchor)
    ("time",     72,  tk.CENTER),
    ("provider", 88,  tk.CENTER),
    ("method",   58,  tk.CENTER),
    ("url",      300, tk.W),
    ("status",   52,  tk.CENTER),
    ("model",    120, tk.W),
]


def _build_call_tree(parent: tk.Widget) -> ttk.Treeview:
    tree = ttk.Treeview(parent, columns=_CALL_COLS, show="headings", selectmode="browse")
    for col, width, anchor in _CALL_COL_SPEC:
        tree.heading(col, text=col.capitalize())
        tree.column(col, width=width, anchor=anchor, stretch=(col == "url"))
    vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.RIGHT, fill=tk.Y)
    return tree


def _tree_values(call: alc.CapturedCall):
    return (
        _fmt_ts(call.timestamp),
        call.provider,
        call.method,
        _truncate(call.url),
        call.response_status if call.response_status is not None else "—",
        call.model or "—",
    )


# ---------------------------------------------------------------------------
# Live Capture tab
# ---------------------------------------------------------------------------


class _LiveTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, status_cb) -> None:
        super().__init__(parent)
        self._status = status_cb
        self._session: Optional[alc.CaptureSession] = None
        self._calls: List[alc.CapturedCall] = []
        self._queue: queue.Queue = queue.Queue()

        self._build()
        self._poll()

    def _build(self) -> None:
        # Settings row
        ctrl = ttk.LabelFrame(self, text="Capture settings", padding=6)
        ctrl.pack(fill=tk.X, padx=6, pady=(6, 0))

        ttk.Label(ctrl, text="Tag filter:").grid(row=0, column=0, sticky=tk.W)
        self._tag = tk.StringVar(value="OkHttp")
        ttk.Entry(ctrl, textvariable=self._tag, width=16).grid(
            row=0, column=1, padx=(4, 12), sticky=tk.W
        )

        ttk.Label(ctrl, text="Timeout (s, 0=∞):").grid(row=0, column=2, sticky=tk.W)
        self._timeout = tk.StringVar(value="0")
        ttk.Entry(ctrl, textvariable=self._timeout, width=6).grid(
            row=0, column=3, padx=(4, 12)
        )

        ttk.Label(ctrl, text="Output file:").grid(row=0, column=4, sticky=tk.W)
        self._output = tk.StringVar(value="captures.jsonl")
        ttk.Entry(ctrl, textvariable=self._output, width=24).grid(
            row=0, column=5, padx=(4, 2)
        )
        ttk.Button(ctrl, text="…", width=3, command=self._pick_output).grid(row=0, column=6)

        # Button row
        btn = ttk.Frame(self)
        btn.pack(fill=tk.X, padx=6, pady=4)
        self._start_btn = ttk.Button(btn, text="▶  Start", command=self._start)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._stop_btn = ttk.Button(btn, text="■  Stop", command=self._stop, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn, text="Export JSONL…", command=self._export).pack(side=tk.LEFT)

        # Call list
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self._tree = _build_call_tree(tree_frame)
        self._tree.bind("<Double-1>", self._on_double_click)

    # ------------------------------------------------------------------

    def _start(self) -> None:
        device = self.master.master._selected_device()  # App toolbar
        tag     = self._tag.get().strip() or "OkHttp"
        try:
            timeout = max(0, int(self._timeout.get() or "0"))
        except ValueError:
            timeout = 0

        self._calls.clear()
        self._session = alc.CaptureSession(device_serial=device, tag_filter=tag)
        try:
            self._session.start()
        except RuntimeError as exc:
            messagebox.showerror("ADB error", str(exc), parent=self)
            return

        self._start_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)
        self._status("Capture running…")
        threading.Thread(
            target=self._worker, args=(self._session, timeout), daemon=True
        ).start()

    def _worker(self, session: alc.CaptureSession, timeout: int) -> None:
        start = time.time()
        try:
            for call in session.stream():
                self._queue.put(call)
                if timeout and (time.time() - start) > timeout:
                    break
        except Exception as exc:  # noqa: BLE001
            self._queue.put(exc)
        finally:
            self._queue.put(None)

    def _stop(self) -> None:
        if self._session:
            self._session.stop()

    def _clear(self) -> None:
        self._tree.delete(*self._tree.get_children())
        self._calls.clear()

    def _poll(self) -> None:
        try:
            while True:
                item = self._queue.get_nowait()
                if item is None:
                    self._start_btn.config(state=tk.NORMAL)
                    self._stop_btn.config(state=tk.DISABLED)
                    self._status(f"Capture stopped — {len(self._calls)} call(s).")
                elif isinstance(item, Exception):
                    self._status(f"Error: {item}")
                    self._start_btn.config(state=tk.NORMAL)
                    self._stop_btn.config(state=tk.DISABLED)
                else:
                    call: alc.CapturedCall = item
                    self._calls.append(call)
                    self._tree.insert("", tk.END, iid=call.call_id, values=_tree_values(call))
                    self._tree.see(call.call_id)
                    self._status(f"Capturing… {len(self._calls)} call(s).")
        except queue.Empty:
            pass
        self.after(150, self._poll)

    def _on_double_click(self, _event) -> None:
        sel = self._tree.selection()
        if sel:
            call = next((c for c in self._calls if c.call_id == sel[0]), None)
            if call:
                _CallDetailWindow(self, call)

    def _export(self) -> None:
        if not self._calls:
            messagebox.showinfo("Nothing to export", "No captured calls yet.", parent=self)
            return
        path_str = self._output.get().strip() or "captures.jsonl"
        path = Path(path_str)
        try:
            with path.open("w", encoding="utf-8") as fh:
                for call in self._calls:
                    fh.write(call.to_jsonl() + "\n")
            self._status(f"Exported {len(self._calls)} call(s) to {path}")
        except OSError as exc:
            messagebox.showerror("Export error", str(exc), parent=self)

    def _pick_output(self) -> None:
        p = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".jsonl",
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
        )
        if p:
            self._output.set(p)

    def export_calls(self) -> None:
        """Called by menu File → Export."""
        self._export()


# ---------------------------------------------------------------------------
# File Parser tab
# ---------------------------------------------------------------------------


class _FileTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, status_cb) -> None:
        super().__init__(parent)
        self._status = status_cb
        self._calls: List[alc.CapturedCall] = []
        self._build()

    def _build(self) -> None:
        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, padx=6, pady=6)
        ttk.Label(ctrl, text="Logcat file:").pack(side=tk.LEFT)
        self._path = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._path, width=44).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="Browse…", command=self._browse).pack(side=tk.LEFT)
        ttk.Button(ctrl, text="Parse", command=self._parse).pack(side=tk.LEFT, padx=8)
        ttk.Button(ctrl, text="Export JSONL…", command=self._export).pack(side=tk.LEFT)

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self._tree = _build_call_tree(tree_frame)
        self._tree.bind("<Double-1>", self._on_double_click)

    def _browse(self) -> None:
        p = filedialog.askopenfilename(
            parent=self,
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")],
        )
        if p:
            self._path.set(p)

    def _parse(self) -> None:
        path_str = self._path.get().strip()
        if not path_str:
            messagebox.showwarning("No file", "Select a logcat file first.", parent=self)
            return
        path = Path(path_str)
        if not path.is_file():
            messagebox.showerror("File not found", str(path), parent=self)
            return
        self._calls = alc.parse_logcat_file(path)
        self._tree.delete(*self._tree.get_children())
        for call in self._calls:
            self._tree.insert("", tk.END, iid=call.call_id, values=_tree_values(call))
        self._status(f"Parsed {len(self._calls)} LLM call(s) from {path.name}")

    def _on_double_click(self, _event) -> None:
        sel = self._tree.selection()
        if sel:
            call = next((c for c in self._calls if c.call_id == sel[0]), None)
            if call:
                _CallDetailWindow(self, call)

    def _export(self) -> None:
        if not self._calls:
            messagebox.showinfo("Nothing to export", "Parse a logcat file first.", parent=self)
            return
        p = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".jsonl",
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
        )
        if not p:
            return
        with Path(p).open("w", encoding="utf-8") as fh:
            for call in self._calls:
                fh.write(call.to_jsonl() + "\n")
        self._status(f"Exported {len(self._calls)} call(s) to {Path(p).name}")


# ---------------------------------------------------------------------------
# Replay tab
# ---------------------------------------------------------------------------


class _ReplayTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, status_cb) -> None:
        super().__init__(parent)
        self._status = status_cb
        self._calls: List[alc.CapturedCall] = []
        self._build()

    def _build(self) -> None:
        # File picker row
        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, padx=6, pady=6)
        ttk.Label(ctrl, text="Captures file:").pack(side=tk.LEFT)
        self._path = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._path, width=40).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="Browse…", command=self._browse).pack(side=tk.LEFT)
        ttk.Button(ctrl, text="Load", command=self._load).pack(side=tk.LEFT, padx=8)

        # API key row
        key_row = ttk.Frame(self)
        key_row.pack(fill=tk.X, padx=6)
        ttk.Label(key_row, text="API key:").pack(side=tk.LEFT)
        self._api_key = tk.StringVar()
        ttk.Entry(key_row, textvariable=self._api_key, width=52, show="•").pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(key_row, text="▶  Replay selected", command=self._replay).pack(
            side=tk.LEFT, padx=8
        )

        # Vertical split: call list (top) + response (bottom)
        pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        top = ttk.Frame(pane)
        pane.add(top, weight=2)
        cols = ("time", "provider", "method", "url", "status")
        self._tree = ttk.Treeview(top, columns=cols, show="headings", selectmode="browse")
        for col, width, anchor in [
            ("time", 78, tk.CENTER), ("provider", 88, tk.CENTER),
            ("method", 58, tk.CENTER), ("url", 300, tk.W), ("status", 52, tk.CENTER),
        ]:
            self._tree.heading(col, text=col.capitalize())
            self._tree.column(col, width=width, anchor=anchor, stretch=(col == "url"))
        vsb = ttk.Scrollbar(top, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        bot = ttk.LabelFrame(pane, text="Replay response")
        pane.add(bot, weight=1)
        self._response = scrolledtext.ScrolledText(
            bot, wrap=tk.WORD, font=("Courier", 10)
        )
        self._response.pack(fill=tk.BOTH, expand=True)

    def _browse(self) -> None:
        p = filedialog.askopenfilename(
            parent=self,
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
        )
        if p:
            self._path.set(p)

    def _load(self) -> None:
        path_str = self._path.get().strip()
        if not path_str:
            messagebox.showwarning("No file", "Select a captures file first.", parent=self)
            return
        try:
            self._calls = alc.load_jsonl(Path(path_str))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Load error", str(exc), parent=self)
            return
        self._tree.delete(*self._tree.get_children())
        for call in self._calls:
            self._tree.insert(
                "", tk.END, iid=call.call_id,
                values=(
                    _fmt_ts(call.timestamp), call.provider, call.method,
                    _truncate(call.url), call.response_status if call.response_status else "—",
                ),
            )
        self._status(f"Loaded {len(self._calls)} call(s) from {Path(path_str).name}")

    def _replay(self) -> None:
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select a call from the list.", parent=self)
            return
        api_key = self._api_key.get().strip()
        if not api_key:
            messagebox.showwarning("No API key", "Enter your API key.", parent=self)
            return
        call = next((c for c in self._calls if c.call_id == sel[0]), None)
        if not call:
            return

        self._response.delete("1.0", tk.END)
        self._response.insert(tk.END, "Sending request…")
        self._status("Replaying call…")

        def worker():
            try:
                result = alc.CaptureSession().replay(call, api_key=api_key)
                text = json.dumps(result, indent=2, ensure_ascii=False)
            except Exception as exc:  # noqa: BLE001
                text = f"Error: {exc}"
            self.after(0, self._show_result, text)

        threading.Thread(target=worker, daemon=True).start()

    def _show_result(self, text: str) -> None:
        self._response.delete("1.0", tk.END)
        self._response.insert(tk.END, text)
        self._status("Replay complete.")


# ---------------------------------------------------------------------------
# Statistics tab
# ---------------------------------------------------------------------------


class _StatsTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, status_cb) -> None:
        super().__init__(parent)
        self._status = status_cb
        self._build()

    def _build(self) -> None:
        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, padx=6, pady=6)
        ttk.Label(ctrl, text="Captures file:").pack(side=tk.LEFT)
        self._path = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._path, width=44).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="Browse…", command=self._browse).pack(side=tk.LEFT)
        ttk.Button(ctrl, text="Load stats", command=self._load).pack(side=tk.LEFT, padx=8)

        self._text = scrolledtext.ScrolledText(
            self, wrap=tk.WORD, font=("Courier", 11), state=tk.DISABLED
        )
        self._text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _browse(self) -> None:
        p = filedialog.askopenfilename(
            parent=self,
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
        )
        if p:
            self._path.set(p)

    def _load(self) -> None:
        path_str = self._path.get().strip()
        if not path_str:
            messagebox.showwarning("No file", "Select a captures file first.", parent=self)
            return
        try:
            calls = alc.load_jsonl(Path(path_str))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Load error", str(exc), parent=self)
            return

        by_provider: dict = {}
        by_model:    dict = {}
        by_status:   dict = {}
        total_tokens = 0

        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model  = c.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1
            status = str(c.response_status or "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            total_tokens += c.prompt_tokens_estimate

        lines = [
            f"File           : {path_str}",
            f"Total calls    : {len(calls)}",
            f"Est. tokens    : {total_tokens:,}",
            "",
            "By provider:",
        ]
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<20s}  {v:>5}")
        lines += ["", "By model:"]
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<32s}  {v:>5}")
        lines += ["", "By HTTP status:"]
        for k, v in sorted(by_status.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<10s}  {v:>5}")

        self._text.config(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.insert(tk.END, "\n".join(lines))
        self._text.config(state=tk.DISABLED)
        self._status(f"Statistics loaded for {len(calls)} call(s).")


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------


class App(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("android-llm-capture")
        self.geometry("960x680")
        self.minsize(720, 520)

        self._build_menu()
        self._build_toolbar()
        self._build_notebook()
        self._build_statusbar()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_m = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file_m)
        file_m.add_command(
            label="Export live captures…",
            command=lambda: self._live_tab.export_calls(),
        )
        file_m.add_separator()
        file_m.add_command(label="Quit", command=self.destroy)

        help_m = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="Help", menu=help_m)
        help_m.add_command(label="About", command=self._about)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, relief=tk.FLAT)
        bar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(6, 0))

        ttk.Label(bar, text="ADB device:").pack(side=tk.LEFT)
        self._device_var = tk.StringVar(value="(auto)")
        self._device_combo = ttk.Combobox(
            bar, textvariable=self._device_var, width=26, state="readonly"
        )
        self._device_combo.pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(bar, text="↻ Refresh", command=self._refresh_devices).pack(
            side=tk.LEFT, padx=4
        )
        self._device_lbl = ttk.Label(bar, text="", foreground="grey")
        self._device_lbl.pack(side=tk.LEFT, padx=6)

        self._refresh_devices()

    def _build_notebook(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self._live_tab   = _LiveTab(nb,   self._set_status)
        self._file_tab   = _FileTab(nb,   self._set_status)
        self._replay_tab = _ReplayTab(nb, self._set_status)
        self._stats_tab  = _StatsTab(nb,  self._set_status)

        nb.add(self._live_tab,   text="Live Capture")
        nb.add(self._file_tab,   text="File Parser")
        nb.add(self._replay_tab, text="Replay")
        nb.add(self._stats_tab,  text="Statistics")

    def _build_statusbar(self) -> None:
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(
            self,
            textvariable=self._status_var,
            anchor=tk.W,
            relief=tk.SUNKEN,
            padding=(6, 2),
        ).pack(side=tk.BOTTOM, fill=tk.X)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _refresh_devices(self) -> None:
        devices = alc.list_devices()
        values = ["(auto)"] + devices
        self._device_combo["values"] = values
        self._device_combo.set(values[0])
        if devices:
            self._device_lbl.config(
                text=f"{len(devices)} device(s) found", foreground="green"
            )
        else:
            self._device_lbl.config(text="No devices detected", foreground="orange")

    def _selected_device(self) -> Optional[str]:
        val = self._device_var.get()
        return None if val == "(auto)" else val

    def _set_status(self, msg: str) -> None:
        self._status_var.set(msg)

    def _about(self) -> None:
        messagebox.showinfo(
            "About android-llm-capture",
            "android-llm-capture  v0.1.0\n\n"
            "ADB-based tool for capturing and replaying\n"
            "LLM API interactions from Android devices.\n\n"
            "https://github.com/vdeshmukh203/android-llm-capture",
            parent=self,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Launch the GUI application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
