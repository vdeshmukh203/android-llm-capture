#!/usr/bin/env python3
"""
android_llm_capture_gui.py — Tkinter GUI for Android LLM Network Traffic Capture

Provides a graphical front-end for the android_llm_capture library:
  - List connected ADB devices and start/stop live capture
  - Open and parse saved logcat or JSONL capture files
  - Inspect request bodies, response bodies, and call metadata
  - Export captured calls to JSONL
  - Display per-provider and per-model statistics

Stdlib-only (tkinter). No external dependencies beyond android_llm_capture.
"""

from __future__ import annotations

import datetime
import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from pathlib import Path
from typing import List, Optional

import android_llm_capture as alc


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Android LLM Capture")
        self.geometry("1100x700")
        self.minsize(800, 500)

        self._session: Optional[alc.CaptureSession] = None
        self._calls: List[alc.CapturedCall] = []
        self._capture_thread: Optional[threading.Thread] = None

        self._build_menu()
        self._build_toolbar()
        self._build_main()
        self._build_statusbar()

        self._refresh_devices()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open logcat / JSONL…", command=self._open_file,
                              accelerator="Ctrl+O")
        file_menu.add_command(label="Export JSONL…", command=self._export,
                              accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Clear all calls", command=self._clear)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.destroy, accelerator="Ctrl+Q")

        view_menu = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Statistics", command=self._show_stats)
        view_menu.add_command(label="Refresh devices", command=self._refresh_devices)

        self.bind_all("<Control-o>", lambda _e: self._open_file())
        self.bind_all("<Control-s>", lambda _e: self._export())
        self.bind_all("<Control-q>", lambda _e: self.destroy())

    def _build_toolbar(self) -> None:
        toolbar = ttk.Frame(self, relief=tk.GROOVE)
        toolbar.pack(fill=tk.X, padx=4, pady=(4, 0))

        # Device selector
        ttk.Label(toolbar, text="Device:").pack(side=tk.LEFT, padx=(4, 2))
        self._device_var = tk.StringVar()
        self._device_combo = ttk.Combobox(
            toolbar, textvariable=self._device_var, width=22, state="readonly"
        )
        self._device_combo.pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(toolbar, text="↺", width=3, command=self._refresh_devices).pack(
            side=tk.LEFT, padx=(0, 8)
        )

        # Tag filter
        ttk.Label(toolbar, text="Tag:").pack(side=tk.LEFT, padx=(0, 2))
        self._tag_var = tk.StringVar(value="OkHttp")
        ttk.Entry(toolbar, textvariable=self._tag_var, width=12).pack(
            side=tk.LEFT, padx=(0, 8)
        )

        # Capture controls
        self._start_btn = ttk.Button(
            toolbar, text="▶  Start Capture", command=self._start_capture
        )
        self._start_btn.pack(side=tk.LEFT, padx=2)
        self._stop_btn = ttk.Button(
            toolbar, text="■  Stop", command=self._stop_capture, state=tk.DISABLED
        )
        self._stop_btn.pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=8, pady=4
        )

        # File operations
        ttk.Button(toolbar, text="Open File…", command=self._open_file).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(toolbar, text="Export JSONL…", command=self._export).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(toolbar, text="Stats", command=self._show_stats).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(toolbar, text="Clear", command=self._clear).pack(
            side=tk.LEFT, padx=2
        )

    def _build_main(self) -> None:
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Left panel: calls table
        left = ttk.Frame(paned)
        paned.add(left, weight=2)

        cols = ("time", "provider", "method", "model", "status", "tokens")
        self._tree = ttk.Treeview(
            left, columns=cols, show="headings", selectmode="browse"
        )
        col_widths = {"time": 100, "provider": 90, "method": 55,
                      "model": 130, "status": 55, "tokens": 70}
        for col in cols:
            self._tree.heading(col, text=col.capitalize(),
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=col_widths[col], minwidth=40, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.pack(fill=tk.BOTH, expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Colour-code providers
        for provider, colour in {
            "openai": "#d4edda", "anthropic": "#cce5ff",
            "google": "#fff3cd", "cohere": "#f8d7da",
            "mistral": "#e2d9f3", "groq": "#d1ecf1",
        }.items():
            self._tree.tag_configure(provider, background=colour)

        # Right panel: detail notebook
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        nb = ttk.Notebook(right)
        nb.pack(fill=tk.BOTH, expand=True)

        self._req_text  = self._make_text(nb, "Request")
        self._resp_text = self._make_text(nb, "Response")
        self._meta_text = self._make_text(nb, "Metadata")

    def _make_text(self, parent: ttk.Notebook, label: str) -> scrolledtext.ScrolledText:
        st = scrolledtext.ScrolledText(parent, wrap=tk.WORD, state=tk.DISABLED,
                                       font=("Courier", 10))
        parent.add(st, text=label)
        return st

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, relief=tk.SUNKEN)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self._status_var, anchor=tk.W).pack(
            fill=tk.X, padx=6, pady=2
        )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _refresh_devices(self) -> None:
        devices = alc.list_devices()
        choices = devices or ["(no device)"]
        self._device_combo["values"] = choices
        self._device_combo.set(choices[0])
        if not devices:
            self._status("No ADB devices found — connect a device or start an emulator.")
        else:
            self._status(f"{len(devices)} device(s) found.")

    # ------------------------------------------------------------------
    # Capture controls
    # ------------------------------------------------------------------

    def _start_capture(self) -> None:
        raw_device = self._device_var.get()
        device: Optional[str] = None if (not raw_device or raw_device == "(no device)") else raw_device
        tag = self._tag_var.get().strip() or "OkHttp"

        self._session = alc.CaptureSession(device_serial=device, tag_filter=tag)
        try:
            self._session.start()
        except RuntimeError as exc:
            messagebox.showerror("Cannot start capture", str(exc))
            self._session = None
            return

        self._start_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)
        self._status(f"Capturing from {device or 'default device'} (tag={tag})…")

        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True
        )
        self._capture_thread.start()

    def _capture_loop(self) -> None:
        try:
            assert self._session is not None
            for call in self._session.stream():
                self._calls.append(call)
                self.after(0, self._append_row, call)
        except Exception as exc:
            self.after(0, self._status, f"Capture error: {exc}")

    def _stop_capture(self) -> None:
        if self._session:
            self._session.stop()
            self._session = None
        self._start_btn.config(state=tk.NORMAL)
        self._stop_btn.config(state=tk.DISABLED)
        self._status(f"Stopped. {len(self._calls)} call(s) captured.")

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def _open_file(self) -> None:
        path_str = filedialog.askopenfilename(
            title="Open logcat dump or JSONL captures file",
            filetypes=[
                ("Supported files", "*.log *.txt *.jsonl"),
                ("JSONL captures", "*.jsonl"),
                ("Logcat dumps", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() == ".jsonl":
            self._load_jsonl(path)
        else:
            self._load_logcat(path)

    def _load_logcat(self, path: Path) -> None:
        try:
            calls = alc.parse_logcat_file(path)
        except OSError as exc:
            messagebox.showerror("Cannot open file", str(exc))
            return
        self._calls.extend(calls)
        for call in calls:
            self._append_row(call)
        self._status(f"Loaded {len(calls)} call(s) from {path.name}.")

    def _load_jsonl(self, path: Path) -> None:
        loaded: List[alc.CapturedCall] = []
        try:
            with path.open(encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError as exc:
                        messagebox.showwarning(
                            "Parse warning",
                            f"Line {lineno} in {path.name} is not valid JSON: {exc}",
                        )
                        continue
                    loaded.append(
                        alc.CapturedCall(
                            call_id=obj["call_id"],
                            timestamp=obj["timestamp"],
                            provider=obj["provider"],
                            url=obj["url"],
                            method=obj["method"],
                            request_body=obj.get("request_body"),
                            response_status=obj.get("response_status"),
                            response_body=obj.get("response_body"),
                            source=obj.get("source", "file"),
                        )
                    )
        except OSError as exc:
            messagebox.showerror("Cannot open file", str(exc))
            return
        self._calls.extend(loaded)
        for call in loaded:
            self._append_row(call)
        self._status(f"Loaded {len(loaded)} call(s) from {path.name}.")

    def _export(self) -> None:
        if not self._calls:
            messagebox.showinfo("Nothing to export", "No calls have been captured yet.")
            return
        path_str = filedialog.asksaveasfilename(
            title="Export captures",
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*.*")],
        )
        if not path_str:
            return
        path = Path(path_str)
        try:
            with path.open("w", encoding="utf-8") as fh:
                for call in self._calls:
                    fh.write(call.to_jsonl() + "\n")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self._status(f"Exported {len(self._calls)} call(s) to {path.name}.")

    def _clear(self) -> None:
        self._calls.clear()
        self._tree.delete(*self._tree.get_children())
        self._set_text(self._req_text, "")
        self._set_text(self._resp_text, "")
        self._set_text(self._meta_text, "")
        self._status("Cleared.")

    # ------------------------------------------------------------------
    # Table management
    # ------------------------------------------------------------------

    def _append_row(self, call: alc.CapturedCall) -> None:
        ts = datetime.datetime.fromtimestamp(call.timestamp).strftime("%H:%M:%S.%f")[:12]
        self._tree.insert(
            "", tk.END,
            iid=call.call_id,
            values=(
                ts,
                call.provider,
                call.method,
                call.model or "—",
                call.response_status if call.response_status is not None else "—",
                call.prompt_tokens_estimate,
            ),
            tags=(call.provider,),
        )
        self._tree.see(call.call_id)

    def _sort_by(self, col: str) -> None:
        rows = [(self._tree.set(iid, col), iid) for iid in self._tree.get_children("")]
        rows.sort(key=lambda x: x[0])
        for index, (_, iid) in enumerate(rows):
            self._tree.move(iid, "", index)

    # ------------------------------------------------------------------
    # Detail panel
    # ------------------------------------------------------------------

    def _on_select(self, _event=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        call_id = sel[0]
        call = next((c for c in self._calls if c.call_id == call_id), None)
        if not call:
            return

        req_str = (
            json.dumps(call.request_body, indent=2, ensure_ascii=False)
            if call.request_body
            else "(none)"
        )
        self._set_text(self._req_text, req_str)

        resp = call.response_body or "(none)"
        # Pretty-print JSON responses when possible
        try:
            resp = json.dumps(json.loads(resp), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass
        self._set_text(self._resp_text, resp)

        meta = {
            "call_id":        call.call_id,
            "timestamp":      call.timestamp,
            "timestamp_iso":  datetime.datetime.fromtimestamp(call.timestamp).isoformat(),
            "provider":       call.provider,
            "url":            call.url,
            "method":         call.method,
            "response_status": call.response_status,
            "source":         call.source,
            "model":          call.model,
            "prompt_tokens_estimate": call.prompt_tokens_estimate,
            "request_hash":   call.request_hash,
            "response_hash":  call.response_hash,
        }
        self._set_text(self._meta_text, json.dumps(meta, indent=2))

    # ------------------------------------------------------------------
    # Statistics window
    # ------------------------------------------------------------------

    def _show_stats(self) -> None:
        if not self._calls:
            messagebox.showinfo("Statistics", "No calls captured yet.")
            return

        win = tk.Toplevel(self)
        win.title("Capture Statistics")
        win.geometry("400x350")
        win.resizable(True, True)

        by_provider: dict = {}
        by_model: dict = {}
        total_tokens = 0
        for call in self._calls:
            by_provider[call.provider] = by_provider.get(call.provider, 0) + 1
            model = call.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1
            total_tokens += call.prompt_tokens_estimate

        lines = [
            f"Total calls:          {len(self._calls)}",
            f"Est. prompt tokens:   {total_tokens:,}",
            "",
            "By provider:",
        ]
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<20} {v}")
        lines += ["", "By model:"]
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<30} {v}")

        st = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Courier", 10))
        st.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        st.insert("1.0", "\n".join(lines))
        st.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _set_text(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        widget.config(state=tk.DISABLED)

    def _status(self, msg: str) -> None:
        self._status_var.set(msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
