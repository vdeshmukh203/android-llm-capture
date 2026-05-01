#!/usr/bin/env python3
"""
android_llm_capture_gui — Tkinter GUI for Android LLM Capture

Launch via:
    android-llm-capture gui
    python android_llm_capture_gui.py

Three-tab interface: Capture (live ADB streaming), Replay (re-execute saved
calls), and Stats (summary of any JSONL captures file).

Stdlib-only — tkinter is part of the Python standard library.
"""

from __future__ import annotations

import json
import queue
import sys
import textwrap
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
import tkinter as tk

# Support running the file directly from the project root before installation
try:
    from android_llm_capture import (
        CaptureSession,
        CapturedCall,
        load_jsonl,
        list_devices,
        parse_logcat_file,
        __version__,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from android_llm_capture import (
        CaptureSession,
        CapturedCall,
        load_jsonl,
        list_devices,
        parse_logcat_file,
        __version__,
    )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _truncate(s: str, n: int = 65) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    """Root window for android-llm-capture GUI."""

    def __init__(self) -> None:
        super().__init__()
        self.title(f"Android LLM Capture  v{__version__}")
        self.geometry("1140x760")
        self.minsize(920, 620)

        self._session: CaptureSession | None = None
        self._capture_thread: threading.Thread | None = None
        self._event_queue: queue.Queue = queue.Queue()
        self._calls: list[CapturedCall] = []
        self._replay_calls: list[CapturedCall] = []

        self._build_menu()
        self._build_ui()
        self._poll_queue()  # start the main-thread event-loop polling

    # ------------------------------------------------------------------
    # Menu bar
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        self.configure(menu=menubar)

        file_m = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file_m)
        file_m.add_command(label="Open JSONL…", command=self._open_jsonl)
        file_m.add_command(label="Export JSONL…", command=self._export_jsonl)
        file_m.add_separator()
        file_m.add_command(label="Quit", command=self.quit)

        help_m = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="Help", menu=help_m)
        help_m.add_command(label="About", command=self._show_about)

    # ------------------------------------------------------------------
    # Notebook layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        capture_tab = ttk.Frame(nb)
        replay_tab  = ttk.Frame(nb)
        stats_tab   = ttk.Frame(nb)

        nb.add(capture_tab, text="  Capture  ")
        nb.add(replay_tab,  text="  Replay   ")
        nb.add(stats_tab,   text="  Stats    ")

        self._build_capture_tab(capture_tab)
        self._build_replay_tab(replay_tab)
        self._build_stats_tab(stats_tab)

        # Status bar at bottom
        self._status_var = tk.StringVar(value="  Ready")
        ttk.Label(self, textvariable=self._status_var, anchor="w",
                  relief="sunken").pack(fill="x", side="bottom")

    # ------------------------------------------------------------------
    # Capture tab
    # ------------------------------------------------------------------

    def _build_capture_tab(self, parent: ttk.Frame) -> None:
        ctrl = ttk.LabelFrame(parent, text="Capture Controls")
        ctrl.pack(fill="x", padx=6, pady=4)
        ctrl.columnconfigure(1, weight=1)

        # Row 0: device selector
        ttk.Label(ctrl, text="Device serial:").grid(row=0, column=0, sticky="w", padx=6, pady=3)
        self._device_var = tk.StringVar()
        self._device_combo = ttk.Combobox(ctrl, textvariable=self._device_var, width=38)
        self._device_combo.grid(row=0, column=1, sticky="ew", padx=4, pady=3)
        ttk.Button(ctrl, text="Refresh", command=self._refresh_devices,
                   width=10).grid(row=0, column=2, padx=6, pady=3)

        # Row 1: logcat tag
        ttk.Label(ctrl, text="Logcat tag:").grid(row=1, column=0, sticky="w", padx=6, pady=3)
        self._tag_var = tk.StringVar(value="OkHttp")
        ttk.Entry(ctrl, textvariable=self._tag_var, width=22).grid(
            row=1, column=1, sticky="w", padx=4, pady=3)

        # Row 2: timeout
        ttk.Label(ctrl, text="Timeout (s, 0=∞):").grid(row=2, column=0, sticky="w", padx=6, pady=3)
        self._timeout_var = tk.StringVar(value="0")
        ttk.Entry(ctrl, textvariable=self._timeout_var, width=8).grid(
            row=2, column=1, sticky="w", padx=4, pady=3)

        # Row 3: action buttons
        btn_row = ttk.Frame(ctrl)
        btn_row.grid(row=3, column=0, columnspan=3, sticky="w", padx=4, pady=6)
        self._start_btn = ttk.Button(btn_row, text="▶ Start Capture",
                                     command=self._start_capture)
        self._start_btn.pack(side="left", padx=4)
        self._stop_btn = ttk.Button(btn_row, text="■ Stop",
                                    command=self._stop_capture, state="disabled")
        self._stop_btn.pack(side="left", padx=4)
        ttk.Button(btn_row, text="Open JSONL…",
                   command=self._open_jsonl).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Export JSONL…",
                   command=self._export_jsonl).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Clear",
                   command=self._clear_calls).pack(side="left", padx=4)

        # Paned window: call list on top, detail viewer below
        pane = ttk.PanedWindow(parent, orient="vertical")
        pane.pack(fill="both", expand=True, padx=6, pady=4)

        tree_frame = ttk.LabelFrame(pane, text="Captured Calls (click a row to inspect)")
        pane.add(tree_frame, weight=3)

        cols = ("time", "provider", "method", "url", "status", "model")
        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  selectmode="browse")
        widths = {"time": 76, "provider": 96, "method": 66, "url": 330,
                  "status": 66, "model": 160}
        for col in cols:
            self._tree.heading(col, text=col.title())
            self._tree.column(col, width=widths.get(col, 120), anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_capture_select)

        detail_frame = ttk.LabelFrame(pane, text="Call Detail (JSON)")
        pane.add(detail_frame, weight=2)
        self._detail_text = scrolledtext.ScrolledText(
            detail_frame, font=("Courier", 10), wrap="none",
            state="disabled", height=12,
        )
        self._detail_text.pack(fill="both", expand=True, padx=4, pady=4)

        self._refresh_devices()

    # ------------------------------------------------------------------
    # Replay tab
    # ------------------------------------------------------------------

    def _build_replay_tab(self, parent: ttk.Frame) -> None:
        ctrl = ttk.LabelFrame(parent, text="Replay Controls")
        ctrl.pack(fill="x", padx=6, pady=4)
        ctrl.columnconfigure(1, weight=1)

        ttk.Button(ctrl, text="Load JSONL…",
                   command=self._load_for_replay).grid(row=0, column=0, padx=6, pady=4)
        self._replay_file_var = tk.StringVar(value="(no file loaded)")
        ttk.Label(ctrl, textvariable=self._replay_file_var, anchor="w").grid(
            row=0, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(ctrl, text="API Key:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self._apikey_var = tk.StringVar()
        self._apikey_entry = ttk.Entry(ctrl, textvariable=self._apikey_var,
                                       show="•", width=52)
        self._apikey_entry.grid(row=1, column=1, sticky="ew", padx=4, pady=4)
        self._show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Show", variable=self._show_key_var,
                        command=self._toggle_key_visibility).grid(
            row=1, column=2, padx=6)

        btn_row = ttk.Frame(ctrl)
        btn_row.grid(row=2, column=0, columnspan=3, sticky="w", padx=4, pady=6)
        ttk.Button(btn_row, text="▶ Replay selected",
                   command=self._replay_selected).pack(side="left", padx=4)
        ttk.Button(btn_row, text="▶ Replay last",
                   command=self._replay_last).pack(side="left", padx=4)

        pane = ttk.PanedWindow(parent, orient="vertical")
        pane.pack(fill="both", expand=True, padx=6, pady=4)

        list_frame = ttk.LabelFrame(pane, text="Loaded Calls")
        pane.add(list_frame, weight=1)
        cols = ("call_id", "provider", "model", "status")
        self._replay_tree = ttk.Treeview(list_frame, columns=cols, show="headings",
                                         selectmode="browse")
        for col in cols:
            self._replay_tree.heading(col, text=col.replace("_", " ").title())
            self._replay_tree.column(col, width=160)
        vsb2 = ttk.Scrollbar(list_frame, orient="vertical",
                              command=self._replay_tree.yview)
        self._replay_tree.configure(yscrollcommand=vsb2.set)
        self._replay_tree.pack(side="left", fill="both", expand=True)
        vsb2.pack(side="right", fill="y")

        resp_frame = ttk.LabelFrame(pane, text="Replay Response")
        pane.add(resp_frame, weight=2)
        self._replay_resp_text = scrolledtext.ScrolledText(
            resp_frame, font=("Courier", 10), wrap="none", state="disabled")
        self._replay_resp_text.pack(fill="both", expand=True, padx=4, pady=4)

    def _toggle_key_visibility(self) -> None:
        self._apikey_entry.configure(show="" if self._show_key_var.get() else "•")

    # ------------------------------------------------------------------
    # Stats tab
    # ------------------------------------------------------------------

    def _build_stats_tab(self, parent: ttk.Frame) -> None:
        ctrl = ttk.Frame(parent)
        ctrl.pack(fill="x", padx=6, pady=6)
        ttk.Button(ctrl, text="Load JSONL…",
                   command=self._load_for_stats).pack(side="left", padx=4)
        ttk.Button(ctrl, text="Analyse current captures",
                   command=self._refresh_stats).pack(side="left", padx=4)

        self._stats_text = scrolledtext.ScrolledText(
            parent, font=("Courier", 11), wrap="none", state="disabled")
        self._stats_text.pack(fill="both", expand=True, padx=6, pady=4)

    # ------------------------------------------------------------------
    # Capture controls
    # ------------------------------------------------------------------

    def _refresh_devices(self) -> None:
        devices = list_devices()
        self._device_combo["values"] = devices
        if devices and not self._device_var.get():
            self._device_var.set(devices[0])
        n = len(devices)
        self._set_status(f"{n} device{'s' if n != 1 else ''} detected")

    def _start_capture(self) -> None:
        if self._capture_thread and self._capture_thread.is_alive():
            return
        serial  = self._device_var.get().strip() or None
        tag     = self._tag_var.get().strip() or "OkHttp"
        try:
            timeout = int(self._timeout_var.get())
        except ValueError:
            timeout = 0

        self._session = CaptureSession(device_serial=serial, tag_filter=tag)
        try:
            self._session.start()
        except RuntimeError as exc:
            messagebox.showerror("ADB Error", str(exc))
            return

        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._set_status("Capture running…")

        self._capture_thread = threading.Thread(
            target=self._capture_worker, args=(timeout,), daemon=True
        )
        self._capture_thread.start()

    def _capture_worker(self, timeout: int) -> None:
        start = time.time()
        try:
            for call in self._session.stream():  # type: ignore[union-attr]
                self._event_queue.put(("call", call))
                if timeout and (time.time() - start) > timeout:
                    break
        except Exception as exc:
            self._event_queue.put(("error", str(exc)))
        finally:
            self._event_queue.put(("capture_stopped", None))

    def _stop_capture(self) -> None:
        if self._session:
            self._session.stop()

    # ------------------------------------------------------------------
    # Queue polling (runs on the main/GUI thread)
    # ------------------------------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._event_queue.get_nowait()
                if kind == "call":
                    self._add_call_to_tree(payload)
                elif kind == "capture_stopped":
                    self._start_btn.configure(state="normal")
                    self._stop_btn.configure(state="disabled")
                    self._set_status(
                        f"Capture ended — {len(self._calls)} call(s) captured"
                    )
                elif kind == "error":
                    messagebox.showerror("Capture Error", payload)
                elif kind == "replay_result":
                    self._set_replay_response(payload)
                    self._set_status("Replay complete")
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    # ------------------------------------------------------------------
    # Call list management
    # ------------------------------------------------------------------

    def _add_call_to_tree(self, call: CapturedCall) -> None:
        self._calls.append(call)
        iid = str(len(self._calls) - 1)
        self._tree.insert(
            "", "end", iid=iid,
            values=(
                _fmt_ts(call.timestamp),
                call.provider,
                call.method,
                _truncate(call.url),
                call.response_status or "—",
                call.model or "—",
            ),
        )
        self._tree.see(iid)
        self._set_status(f"Captured {len(self._calls)} call(s)")

    def _on_capture_select(self, _event=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx >= len(self._calls):
            return
        detail = json.dumps(self._calls[idx].to_dict(), indent=2, ensure_ascii=False)
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("end", detail)
        self._detail_text.configure(state="disabled")

    def _clear_calls(self) -> None:
        self._calls.clear()
        if self._session:
            self._session.calls.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.configure(state="disabled")
        self._set_status("Cleared")

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def _open_jsonl(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
            title="Open JSONL captures",
        )
        if not path:
            return
        try:
            calls = load_jsonl(Path(path))
        except Exception as exc:
            messagebox.showerror("Load Error", str(exc))
            return
        self._clear_calls()
        for call in calls:
            self._add_call_to_tree(call)
        self._set_status(f"Loaded {len(calls)} call(s) from {path}")

    def _export_jsonl(self) -> None:
        if not self._calls:
            messagebox.showinfo("Export", "No calls to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
            title="Export captures as JSONL",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            for call in self._calls:
                fh.write(call.to_jsonl() + "\n")
        self._set_status(f"Exported {len(self._calls)} call(s) → {path}")

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def _load_for_replay(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
            title="Load JSONL for replay",
        )
        if not path:
            return
        try:
            self._replay_calls = load_jsonl(Path(path))
        except Exception as exc:
            messagebox.showerror("Load Error", str(exc))
            return
        self._replay_file_var.set(path)
        for iid in self._replay_tree.get_children():
            self._replay_tree.delete(iid)
        for i, call in enumerate(self._replay_calls):
            self._replay_tree.insert(
                "", "end", iid=str(i),
                values=(call.call_id, call.provider, call.model or "—",
                        call.response_status or "—"),
            )
        self._set_status(f"Loaded {len(self._replay_calls)} call(s) for replay")

    def _replay_selected(self) -> None:
        sel = self._replay_tree.selection()
        if not sel:
            messagebox.showinfo("Replay", "Select a call to replay.")
            return
        self._do_replay(self._replay_calls[int(sel[0])])

    def _replay_last(self) -> None:
        if not self._replay_calls:
            messagebox.showinfo("Replay", "No calls loaded. Use 'Load JSONL…' first.")
            return
        self._do_replay(self._replay_calls[-1])

    def _do_replay(self, call: CapturedCall) -> None:
        api_key = self._apikey_var.get().strip()
        if not api_key:
            messagebox.showwarning("Replay", "Enter an API key first.")
            return
        if not call.request_body:
            messagebox.showwarning("Replay", "Selected call has no request body to replay.")
            return
        self._set_status(f"Replaying {call.call_id}…")

        def worker() -> None:
            try:
                result = CaptureSession().replay(call, api_key=api_key)
                text = json.dumps(result, indent=2, ensure_ascii=False)
            except Exception as exc:
                text = f"ERROR: {exc}"
            self._event_queue.put(("replay_result", text))

        threading.Thread(target=worker, daemon=True).start()

    def _set_replay_response(self, text: str) -> None:
        self._replay_resp_text.configure(state="normal")
        self._replay_resp_text.delete("1.0", "end")
        self._replay_resp_text.insert("end", text)
        self._replay_resp_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def _load_for_stats(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSONL files", "*.jsonl"), ("All files", "*.*")],
            title="Load JSONL for statistics",
        )
        if not path:
            return
        try:
            calls = load_jsonl(Path(path))
        except Exception as exc:
            messagebox.showerror("Load Error", str(exc))
            return
        self._show_stats(calls)

    def _refresh_stats(self) -> None:
        self._show_stats(self._calls)

    def _show_stats(self, calls: list[CapturedCall]) -> None:
        if not calls:
            self._stats_write("No calls to analyse.")
            return

        by_provider: dict[str, int] = {}
        by_model:    dict[str, int] = {}
        by_status:   dict[str, int] = {}
        total_tokens = 0

        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model  = c.model or "unknown"
            status = str(c.response_status) if c.response_status else "—"
            by_model[model]    = by_model.get(model, 0) + 1
            by_status[status]  = by_status.get(status, 0) + 1
            total_tokens      += c.prompt_tokens_estimate

        n = len(calls)
        lines = [
            f"Total calls captured : {n}",
            f"Prompt tokens (est.) : {total_tokens}",
            "",
            f"{'Provider':<22} {'Count':>6}  {'Share':>6}",
            "-" * 38,
        ]
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<20} {v:>6}  {100*v/n:>5.1f}%")
        lines += ["", f"{'Model':<32} {'Count':>6}  {'Share':>6}", "-" * 46]
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<30} {v:>6}  {100*v/n:>5.1f}%")
        lines += ["", f"{'HTTP Status':<16} {'Count':>6}", "-" * 24]
        for k, v in sorted(by_status.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<14} {v:>6}")

        self._stats_write("\n".join(lines))

    def _stats_write(self, text: str) -> None:
        self._stats_text.configure(state="normal")
        self._stats_text.delete("1.0", "end")
        self._stats_text.insert("end", text)
        self._stats_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _set_status(self, msg: str) -> None:
        self._status_var.set(f"  {msg}")

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About Android LLM Capture",
            textwrap.dedent(f"""\
                android-llm-capture  v{__version__}

                ADB-based tool for capturing and replaying LLM API
                calls from closed Android applications.

                Stdlib-only — no external dependencies.

                Author: Vaibhav Deshmukh
                License: MIT
            """),
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
