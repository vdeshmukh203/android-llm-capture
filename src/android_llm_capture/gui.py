"""Tkinter GUI for android-llm-capture.

Launch with::

    python -m android_llm_capture.gui
    # or
    android-llm-capture-gui          # if installed via pip
    # or
    android-llm-capture gui          # CLI subcommand
"""

from __future__ import annotations

import datetime
import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from pathlib import Path
from typing import Dict, List, Optional

from .adb import ADBClient
from .capture import AndroidCapture, CapturedCall, parse_logcat_file, load_jsonl


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class CaptureApp(tk.Tk):
    """Full-featured GUI for capturing and inspecting Android LLM API calls."""

    _VERSION = "0.1.0"

    def __init__(self) -> None:
        super().__init__()
        self.title("android-llm-capture")
        self.geometry("1200x720")
        self.minsize(860, 520)

        self._session: Optional[AndroidCapture] = None
        self._thread: Optional[threading.Thread] = None
        self._queue: queue.Queue[CapturedCall] = queue.Queue()
        self._calls: List[CapturedCall] = []
        self._running = False

        self._build_ui()
        self._refresh_devices()
        self._poll_queue()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

    def _build_menu(self) -> None:
        mb = tk.Menu(self)

        fm = tk.Menu(mb, tearoff=0)
        fm.add_command(label="Open logcat / JSONL…", command=self._open_file, accelerator="Ctrl+O")
        fm.add_command(label="Export JSONL…",        command=self._export,    accelerator="Ctrl+S")
        fm.add_separator()
        fm.add_command(label="Quit", command=self.quit)
        mb.add_cascade(label="File", menu=fm)

        cm = tk.Menu(mb, tearoff=0)
        cm.add_command(label="Start capture", command=self._start_capture)
        cm.add_command(label="Stop capture",  command=self._stop_capture)
        cm.add_separator()
        cm.add_command(label="Refresh devices", command=self._refresh_devices)
        cm.add_separator()
        cm.add_command(label="Clear calls", command=self._clear_calls)
        mb.add_cascade(label="Capture", menu=cm)

        hm = tk.Menu(mb, tearoff=0)
        hm.add_command(label="About", command=self._show_about)
        mb.add_cascade(label="Help", menu=hm)

        self.config(menu=mb)
        self.bind("<Control-o>", lambda _: self._open_file())
        self.bind("<Control-s>", lambda _: self._export())

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(4, 3))
        bar.pack(side=tk.TOP, fill=tk.X)

        # Device selector
        ttk.Label(bar, text="Device:").pack(side=tk.LEFT, padx=(0, 2))
        self._dev_var = tk.StringVar(value="(none)")
        self._dev_cb  = ttk.Combobox(bar, textvariable=self._dev_var, width=26, state="readonly")
        self._dev_cb.pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(bar, text="⟳", command=self._refresh_devices, width=3).pack(side=tk.LEFT, padx=(0, 8))

        # Tag filter
        ttk.Label(bar, text="Tag:").pack(side=tk.LEFT, padx=(0, 2))
        self._tag_var = tk.StringVar(value="OkHttp")
        ttk.Entry(bar, textvariable=self._tag_var, width=12).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        # Capture controls
        self._btn_start = ttk.Button(bar, text="▶  Start", command=self._start_capture, width=11)
        self._btn_start.pack(side=tk.LEFT, padx=2)
        self._btn_stop  = ttk.Button(bar, text="■  Stop",  command=self._stop_capture,
                                     width=11, state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=2)

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        ttk.Button(bar, text="Open File…", command=self._open_file, width=11).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Export…",    command=self._export,    width=9).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Clear",      command=self._clear_calls, width=7).pack(side=tk.LEFT, padx=2)

        # Call counter (right-aligned)
        self._count_var = tk.StringVar(value="0 calls")
        ttk.Label(bar, textvariable=self._count_var, foreground="gray").pack(side=tk.RIGHT, padx=8)

    def _build_body(self) -> None:
        pw = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        # ── Left panel: calls treeview ─────────────────────────────────────
        lf = ttk.Frame(pw)
        pw.add(lf, weight=1)

        hdr = ttk.Frame(lf)
        hdr.pack(fill=tk.X, padx=4, pady=(4, 0))
        ttk.Label(hdr, text="Captured Calls", font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)

        tf = ttk.Frame(lf)
        tf.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        cols = ("provider", "method", "model", "status", "tokens", "time")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")

        col_defs = [
            ("provider", "Provider", 95,  tk.CENTER),
            ("method",   "Method",   60,  tk.CENTER),
            ("model",    "Model",   130,  tk.W),
            ("status",   "Status",   55,  tk.CENTER),
            ("tokens",   "~Tokens",  65,  tk.RIGHT),
            ("time",     "Time",     72,  tk.CENTER),
        ]
        for cid, heading, width, anchor in col_defs:
            self._tree.heading(cid, text=heading, command=lambda c=cid: self._sort_tree(c))
            self._tree.column(cid, width=width, anchor=anchor, minwidth=40)

        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL,   command=self._tree.yview)
        hsb = ttk.Scrollbar(tf, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # colour codes for HTTP status
        self._tree.tag_configure("ok",    foreground="#1a7f1a")
        self._tree.tag_configure("error", foreground="#cc2200")

        # ── Right panel: detail notebook ───────────────────────────────────
        rf = ttk.Frame(pw)
        pw.add(rf, weight=2)

        nb = ttk.Notebook(rf)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ── Request tab ────────────────────────────────────────────────────
        rqf = ttk.Frame(nb)
        nb.add(rqf, text="  Request  ")

        meta = ttk.Frame(rqf)
        meta.pack(fill=tk.X, padx=4, pady=(4, 0))

        for i, (lbl, attr) in enumerate([
            ("Provider:", "_det_provider_var"),
            ("Method:",   "_det_method_var"),
            ("Model:",    "_det_model_var"),
        ]):
            ttk.Label(meta, text=lbl, width=10, anchor=tk.E).grid(row=0, column=i*2,     sticky=tk.E, padx=(4, 1))
            var = tk.StringVar()
            setattr(self, attr, var)
            ttk.Entry(meta, textvariable=var, state="readonly", width=20).grid(row=0, column=i*2+1, sticky=tk.W, padx=(0, 8))

        ttk.Label(rqf, text="URL:").pack(anchor=tk.W, padx=4, pady=(4, 0))
        self._url_var = tk.StringVar()
        ttk.Entry(rqf, textvariable=self._url_var, state="readonly").pack(fill=tk.X, padx=4, pady=(0, 4))

        ttk.Label(rqf, text="Request body:").pack(anchor=tk.W, padx=4)
        self._req_txt = scrolledtext.ScrolledText(rqf, wrap=tk.WORD, font=("Courier", 9), height=16)
        self._req_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        # ── Response tab ───────────────────────────────────────────────────
        rsf = ttk.Frame(nb)
        nb.add(rsf, text="  Response  ")

        rmeta = ttk.Frame(rsf)
        rmeta.pack(fill=tk.X, padx=4, pady=(4, 0))
        ttk.Label(rmeta, text="HTTP status:", width=12, anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=(4, 1))
        self._st_var = tk.StringVar()
        ttk.Entry(rmeta, textvariable=self._st_var, state="readonly", width=6).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(rsf, text="Response body:").pack(anchor=tk.W, padx=4, pady=(4, 0))
        self._resp_txt = scrolledtext.ScrolledText(rsf, wrap=tk.WORD, font=("Courier", 9), height=20)
        self._resp_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        # ── Stats tab ──────────────────────────────────────────────────────
        stf = ttk.Frame(nb)
        nb.add(stf, text="  Stats  ")
        self._stats_txt = scrolledtext.ScrolledText(stf, wrap=tk.WORD, font=("Courier", 10))
        self._stats_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    def _build_statusbar(self) -> None:
        self._status_var = tk.StringVar(value="Ready.")
        sb = ttk.Frame(self, relief=tk.SUNKEN)
        sb.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(sb, textvariable=self._status_var, anchor=tk.W, padding=(4, 1)).pack(fill=tk.X)

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _refresh_devices(self) -> None:
        devs = ADBClient.list_devices()
        self._dev_cb["values"] = devs if devs else ["(none)"]
        if devs:
            self._dev_cb.set(devs[0])
            self._set_status(f"{len(devs)} device(s) found: {', '.join(devs)}")
        else:
            self._dev_cb.set("(none)")
            self._set_status("No ADB devices found. Connect a device or start an emulator, then click ⟳.")

    # ------------------------------------------------------------------
    # Capture control
    # ------------------------------------------------------------------

    def _start_capture(self) -> None:
        if self._running:
            return
        serial = self._dev_var.get()
        if serial == "(none)":
            messagebox.showwarning("No device selected",
                                   "Connect a device or emulator and click ⟳ to refresh.")
            return
        tag = self._tag_var.get().strip() or "OkHttp"
        self._session = AndroidCapture(device_serial=serial, tag_filter=tag)
        try:
            self._session.start()
        except RuntimeError as exc:
            messagebox.showerror("ADB error", str(exc))
            return
        self._running = True
        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._set_status(f"● Capturing from {serial}  (tag={tag})…")
        self._thread = threading.Thread(target=self._capture_worker, daemon=True)
        self._thread.start()

    def _capture_worker(self) -> None:
        assert self._session is not None
        try:
            for call in self._session.stream():
                self._queue.put(call)
        except Exception:
            pass

    def _stop_capture(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._session:
            self._session.stop()
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._set_status(f"Capture stopped.  {len(self._calls)} call(s) captured.")

    # ------------------------------------------------------------------
    # Queue polling (GUI thread)
    # ------------------------------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                call = self._queue.get_nowait()
                self._add_call(call)
        except queue.Empty:
            pass
        finally:
            self.after(150, self._poll_queue)

    # ------------------------------------------------------------------
    # Calls list management
    # ------------------------------------------------------------------

    def _add_call(self, call: CapturedCall) -> None:
        self._calls.append(call)
        ts  = datetime.datetime.fromtimestamp(call.timestamp).strftime("%H:%M:%S")
        st  = str(call.response_status or "?")
        tag = "ok" if (call.response_status or 0) < 400 else "error"
        self._tree.insert("", tk.END, iid=call.call_id, tags=(tag,), values=(
            call.provider,
            call.method,
            call.model or "—",
            st,
            call.prompt_tokens_estimate,
            ts,
        ))
        self._tree.see(call.call_id)
        self._count_var.set(f"{len(self._calls)} call{'s' if len(self._calls) != 1 else ''}")
        self._update_stats_tab()

    def _clear_calls(self) -> None:
        self._calls.clear()
        if self._session:
            self._session.calls.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._clear_detail_pane()
        self._count_var.set("0 calls")
        self._update_stats_tab()
        self._set_status("Cleared.")

    # ------------------------------------------------------------------
    # Selection / detail
    # ------------------------------------------------------------------

    def _on_tree_select(self, _evt) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        call = next((c for c in self._calls if c.call_id == sel[0]), None)
        if call:
            self._show_call_detail(call)

    def _show_call_detail(self, call: CapturedCall) -> None:
        self._det_provider_var.set(call.provider)
        self._det_method_var.set(call.method)
        self._det_model_var.set(call.model or "—")
        self._url_var.set(call.url)
        self._st_var.set(str(call.response_status or ""))

        req_content = (
            json.dumps(call.request_body, indent=2, ensure_ascii=False)
            if call.request_body else ""
        )
        resp_content = self._pretty_json(call.response_body)

        for widget, content in ((self._req_txt, req_content), (self._resp_txt, resp_content)):
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            widget.insert(tk.END, content)
            widget.config(state=tk.DISABLED)

    def _clear_detail_pane(self) -> None:
        for var in (self._det_provider_var, self._det_method_var,
                    self._det_model_var, self._url_var, self._st_var):
            var.set("")
        for widget in (self._req_txt, self._resp_txt):
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            widget.config(state=tk.DISABLED)

    @staticmethod
    def _pretty_json(body: Optional[str]) -> str:
        if not body:
            return ""
        try:
            return json.dumps(json.loads(body), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return body

    # ------------------------------------------------------------------
    # Stats tab
    # ------------------------------------------------------------------

    def _update_stats_tab(self) -> None:
        by_provider: Dict[str, int] = {}
        by_model: Dict[str, int] = {}
        total_tokens = 0
        errors = 0
        for c in self._calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            m = c.model or "unknown"
            by_model[m] = by_model.get(m, 0) + 1
            total_tokens += c.prompt_tokens_estimate
            if (c.response_status or 0) >= 400:
                errors += 1

        lines = [
            f"Total calls   : {len(self._calls)}",
            f"HTTP errors   : {errors}",
            f"Est. tokens   : {total_tokens:,}",
            "",
            "By provider",
            "-----------",
            *[f"  {k:<22} {v:>5}" for k, v in sorted(by_provider.items(), key=lambda x: -x[1])],
            "",
            "By model",
            "--------",
            *[f"  {k:<30} {v:>5}" for k, v in sorted(by_model.items(), key=lambda x: -x[1])],
        ]
        self._stats_txt.config(state=tk.NORMAL)
        self._stats_txt.delete("1.0", tk.END)
        self._stats_txt.insert(tk.END, "\n".join(lines))
        self._stats_txt.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Column sorting
    # ------------------------------------------------------------------

    def _sort_tree(self, col: str) -> None:
        rows = [(self._tree.set(k, col), k) for k in self._tree.get_children("")]
        rows.sort(key=lambda x: x[0])
        for idx, (_, k) in enumerate(rows):
            self._tree.move(k, "", idx)

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

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
            messagebox.showerror("Parse error", f"Failed to parse {p.name}:\n{exc}")
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
            filetypes=[("JSONL", "*.jsonl"), ("JSON array", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        p = Path(path)
        with p.open("w", encoding="utf-8") as fh:
            if p.suffix == ".json":
                json.dump([c.to_dict() for c in self._calls], fh, indent=2, ensure_ascii=False)
            else:
                for call in self._calls:
                    fh.write(call.to_jsonl() + "\n")
        self._set_status(f"Exported {len(self._calls)} call(s) to {p.name}")

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _set_status(self, msg: str) -> None:
        self._status_var.set(msg)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About android-llm-capture",
            f"android-llm-capture  v{self._VERSION}\n\n"
            "ADB-based tool for capturing LLM API interactions\n"
            "from Android devices and emulators.\n\n"
            "Providers detected: OpenAI · Anthropic · Google · Cohere\n"
            "                    Mistral · Together · HuggingFace · Groq\n"
            "                    Azure OpenAI · Ollama\n\n"
            "Author:  Vaibhav Deshmukh\n"
            "License: MIT",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def launch_gui() -> None:
    """Launch the GUI application."""
    app = CaptureApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
