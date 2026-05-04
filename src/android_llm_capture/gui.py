"""Tkinter graphical interface for android-llm-capture."""
from __future__ import annotations

import datetime
import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import List, Optional

from ._models import CapturedCall
from ._parser import parse_logcat_file, parse_logcat_line
from .adb import ADBClient
from .capture import AndroidCapture


class _App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("android-llm-capture")
        self.geometry("1100x700")
        self.minsize(800, 500)

        self._session: Optional[AndroidCapture] = None
        self._thread: Optional[threading.Thread] = None
        self._calls: List[CapturedCall] = []

        self._build_ui()
        self._refresh_devices()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self._build_toolbar()
        self._build_status_bar()
        self._build_main_pane()

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(4, 4))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Device:").pack(side=tk.LEFT)
        self._device_var = tk.StringVar(value="(auto)")
        self._device_combo = ttk.Combobox(
            bar, textvariable=self._device_var, width=22, state="readonly"
        )
        self._device_combo.pack(side=tk.LEFT, padx=(2, 8))

        ttk.Label(bar, text="Tag:").pack(side=tk.LEFT)
        self._tag_var = tk.StringVar(value="OkHttp")
        ttk.Entry(bar, textvariable=self._tag_var, width=10).pack(
            side=tk.LEFT, padx=(2, 8)
        )

        self._start_btn = ttk.Button(
            bar, text="▶  Start Capture", command=self._start_capture
        )
        self._start_btn.pack(side=tk.LEFT, padx=2)
        self._stop_btn = ttk.Button(
            bar, text="■  Stop", command=self._stop_capture, state=tk.DISABLED
        )
        self._stop_btn.pack(side=tk.LEFT, padx=2)

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Button(bar, text="Open File…", command=self._open_file).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(bar, text="Export JSONL…", command=self._export_jsonl).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(bar, text="Clear", command=self._clear_calls).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(bar, text="Refresh Devices", command=self._refresh_devices).pack(
            side=tk.LEFT, padx=2
        )

    def _build_status_bar(self) -> None:
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(
            self,
            textvariable=self._status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(4, 2),
        ).pack(side=tk.BOTTOM, fill=tk.X)

    def _build_main_pane(self) -> None:
        pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        # --- Left: call list ---
        left = ttk.Frame(pane)
        pane.add(left, weight=2)

        cols = ("time", "provider", "method", "status", "model", "call_id")
        self._tree = ttk.Treeview(
            left, columns=cols, show="headings", selectmode="browse"
        )
        widths = (80, 90, 55, 55, 160, 120)
        for col, w in zip(cols, widths):
            heading = col.replace("_", " ").title()
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=w, minwidth=40)
        self._tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        vsb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self._tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.tag_configure("ok", foreground="#006400")
        self._tree.tag_configure("err", foreground="#8B0000")

        # --- Right: detail notebook ---
        right = ttk.Frame(pane)
        pane.add(right, weight=3)

        nb = ttk.Notebook(right)
        nb.pack(fill=tk.BOTH, expand=True)

        self._req_text = self._make_text(nb)
        nb.add(self._req_text, text="Request Body")

        self._resp_text = self._make_text(nb)
        nb.add(self._resp_text, text="Response Body")

        self._meta_text = self._make_text(nb)
        nb.add(self._meta_text, text="Metadata")

        stats_frame = ttk.Frame(right)
        nb.add(stats_frame, text="Statistics")
        self._stats_text = scrolledtext.ScrolledText(
            stats_frame, wrap=tk.WORD, font=("Courier", 10), state=tk.DISABLED
        )
        self._stats_text.pack(fill=tk.BOTH, expand=True)

    @staticmethod
    def _make_text(parent) -> scrolledtext.ScrolledText:
        return scrolledtext.ScrolledText(
            parent, wrap=tk.WORD, font=("Courier", 10), state=tk.DISABLED
        )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _refresh_devices(self) -> None:
        try:
            devices = ADBClient().list_devices()
        except RuntimeError:
            devices = []
        values = ["(auto)"] + devices
        self._device_combo["values"] = values
        if self._device_var.get() not in values:
            self._device_var.set("(auto)")
        n = len(devices)
        self._status_var.set(
            f"Found {n} device{'s' if n != 1 else ''}."
            + (" (adb not on PATH)" if not devices else "")
        )

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    def _start_capture(self) -> None:
        raw = self._device_var.get()
        serial = None if raw == "(auto)" else raw
        tag = self._tag_var.get().strip() or "OkHttp"

        self._session = AndroidCapture(device_serial=serial, tag_filter=tag)
        try:
            self._session.start()
        except RuntimeError as exc:
            messagebox.showerror("ADB Error", str(exc))
            self._session = None
            return

        self._start_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)
        self._status_var.set("Capturing…")

        self._thread = threading.Thread(target=self._capture_worker, daemon=True)
        self._thread.start()

    def _capture_worker(self) -> None:
        assert self._session is not None
        try:
            for call in self._session.stream():
                self._calls.append(call)
                self.after(0, self._append_row, call)
        except Exception:
            pass

    def _stop_capture(self) -> None:
        if self._session:
            self._session.stop()
            self._session = None
        self._start_btn.config(state=tk.NORMAL)
        self._stop_btn.config(state=tk.DISABLED)
        n = len(self._calls)
        self._status_var.set(f"Stopped. {n} call{'s' if n != 1 else ''} captured.")
        self._refresh_stats()

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def _open_file(self) -> None:
        path_str = filedialog.askopenfilename(
            title="Open Logcat / Captures File",
            filetypes=[
                ("Logcat / JSONL", "*.log *.txt *.jsonl"),
                ("All files", "*.*"),
            ],
        )
        if not path_str:
            return
        p = Path(path_str)
        calls: List[CapturedCall] = []

        if p.suffix == ".jsonl":
            with p.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        calls.append(CapturedCall(
                            call_id=obj["call_id"],
                            timestamp=obj["timestamp"],
                            provider=obj["provider"],
                            url=obj["url"],
                            method=obj["method"],
                            request_body=obj.get("request_body"),
                            response_status=obj.get("response_status"),
                            response_body=obj.get("response_body"),
                            source=obj.get("source", "file"),
                        ))
                    except (KeyError, json.JSONDecodeError):
                        continue
        else:
            calls = parse_logcat_file(p)

        self._calls = calls
        self._rebuild_table()
        self._refresh_stats()
        self._status_var.set(f"Loaded {len(calls)} calls from {p.name}.")

    def _export_jsonl(self) -> None:
        if not self._calls:
            messagebox.showinfo("Export", "No calls to export.")
            return
        path_str = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path_str:
            return
        p = Path(path_str)
        with p.open("w", encoding="utf-8") as fh:
            for call in self._calls:
                fh.write(call.to_jsonl() + "\n")
        self._status_var.set(f"Exported {len(self._calls)} calls → {p.name}.")

    def _clear_calls(self) -> None:
        self._calls.clear()
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._refresh_stats()
        for widget in (self._req_text, self._resp_text, self._meta_text):
            self._set_text(widget, "")
        self._status_var.set("Cleared.")

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------

    def _append_row(self, call: CapturedCall) -> None:
        ts = datetime.datetime.fromtimestamp(call.timestamp).strftime("%H:%M:%S")
        status = call.response_status or "—"
        tag = "ok" if isinstance(status, int) and status < 400 else "err"
        self._tree.insert(
            "", tk.END, iid=call.call_id,
            values=(ts, call.provider, call.method, status, call.model or "—", call.call_id),
            tags=(tag,),
        )
        self._tree.yview_moveto(1)
        self._refresh_stats()

    def _rebuild_table(self) -> None:
        for row in self._tree.get_children():
            self._tree.delete(row)
        for call in self._calls:
            self._append_row(call)

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

        if call.request_body:
            req_text = json.dumps(call.request_body, indent=2, ensure_ascii=False)
        else:
            req_text = "(no request body captured)"
        self._set_text(self._req_text, req_text)

        if call.response_body:
            try:
                resp_text = json.dumps(
                    json.loads(call.response_body), indent=2, ensure_ascii=False
                )
            except (json.JSONDecodeError, TypeError):
                resp_text = call.response_body
        else:
            resp_text = "(no response body captured)"
        self._set_text(self._resp_text, resp_text)

        meta = {
            "call_id": call.call_id,
            "timestamp": call.timestamp,
            "provider": call.provider,
            "url": call.url,
            "method": call.method,
            "response_status": call.response_status,
            "model": call.model,
            "prompt_tokens_estimate": call.prompt_tokens_estimate,
            "source": call.source,
            "request_hash": call.request_hash,
            "response_hash": call.response_hash,
        }
        self._set_text(self._meta_text, json.dumps(meta, indent=2, ensure_ascii=False))

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def _refresh_stats(self) -> None:
        if not self._calls:
            self._set_text(self._stats_text, "No calls captured yet.")
            return
        by_provider: dict = {}
        by_model: dict = {}
        for c in self._calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model = c.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1

        lines = [f"Total calls: {len(self._calls)}", "", "By provider:"]
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            lines.append(f"  {k}: {v}")
        lines += ["", "By model:"]
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            lines.append(f"  {k}: {v}")
        self._set_text(self._stats_text, "\n".join(lines))

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _set_text(widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)


def run_gui() -> None:
    """Launch the android-llm-capture GUI (blocks until window is closed)."""
    app = _App()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
