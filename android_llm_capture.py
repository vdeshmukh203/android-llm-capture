#!/usr/bin/env python3
"""
android_llm_capture.py — Android LLM Network Traffic Capture

Parses Android logcat output to intercept and replay LLM API calls.
Stdlib-only; no external dependencies required.
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
    "openai":      re.compile(r"api\.openai\.com/v1/", re.IGNORECASE),
    "anthropic":   re.compile(r"api\.anthropic\.com/", re.IGNORECASE),
    "google":      re.compile(r"generativelanguage\.googleapis\.com/", re.IGNORECASE),
    "cohere":      re.compile(r"api\.cohere\.ai/", re.IGNORECASE),
    "mistral":     re.compile(r"api\.mistral\.ai/", re.IGNORECASE),
    "together":    re.compile(r"api\.together\.ai/", re.IGNORECASE),
    "huggingface": re.compile(r"api-inference\.huggingface\.co/", re.IGNORECASE),
    "groq":        re.compile(r"api\.groq\.com/", re.IGNORECASE),
}

# OkHttp logging-interceptor line patterns
_OKHTTP_REQUEST  = re.compile(
    r"--> (?P<method>POST|GET|PUT|PATCH|DELETE) (?P<url>https?://\S+)"
)
_OKHTTP_REQ_END  = re.compile(r"--> END \w+")
_OKHTTP_RESPONSE = re.compile(
    r"<-- (?P<status>\d{3}) .+ (?P<url>https?://\S+)"
)
_OKHTTP_RESP_END = re.compile(r"<-- END HTTP")

# Cronet URL-level detection (body rarely available via logcat)
_CRONET_URL = re.compile(
    r"(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)",
    re.IGNORECASE,
)

# A line whose first non-whitespace character opens a JSON object or array
_JSON_LINE = re.compile(r"^\s*[{\[]")


def _detect_provider(url: str) -> Optional[str]:
    """Return the provider name for a URL, or ``None`` if not an LLM endpoint."""
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
    """A single captured LLM API request/response pair."""

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str  # "logcat" or "file"
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        self.request_hash = _sha256(req_str)
        self.response_hash = _sha256(self.response_body or "")

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def model(self) -> Optional[str]:
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough token count from request messages (word-count × 4/3)."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "")
            for m in messages
            if isinstance(m, dict) and isinstance(m.get("content"), str)
        )
        return max(1, len(text.split()) * 4 // 3)


# ---------------------------------------------------------------------------
# Logcat line parser
# ---------------------------------------------------------------------------

def _new_call_state(url: str, method: str, provider: str) -> Dict:
    return {
        "url": url,
        "method": method,
        "provider": provider,
        "body_lines": [],
        "resp_lines": [],
        "phase": "request",
    }


def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    """Stateful parser for a single logcat line.

    *state* is mutated to accumulate partial call information across consecutive
    lines.  Returns a :class:`CapturedCall` when a complete request/response
    pair is detected, otherwise returns ``None``.

    Supported interceptors
    ----------------------
    * OkHttp ``HttpLoggingInterceptor`` (request + response body)
    * Cronet (URL-level only; no body extraction)
    """
    line = line.strip()
    if not line:
        return None

    # OkHttp request start — always resets state for a new outgoing call
    m = _OKHTTP_REQUEST.search(line)
    if m:
        url = m.group("url")
        provider = _detect_provider(url)
        if provider:
            state.clear()
            state.update(_new_call_state(url, m.group("method"), provider))
        return None

    phase = state.get("phase")

    # ---- request phase: accumulate body until the end-of-request marker ----
    if phase == "request":
        if _OKHTTP_REQ_END.search(line):
            state["phase"] = "awaiting_response"
            return None
        # OkHttp may jump straight to response for HEAD requests / 304 replies
        m_resp = _OKHTTP_RESPONSE.search(line)
        if m_resp and _detect_provider(m_resp.group("url")):
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
            return None
        if _JSON_LINE.match(line):
            state["body_lines"].append(line)
        return None

    # ---- awaiting response header ------------------------------------------
    if phase == "awaiting_response":
        m_resp = _OKHTTP_RESPONSE.search(line)
        if m_resp:
            state["response_status"] = int(m_resp.group("status"))
            state["phase"] = "response"
        return None

    # ---- response phase: accumulate body until end-of-response marker ------
    if phase == "response":
        if _OKHTTP_RESP_END.search(line):
            body_text = "".join(state.get("resp_lines", [])).strip() or None
            call = _finalise_call(state, body_text)
            state.clear()
            return call
        if _JSON_LINE.match(line):
            state["resp_lines"].append(line)
        return None

    # Cronet: URL-level detection only (no body available via standard logcat)
    m_cronet = _CRONET_URL.search(line)
    if m_cronet:
        url = m_cronet.group("url")
        provider = _detect_provider(url)
        if provider:
            state.clear()
            state.update(_new_call_state(url, "POST", provider))

    return None


def _finalise_call(state: Dict, response_body: Optional[str]) -> CapturedCall:
    """Build a :class:`CapturedCall` from accumulated parser state."""
    body_json: Optional[Dict] = None
    raw = "".join(state.get("body_lines", []))
    if raw:
        try:
            body_json = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            body_json = None
    call_id = _sha256(f"{time.time()}{state.get('url', '')}")[:16]
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
    """Parse a saved logcat dump and return all detected LLM API calls."""
    calls: List[CapturedCall] = []
    state: Dict = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result = parse_logcat_line(line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls


# ---------------------------------------------------------------------------
# JSONL loader
# ---------------------------------------------------------------------------

def load_jsonl(path: Path) -> List[CapturedCall]:
    """Reconstruct :class:`CapturedCall` objects from a JSONL captures file."""
    calls: List[CapturedCall] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
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
    return calls


# ---------------------------------------------------------------------------
# CaptureSession (live logcat)
# ---------------------------------------------------------------------------

class CaptureSession:
    """Manages a live ADB logcat capture session."""

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
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
        """Yield :class:`CapturedCall` objects as they are detected in logcat."""
        if not self._proc:
            raise RuntimeError("Call start() before streaming.")
        state: Dict = {}
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            result = parse_logcat_line(line, state)
            if result:
                self.calls.append(result)
                yield result

    def export_jsonl(self, path: Path) -> None:
        """Write all captured calls to *path* as JSONL."""
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        print(f"Exported {len(self.calls)} calls to {path}")

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        """Re-send *call* to the real API endpoint and return the parsed response."""
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
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------

def list_devices() -> List[str]:
    """Return serial strings for all connected (non-offline) ADB devices."""
    try:
        out = subprocess.check_output(["adb", "devices"], timeout=10, text=True)
        lines = out.strip().splitlines()[1:]  # skip the "List of devices" header
        return [
            parts[0]
            for l in lines
            if l.strip() and "offline" not in l
            for parts in [l.split()]
            if parts
        ]
    except Exception:
        return []


def list_packages(device: Optional[str] = None) -> List[str]:
    """Return installed package names on the connected Android device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "pm", "list", "packages"]
    try:
        out = subprocess.check_output(cmd, timeout=30, text=True)
        return [
            l.replace("package:", "").strip()
            for l in out.splitlines()
            if l.startswith("package:")
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Statistics helper
# ---------------------------------------------------------------------------

def compute_stats(calls: List[Dict]) -> Dict[str, Any]:
    """Return provider/model frequency counts for a list of raw call dicts."""
    by_provider: Dict[str, int] = {}
    by_model: Dict[str, int] = {}
    for c in calls:
        prov = c.get("provider", "unknown")
        by_provider[prov] = by_provider.get(prov, 0) + 1
        model = (c.get("request_body") or {}).get("model", "unknown")
        by_model[model] = by_model.get(model, 0) + 1
    return {
        "total": len(calls),
        "by_provider": by_provider,
        "by_model": by_model,
    }


# ---------------------------------------------------------------------------
# GUI (tkinter — stdlib only)
# ---------------------------------------------------------------------------

def launch_gui() -> None:
    """Launch the tkinter graphical interface."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk
    except ImportError:
        print("tkinter is not available in this Python installation.", file=sys.stderr)
        sys.exit(1)

    import datetime
    import threading

    root = tk.Tk()
    root.title("android-llm-capture")
    root.geometry("960x660")
    root.minsize(720, 520)

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    # ------------------------------------------------------------------ #
    # Tab 1 — Live Capture                                                 #
    # ------------------------------------------------------------------ #
    cap_frame = ttk.Frame(notebook)
    notebook.add(cap_frame, text="Live Capture")

    ctrl = ttk.Frame(cap_frame)
    ctrl.pack(fill=tk.X, padx=8, pady=6)

    ttk.Label(ctrl, text="Device:").grid(row=0, column=0, sticky=tk.W)
    device_var = tk.StringVar()
    device_cb = ttk.Combobox(ctrl, textvariable=device_var, width=22, state="readonly")
    device_cb.grid(row=0, column=1, padx=4)

    def refresh_devices() -> None:
        devs = list_devices()
        device_cb["values"] = devs if devs else ["(none)"]
        device_var.set(devs[0] if devs else "(none)")

    ttk.Button(ctrl, text="Refresh", command=refresh_devices).grid(row=0, column=2, padx=4)

    ttk.Label(ctrl, text="Tag:").grid(row=0, column=3, padx=(14, 0))
    tag_var = tk.StringVar(value="OkHttp")
    ttk.Entry(ctrl, textvariable=tag_var, width=12).grid(row=0, column=4, padx=4)

    ttk.Label(ctrl, text="Output:").grid(row=1, column=0, sticky=tk.W, pady=4)
    out_var = tk.StringVar(value="captures.jsonl")
    ttk.Entry(ctrl, textvariable=out_var, width=32).grid(row=1, column=1, columnspan=2, padx=4)

    def browse_output() -> None:
        p = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")],
        )
        if p:
            out_var.set(p)

    ttk.Button(ctrl, text="Browse…", command=browse_output).grid(row=1, column=3, padx=4)

    btn_frame = ttk.Frame(cap_frame)
    btn_frame.pack(fill=tk.X, padx=8)

    log_box = scrolledtext.ScrolledText(cap_frame, height=22, font=("Courier", 10), state=tk.DISABLED)
    log_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

    status_var = tk.StringVar(value="Idle")
    ttk.Label(cap_frame, textvariable=status_var, anchor=tk.W).pack(fill=tk.X, padx=8)

    cap_ctx: Dict[str, Any] = {}

    def _log(msg: str) -> None:
        log_box.configure(state=tk.NORMAL)
        log_box.insert(tk.END, msg + "\n")
        log_box.see(tk.END)
        log_box.configure(state=tk.DISABLED)

    def _capture_thread(serial: str, tag: str, out_path: str) -> None:
        session = CaptureSession(device_serial=serial or None, tag_filter=tag)
        cap_ctx["session"] = session
        try:
            session.start()
        except RuntimeError as exc:
            root.after(0, lambda: messagebox.showerror("ADB error", str(exc)))
            root.after(0, lambda: _reset_buttons())
            return
        root.after(0, lambda: status_var.set("Capturing…"))
        try:
            for call in session.stream():
                if cap_ctx.get("stop"):
                    break
                ts = datetime.datetime.fromtimestamp(call.timestamp).strftime("%H:%M:%S")
                msg = (
                    f"[{ts}] {call.provider:10s} {call.method:6s} "
                    f"{call.url[:50]}  → {call.response_status}"
                )
                root.after(0, lambda m=msg: _log(m))
        except Exception as exc:
            root.after(0, lambda: _log(f"Error: {exc}"))
        finally:
            session.stop()
            session.export_jsonl(Path(out_path))
            n = len(session.calls)
            root.after(0, lambda: status_var.set(f"Done — {n} call(s) saved to {out_path}"))
            root.after(0, _reset_buttons)

    def _reset_buttons() -> None:
        start_btn.configure(state=tk.NORMAL)
        stop_btn.configure(state=tk.DISABLED)

    def start_capture() -> None:
        log_box.configure(state=tk.NORMAL)
        log_box.delete("1.0", tk.END)
        log_box.configure(state=tk.DISABLED)
        cap_ctx.clear()
        serial = device_var.get().strip()
        if serial in ("", "(none)"):
            serial = ""
        tag  = tag_var.get().strip() or "OkHttp"
        out  = out_var.get().strip() or "captures.jsonl"
        start_btn.configure(state=tk.DISABLED)
        stop_btn.configure(state=tk.NORMAL)
        status_var.set("Starting…")
        threading.Thread(target=_capture_thread, args=(serial, tag, out), daemon=True).start()

    def stop_capture() -> None:
        cap_ctx["stop"] = True
        s = cap_ctx.get("session")
        if s:
            s.stop()

    start_btn = ttk.Button(btn_frame, text="Start Capture", command=start_capture)
    start_btn.pack(side=tk.LEFT, padx=4, pady=4)
    stop_btn = ttk.Button(btn_frame, text="Stop", command=stop_capture, state=tk.DISABLED)
    stop_btn.pack(side=tk.LEFT, padx=4)

    refresh_devices()

    # ------------------------------------------------------------------ #
    # Tab 2 — Parse File                                                   #
    # ------------------------------------------------------------------ #
    parse_frame = ttk.Frame(notebook)
    notebook.add(parse_frame, text="Parse File")

    pctrl = ttk.Frame(parse_frame)
    pctrl.pack(fill=tk.X, padx=8, pady=6)

    ttk.Label(pctrl, text="Logcat file:").grid(row=0, column=0, sticky=tk.W)
    pfile_var = tk.StringVar()
    ttk.Entry(pctrl, textvariable=pfile_var, width=44).grid(row=0, column=1, padx=4)

    def browse_input() -> None:
        p = filedialog.askopenfilename(
            filetypes=[("Text / Log", "*.txt *.log"), ("All files", "*")]
        )
        if p:
            pfile_var.set(p)

    ttk.Button(pctrl, text="Browse…", command=browse_input).grid(row=0, column=2, padx=4)

    pout_var = tk.StringVar(value="parsed.jsonl")
    ttk.Label(pctrl, text="Output:").grid(row=1, column=0, sticky=tk.W, pady=4)
    ttk.Entry(pctrl, textvariable=pout_var, width=44).grid(row=1, column=1, padx=4)

    json_array_var = tk.BooleanVar()
    ttk.Checkbutton(pctrl, text="JSON array", variable=json_array_var).grid(row=1, column=2)

    parse_log = scrolledtext.ScrolledText(parse_frame, height=22, font=("Courier", 10), state=tk.DISABLED)
    parse_log.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

    def do_parse() -> None:
        src = pfile_var.get().strip()
        if not src:
            messagebox.showwarning("No file", "Select a logcat file first.")
            return
        p = Path(src)
        if not p.is_file():
            messagebox.showerror("Not found", f"{p} does not exist.")
            return
        calls = parse_logcat_file(p)
        out = Path(pout_var.get().strip() or "parsed.jsonl")
        with out.open("w", encoding="utf-8") as fh:
            if json_array_var.get():
                fh.write(json.dumps([c.to_dict() for c in calls], indent=2, ensure_ascii=False))
            else:
                for c in calls:
                    fh.write(c.to_jsonl() + "\n")
        parse_log.configure(state=tk.NORMAL)
        parse_log.delete("1.0", tk.END)
        parse_log.insert(tk.END, f"Found {len(calls)} LLM call(s) → {out}\n\n")
        for c in calls:
            parse_log.insert(
                tk.END,
                f"  [{c.provider}] {c.method} {c.url[:60]}\n"
                f"    status={c.response_status}  model={c.model}\n\n",
            )
        parse_log.configure(state=tk.DISABLED)

    ttk.Button(pctrl, text="Parse", command=do_parse).grid(row=0, column=3, padx=8)

    # ------------------------------------------------------------------ #
    # Tab 3 — Call Viewer                                                  #
    # ------------------------------------------------------------------ #
    view_frame = ttk.Frame(notebook)
    notebook.add(view_frame, text="Call Viewer")

    vtop = ttk.Frame(view_frame)
    vtop.pack(fill=tk.X, padx=8, pady=6)

    vfile_var = tk.StringVar()
    ttk.Entry(vtop, textvariable=vfile_var, width=55).pack(side=tk.LEFT, padx=4)

    loaded_calls: List[CapturedCall] = []

    cols = ("call_id", "timestamp", "provider", "method", "url", "status", "model")
    col_widths = {
        "call_id": 120, "timestamp": 148, "provider": 84,
        "method": 56, "url": 290, "status": 56, "model": 130,
    }

    tree_outer = ttk.Frame(view_frame)
    tree_outer.pack(fill=tk.BOTH, expand=False, padx=8)

    tree = ttk.Treeview(tree_outer, columns=cols, show="headings", selectmode="browse", height=10)
    for col in cols:
        tree.heading(col, text=col)
        tree.column(col, width=col_widths.get(col, 100), anchor=tk.W)
    vsb = ttk.Scrollbar(tree_outer, orient=tk.VERTICAL, command=tree.yview)
    hsb = ttk.Scrollbar(tree_outer, orient=tk.HORIZONTAL, command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    tree_outer.columnconfigure(0, weight=1)

    detail_pane = ttk.Frame(view_frame)
    detail_pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

    ttk.Label(detail_pane, text="Request body:").pack(anchor=tk.W)
    req_text = scrolledtext.ScrolledText(detail_pane, height=8, font=("Courier", 9), state=tk.DISABLED)
    req_text.pack(fill=tk.BOTH, expand=True)
    ttk.Label(detail_pane, text="Response body:").pack(anchor=tk.W, pady=(4, 0))
    resp_text = scrolledtext.ScrolledText(detail_pane, height=8, font=("Courier", 9), state=tk.DISABLED)
    resp_text.pack(fill=tk.BOTH, expand=True)

    def _show_call(call: CapturedCall) -> None:
        for widget, content in [
            (req_text,  json.dumps(call.request_body, indent=2, ensure_ascii=False) if call.request_body else ""),
            (resp_text, _pretty_json(call.response_body)),
        ]:
            widget.configure(state=tk.NORMAL)
            widget.delete("1.0", tk.END)
            widget.insert(tk.END, content)
            widget.configure(state=tk.DISABLED)

    def _pretty_json(s: Optional[str]) -> str:
        if not s:
            return ""
        try:
            return json.dumps(json.loads(s), indent=2, ensure_ascii=False)
        except Exception:
            return s

    def on_tree_select(event: Any) -> None:
        sel = tree.selection()
        if not sel:
            return
        idx = tree.index(sel[0])
        if 0 <= idx < len(loaded_calls):
            _show_call(loaded_calls[idx])

    tree.bind("<<TreeviewSelect>>", on_tree_select)

    def load_jsonl_gui() -> None:
        p = filedialog.askopenfilename(
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")]
        )
        if not p:
            return
        vfile_var.set(p)
        loaded_calls.clear()
        try:
            loaded_calls.extend(load_jsonl(Path(p)))
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))
            return
        for item in tree.get_children():
            tree.delete(item)
        for call in loaded_calls:
            ts = datetime.datetime.fromtimestamp(call.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            tree.insert("", tk.END, values=(
                call.call_id, ts, call.provider, call.method,
                call.url[:60], call.response_status or "", call.model or "",
            ))

    ttk.Button(vtop, text="Load JSONL…", command=load_jsonl_gui).pack(side=tk.LEFT, padx=4)

    # ------------------------------------------------------------------ #
    # Tab 4 — Statistics                                                   #
    # ------------------------------------------------------------------ #
    stats_frame = ttk.Frame(notebook)
    notebook.add(stats_frame, text="Stats")

    sctrl = ttk.Frame(stats_frame)
    sctrl.pack(fill=tk.X, padx=8, pady=6)

    sfile_var = tk.StringVar()
    ttk.Entry(sctrl, textvariable=sfile_var, width=55).pack(side=tk.LEFT, padx=4)

    stats_text = scrolledtext.ScrolledText(stats_frame, height=28, font=("Courier", 10), state=tk.DISABLED)
    stats_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

    def load_stats() -> None:
        p = filedialog.askopenfilename(
            filetypes=[("JSONL", "*.jsonl"), ("All files", "*")]
        )
        if not p:
            return
        sfile_var.set(p)
        raw: List[Dict] = []
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    raw.append(json.loads(line))
        s = compute_stats(raw)
        stats_text.configure(state=tk.NORMAL)
        stats_text.delete("1.0", tk.END)
        stats_text.insert(tk.END, f"File: {p}\n")
        stats_text.insert(tk.END, f"Total calls: {s['total']}\n\n")
        stats_text.insert(tk.END, "By provider:\n")
        for k, v in sorted(s["by_provider"].items(), key=lambda x: -x[1]):
            bar = "█" * v
            stats_text.insert(tk.END, f"  {k:<14s} {v:4d}  {bar}\n")
        stats_text.insert(tk.END, "\nBy model:\n")
        for k, v in sorted(s["by_model"].items(), key=lambda x: -x[1]):
            bar = "█" * v
            stats_text.insert(tk.END, f"  {k:<24s} {v:4d}  {bar}\n")
        stats_text.configure(state=tk.DISABLED)

    ttk.Button(sctrl, text="Load JSONL…", command=load_stats).pack(side=tk.LEFT, padx=4)

    root.mainloop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="android-llm-capture",
        description="Capture and replay Android LLM API calls.",
    )
    sub = p.add_subparsers(dest="command")

    # live
    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None, help="Android device serial (adb -s).")
    live_p.add_argument("--tag", default="OkHttp", help="Logcat tag to filter (default: OkHttp).")
    live_p.add_argument("--output", "-o", default="captures.jsonl", metavar="FILE")
    live_p.add_argument(
        "--timeout", type=int, default=0,
        help="Stop after N seconds (0 = run until Ctrl-C).",
    )

    # file
    file_p = sub.add_parser("file", help="Parse a saved logcat file.")
    file_p.add_argument("logcat", help="Path to a logcat dump file.")
    file_p.add_argument("--output", "-o", default="captures.jsonl", metavar="FILE")
    file_p.add_argument(
        "--json", action="store_true",
        help="Write a JSON array instead of JSONL.",
    )

    # replay
    replay_p = sub.add_parser("replay", help="Replay a captured call against the real API.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id", help="call_id to replay, or 'last'.")
    replay_p.add_argument("--api-key", required=True, help="Provider API key.")

    # stats
    stats_p = sub.add_parser("stats", help="Print statistics for a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    # gui
    sub.add_parser("gui", help="Launch the graphical user interface.")

    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.command == "gui":
        launch_gui()
        return 0

    if args.command == "live":
        session = CaptureSession(device_serial=args.serial, tag_filter=args.tag)
        print(f"Starting live capture (tag={args.tag}). Press Ctrl-C to stop.")
        try:
            session.start()
            t0 = time.time()
            for call in session.stream():
                print(
                    f"[{call.provider}] {call.method} {call.url[:60]}"
                    f"  status={call.response_status}"
                )
                if args.timeout and (time.time() - t0) > args.timeout:
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
        print(f"Found {len(calls)} LLM call(s) → {out}")
        return 0

    if args.command == "replay":
        caps_path = Path(args.captures)
        if not caps_path.is_file():
            print(f"Error: {caps_path} not found", file=sys.stderr)
            return 1
        calls = load_jsonl(caps_path)
        if not calls:
            print("No calls found in captures file.", file=sys.stderr)
            return 1
        if args.call_id == "last":
            target = calls[-1]
        else:
            target = next((c for c in calls if c.call_id == args.call_id), None)
        if not target:
            print(f"call_id {args.call_id!r} not found.", file=sys.stderr)
            return 1
        result = CaptureSession().replay(target, api_key=args.api_key)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if args.command == "stats":
        caps_path = Path(args.captures)
        if not caps_path.is_file():
            print(f"Error: {caps_path} not found", file=sys.stderr)
            return 1
        raw: List[Dict] = []
        with caps_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    raw.append(json.loads(line))
        s = compute_stats(raw)
        print(f"Total calls: {s['total']}")
        print("By provider:")
        for k, v in sorted(s["by_provider"].items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("By model:")
        for k, v in sorted(s["by_model"].items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    print("android-llm-capture: specify a subcommand (live, file, replay, stats, gui)")
    print("Use --help for usage.")
    return 1


# ---------------------------------------------------------------------------
# Backwards-compatible aliases
# ---------------------------------------------------------------------------

#: Alias kept for code that imported the old name.
LLMCapture = CaptureSession

#: Entry-point target declared in pyproject.toml.
_cli = main


if __name__ == "__main__":
    sys.exit(main())
