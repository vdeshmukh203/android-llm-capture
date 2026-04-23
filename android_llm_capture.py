"""
android_llm_capture: Capture and replay LLM API calls from Android applications via ADB.

Uses Android Debug Bridge (ADB) logcat stream parsing to intercept, record, and replay
HTTP requests made by LLM SDKs running inside Android apps without requiring root or
app modification.
"""
from __future__ import annotations
import re, json, subprocess, threading, time, hashlib, datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":     re.compile(r"https://api\.openai\.com/v\d+/(chat/completions|completions|embeddings)"),
    "anthropic":  re.compile(r"https://api\.anthropic\.com/v\d+/messages"),
    "cohere":     re.compile(r"https://api\.cohere\.ai/v\d+/generate"),
    "huggingface":re.compile(r"https://api-inference\.huggingface\.co/models/"),
    "palm":       re.compile(r"https://generativelanguage\.googleapis\.com"),
    "azure_oai":  re.compile(r"https://[^.]+\.openai\.azure\.com/openai/deployments/"),
}

LOGCAT_TAGS = ["OkHttp", "Retrofit", "HttpLogging", "NetworkInterceptor",
               "Volley", "AndroidHttpClient"]

class CapturedCall:
    """A single captured LLM API interaction."""
    def __init__(self, provider, url, method, request_body, response_body,
                 timestamp=None, package=""):
        self.provider = provider
        self.url = url
        self.method = method.upper()
        self.request_body = request_body
        self.response_body = response_body
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()
        self.package = package
        self.call_id = hashlib.sha256(
            f"{self.timestamp}{self.url}{self.request_body}".encode()
        ).hexdigest()[:16]

    def request_json(self):
        try:
            return json.loads(self.request_body) if self.request_body else None
        except json.JSONDecodeError:
            return None

    def response_json(self):
        try:
            return json.loads(self.response_body) if self.response_body else None
        except json.JSONDecodeError:
            return None

    def to_dict(self):
        return {
            "call_id": self.call_id, "provider": self.provider,
            "url": self.url, "method": self.method,
            "package": self.package, "timestamp": self.timestamp,
            "request_body": self.request_body, "response_body": self.response_body,
        }

def _adb(*args, device=None):
    cmd = ["adb"] + (["-s", device] if device else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)

def list_devices():
    result = _adb("devices")
    return [l.split()[0] for l in result.stdout.splitlines()[1:] if l.split()[1:] == ["device"]]

def list_packages(device=None):
    r = _adb("shell", "pm", "list", "packages", device=device)
    return [l.replace("package:", "").strip() for l in r.stdout.splitlines() if l.startswith("package:")]

def get_device_model(device=None):
    return _adb("shell", "getprop", "ro.product.model", device=device).stdout.strip()

_URL_RE = re.compile(r"(https?://\S+)")
_JSON_RE = re.compile(r"(\{.*\}|\[.*\])")

def _detect_provider(url):
    for name, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return name
    return "unknown"

def _parse_logcat_line(line):
    url_match = _URL_RE.search(line)
    if not url_match:
        return None
    url = url_match.group(1).rstrip(")")
    provider = _detect_provider(url)
    if provider == "unknown":
        return None
    method = "POST"
    for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        if f"--> {m}" in line:
            method = m
            break
    body_match = _JSON_RE.search(line)
    body = body_match.group(0) if body_match else None
    direction = "request" if "-->" in line else "response" if "<--" in line else "unknown"
    return {"url": url, "provider": provider, "method": method,
            "body": body, "direction": direction}

class LLMCapture:
    """Captures LLM API calls from an Android device via ADB logcat."""
    def __init__(self, device=None, output_path=None, providers=None):
        self.device = device
        self.output_path = Path(output_path) if output_path else None
        self.providers = set(providers) if providers else set(LLM_PATTERNS.keys())
        self._calls = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def _stream_logcat(self):
        tag_args = []
        for tag in LOGCAT_TAGS:
            tag_args += ["-s", f"{tag}:D"]
        cmd = ["adb"] + (["-s", self.device] if self.device else [])
        cmd += ["logcat", "-v", "brief"] + tag_args
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors="replace") as proc:
            for line in proc.stdout:
                if self._stop_event.is_set():
                    proc.terminate()
                    break
                yield line.rstrip()

    def _process_lines(self):
        pending = {}
        for line in self._stream_logcat():
            parsed = _parse_logcat_line(line)
            if not parsed:
                continue
            url = parsed["url"]
            if parsed["direction"] == "request":
                pending[url] = {
                    "provider": parsed["provider"], "url": url,
                    "method": parsed["method"], "request_body": parsed["body"],
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                }
            elif parsed["direction"] == "response" and url in pending:
                entry = pending.pop(url)
                call = CapturedCall(
                    provider=entry["provider"], url=entry["url"],
                    method=entry["method"], request_body=entry.get("request_body"),
                    response_body=parsed["body"], timestamp=entry["timestamp"],
                )
                with self._lock:
                    self._calls.append(call)
                    if self.output_path:
                        with self.output_path.open("a") as f:
                            f.write(json.dumps(call.to_dict()) + "\n")

    def capture(self, duration=60.0):
        """Stream logcat for duration seconds and return captured calls."""
        self._stop_event.clear()
        self._calls = []
        t = threading.Thread(target=self._process_lines, daemon=True)
        t.start()
        time.sleep(duration)
        self._stop_event.set()
        t.join(timeout=5)
        return list(self._calls)

    def stop(self):
        self._stop_event.set()
        return list(self._calls)

    def __enter__(self): return self
    def __exit__(self, *_): self.stop()

def replay_call(call, token, timeout=30.0):
    """Re-issue a captured LLM API call using the stored request body."""
    import urllib.request
    if not call.request_body:
        raise ValueError(f"Call {call.call_id} has no stored request body.")
    req = urllib.request.Request(
        url=call.url, data=call.request_body.encode(), method=call.method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        raise RuntimeError(f"Replay failed for {call.call_id}: {exc}") from exc

def _cli():
    import argparse
    parser = argparse.ArgumentParser(prog="android-llm-capture",
        description="Capture LLM API calls from Android apps via ADB logcat.")
    sub = parser.add_subparsers(dest="cmd")
    cap_p = sub.add_parser("capture", help="Capture calls for N seconds.")
    cap_p.add_argument("-d", "--device", default=None)
    cap_p.add_argument("-t", "--duration", type=float, default=60.0)
    cap_p.add_argument("-o", "--output", default="captures.jsonl")
    sub.add_parser("devices", help="List connected ADB devices.")
    args = parser.parse_args()
    if args.cmd == "devices":
        devs = list_devices()
        print("\n".join(devs) if devs else "No devices connected.")
    elif args.cmd == "capture":
        print(f"Capturing for {args.duration}s -> {args.output}")
        with LLMCapture(device=args.device, output_path=args.output) as cap:
            calls = cap.capture(duration=args.duration)
        print(f"Captured {len(calls)} LLM call(s).")
        for c in calls:
            print(f"  [{c.provider}] {c.method} {c.url} (id={c.call_id})")
    else:
        parser.print_help()

if __name__ == "__main__":
    _cli()
