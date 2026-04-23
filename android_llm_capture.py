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


LLM_PATTERNS: Dict[str, re.Pattern] = {
    "openai":      re.compile(r'api\.openai\.com/v1/', re.IGNORECASE),
    "anthropic":   re.compile(r'api\.anthropic\.com/', re.IGNORECASE),
    "google":      re.compile(r'generativelanguage\.googleapis\.com/', re.IGNORECASE),
    "cohere":      re.compile(r'api\.cohere\.ai/', re.IGNORECASE),
    "mistral":     re.compile(r'api\.mistral\.ai/', re.IGNORECASE),
    "together":    re.compile(r'api\.together\.ai/', re.IGNORECASE),
    "huggingface": re.compile(r'api-inference\.huggingface\.co/', re.IGNORECASE),
    "groq":        re.compile(r'api\.groq\.com/', re.IGNORECASE),
}

_OKHTTP_REQUEST  = re.compile(r'--> (?P<method>POST|GET|PUT|PATCH) (?P<url>https?://\S+)')
_OKHTTP_RESPONSE = re.compile(r'<-- (?P<status>\d{3}) .* (?P<url>https?://\S+)')
_OKHTTP_BODY     = re.compile(r'(?P<body>\{.*\}|\[.*\])')
_CRONET_URL      = re.compile(r'(?:CronetEngine|Cronet)\s*(?:request|url):\s*(?P<url>https?://\S+)', re.IGNORECASE)


def _detect_provider(url: str) -> Optional[str]:
    for provider, pattern in LLM_PATTERNS.items():
        if pattern.search(url):
            return provider
    return None


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class CapturedCall:
    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self):
        req_str = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        self.request_hash  = _sha256(req_str)
        self.response_hash = _sha256(self.response_body or "")

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def model(self) -> Optional[str]:
        return self.request_body.get("model") if self.request_body else None

    @property
    def prompt_tokens_estimate(self) -> int:
        if not self.request_body:
            return 0
        msgs = self.request_body.get("messages", [])
        text = " ".join(m.get("content","") for m in msgs if isinstance(m,dict))
        return max(1, len(text.split())*4//3)


def parse_logcat_line(line: str, state: Dict) -> Optional[CapturedCall]:
    line = line.strip()
    if not line:
        return None
    m = _OKHTTP_REQUEST.search(line)
    if m:
        url = m.group("url")
        provider = _detect_provider(url)
        if provider:
            state.update({"url":url,"method":m.group("method"),"provider":provider,
                          "body_lines":[],"phase":"request"})
        return None
    if state.get("phase")=="request" and state.get("url"):
        mb = _OKHTTP_BODY.search(line)
        if mb:
            state["body_lines"].append(mb.group("body"))
        return None
    mr = _OKHTTP_RESPONSE.search(line)
    if mr and state.get("url"):
        state["response_status"] = int(mr.group("status"))
        state["phase"] = "response"
        return None
    if state.get("phase")=="response":
        mb = _OKHTTP_BODY.search(line)
        if mb:
            raw = mb.group("body")
            call = _finalise_call(state, raw)
            state.clear()
            return call
    mc = _CRONET_URL.search(line)
    if mc:
        url = mc.group("url")
        provider = _detect_provider(url)
        if provider:
            state.update({"url":url,"method":"POST","provider":provider,"body_lines":[],"phase":"request"})
    return None


def _finalise_call(state: Dict, response_body: Optional[str]) -> CapturedCall:
    body_json = None
    if state.get("body_lines"):
        try:
            body_json = json.loads(" ".join(state["body_lines"]))
        except Exception:
            pass
    call_id = _sha256(f"{time.time()}{state.get('url','')}")[:16]
    return CapturedCall(
        call_id=call_id, timestamp=time.time(),
        provider=state.get("provider","unknown"),
        url=state.get("url",""), method=state.get("method","POST"),
        request_body=body_json, response_status=state.get("response_status"),
        response_body=response_body, source="logcat",
    )


def parse_logcat_file(path: Path) -> List[CapturedCall]:
    calls = []
    state: Dict = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result = parse_logcat_line(line, state)
            if result:
                result.source = "file"
                calls.append(result)
    return calls


class CaptureSession:
    def __init__(self, device_serial: Optional[str] = None, tag_filter: str = "OkHttp"):
        self.device_serial = device_serial
        self.tag_filter = tag_filter
        self.calls: List[CapturedCall] = []
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += ["logcat", "-v", "brief", f"{self.tag_filter}:V", "*:S"]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except FileNotFoundError:
            raise RuntimeError("adb not found — ensure Android SDK platform-tools is on PATH.")

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            self._proc = None

    def stream(self) -> Iterator[CapturedCall]:
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
        with path.open("w", encoding="utf-8") as fh:
            for call in self.calls:
                fh.write(call.to_jsonl() + "\n")
        print(f"Exported {len(self.calls)} calls to {path}")

    def replay(self, call: CapturedCall, api_key: str) -> Dict[str, Any]:
        if not call.request_body:
            raise ValueError("No request body to replay.")
        headers = {"Content-Type": "application/json"}
        if call.provider == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
        elif call.provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        payload = json.dumps(call.request_body).encode()
        req = urllib.request.Request(call.url, data=payload, headers=headers, method=call.method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


def _parse_args(argv=None):
    p = argparse.ArgumentParser(prog="android_llm_capture",
                                description="Capture and replay Android LLM API calls.")
    sub = p.add_subparsers(dest="command")
    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None)
    live_p.add_argument("--tag", default="OkHttp")
    live_p.add_argument("--output", "-o", default="captures.jsonl")
    live_p.add_argument("--timeout", type=int, default=0)
    file_p = sub.add_parser("file", help="Parse a saved logcat file.")
    file_p.add_argument("logcat")
    file_p.add_argument("--output", "-o", default="captures.jsonl")
    file_p.add_argument("--json", action="store_true")
    replay_p = sub.add_parser("replay", help="Replay a captured call.")
    replay_p.add_argument("captures")
    replay_p.add_argument("call_id")
    replay_p.add_argument("--api-key", required=True)
    stats_p = sub.add_parser("stats", help="Show statistics about a captures file.")
    stats_p.add_argument("captures")
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
                if args.timeout and (time.time()-start) > args.timeout:
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
    if args.command == "stats":
        calls = []
        with open(args.captures, encoding="utf-8") as fh:
            for line in fh:
                line=line.strip()
                if line:
                    calls.append(json.loads(line))
        by_provider: Dict[str,int] = {}
        by_model: Dict[str,int] = {}
        for c in calls:
            by_provider[c["provider"]] = by_provider.get(c["provider"],0)+1
            model = (c.get("request_body") or {}).get("model","unknown")
            by_model[model] = by_model.get(model,0)+1
        print(f"Total calls: {len(calls)}")
        for k,v in sorted(by_provider.items(),key=lambda x:-x[1]):
            print(f"  {k}: {v}")
        return 0
    print("Specify a subcommand: live, file, replay, stats")
    return 1


if __name__ == "__main__":
    sys.exit(main())
