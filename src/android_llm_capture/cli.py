"""Command-line interface for android-llm-capture."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List

from ._models import CapturedCall
from ._parser import parse_logcat_file, parse_logcat_line
from .capture import AndroidCapture


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="android-llm-capture",
        description="Capture and replay Android LLM API calls via ADB.",
    )
    sub = p.add_subparsers(dest="command")

    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None, help="ADB device serial.")
    live_p.add_argument("--tag", default="OkHttp", help="Logcat tag filter.")
    live_p.add_argument("--output", "-o", default="captures.jsonl")
    live_p.add_argument(
        "--timeout", type=int, default=0,
        help="Stop after N seconds (0 = run until Ctrl-C).",
    )

    file_p = sub.add_parser("file", help="Parse a saved logcat dump file.")
    file_p.add_argument("logcat", help="Path to logcat dump file.")
    file_p.add_argument("--output", "-o", default="captures.jsonl")
    file_p.add_argument("--json", action="store_true", help="Output a JSON array.")

    replay_p = sub.add_parser("replay", help="Replay a captured call against the real API.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id", help="call_id to replay, or 'last'.")
    replay_p.add_argument("--api-key", required=True, help="Provider API key.")

    stats_p = sub.add_parser("stats", help="Show statistics for a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    sub.add_parser("gui", help="Launch the graphical user interface.")

    return p.parse_args(argv)


def _load_jsonl(path: Path) -> List[CapturedCall]:
    calls: List[CapturedCall] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
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
            except (KeyError, json.JSONDecodeError) as exc:
                print(f"Warning: skipping malformed record at line {lineno}: {exc}",
                      file=sys.stderr)
    return calls


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.command == "gui":
        from .gui import run_gui
        run_gui()
        return 0

    if args.command == "live":
        session = AndroidCapture(device_serial=args.serial, tag_filter=args.tag)
        print(f"Starting live capture (tag={args.tag}). Press Ctrl-C to stop.")
        try:
            session.start()
            start = time.time()
            for call in session.stream():
                ts = time.strftime("%H:%M:%S")
                print(
                    f"[{ts}] [{call.provider}] {call.method} "
                    f"{call.url[:60]} status={call.response_status}"
                )
                if args.timeout and (time.time() - start) > args.timeout:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            session.stop()
        out = Path(args.output)
        session.export_jsonl(out)
        print(f"Exported {len(session.calls)} calls → {out}")
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
                fh.write(json.dumps(
                    [c.to_dict() for c in calls], indent=2, ensure_ascii=False
                ))
            else:
                for c in calls:
                    fh.write(c.to_jsonl() + "\n")
        print(f"Found {len(calls)} LLM calls → {out}")
        return 0

    if args.command == "replay":
        caps_path = Path(args.captures)
        if not caps_path.is_file():
            print(f"Error: {caps_path} not found", file=sys.stderr)
            return 1
        calls = _load_jsonl(caps_path)
        if not calls:
            print("No calls found.", file=sys.stderr)
            return 1
        if args.call_id == "last":
            target = calls[-1]
        else:
            target = next((c for c in calls if c.call_id == args.call_id), None)
        if not target:
            print(f"call_id {args.call_id!r} not found.", file=sys.stderr)
            return 1
        session = AndroidCapture()
        try:
            result = session.replay(target, api_key=args.api_key)
        except (ValueError, RuntimeError) as exc:
            print(f"Replay failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if args.command == "stats":
        caps_path = Path(args.captures)
        if not caps_path.is_file():
            print(f"Error: {caps_path} not found", file=sys.stderr)
            return 1
        try:
            calls = _load_jsonl(caps_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Error reading captures: {exc}", file=sys.stderr)
            return 1
        by_provider: dict = {}
        by_model: dict = {}
        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            model = c.model or "unknown"
            by_model[model] = by_model.get(model, 0) + 1
        print(f"Total calls: {len(calls)}")
        print("By provider:")
        for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("By model:")
        for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        return 0

    print("android-llm-capture: specify a subcommand (live, file, replay, stats, gui)")
    print("Use --help for usage.")
    return 1


_cli = main
