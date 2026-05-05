"""Command-line interface for android-llm-capture."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

from .capture import CaptureSession
from .models import CapturedCall
from .parser import parse_logcat_file


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="android-llm-capture",
        description="Capture and replay LLM API calls from Android devices via ADB logcat.",
    )
    sub = p.add_subparsers(dest="command")

    # ── live ──────────────────────────────────────────────────────────
    live_p = sub.add_parser("live", help="Stream live logcat and capture LLM calls.")
    live_p.add_argument("--serial", default=None,
                        help="Android device serial (adb -s).")
    live_p.add_argument("--tag", default="OkHttp",
                        help="Logcat tag to filter (default: OkHttp).")
    live_p.add_argument("--output", "-o", default="captures.jsonl",
                        help="Output JSONL file (default: captures.jsonl).")
    live_p.add_argument("--timeout", type=int, default=0,
                        help="Stop after N seconds (0 = run until Ctrl-C).")

    # ── file ──────────────────────────────────────────────────────────
    file_p = sub.add_parser("file", help="Parse a saved logcat dump file.")
    file_p.add_argument("logcat", help="Path to the logcat dump file.")
    file_p.add_argument("--output", "-o", default="captures.jsonl",
                        help="Output file (default: captures.jsonl).")
    file_p.add_argument("--json", action="store_true",
                        help="Write a pretty-printed JSON array instead of JSONL.")

    # ── replay ────────────────────────────────────────────────────────
    replay_p = sub.add_parser("replay", help="Replay a captured call against the live API.")
    replay_p.add_argument("captures", help="JSONL captures file.")
    replay_p.add_argument("call_id",
                          help="call_id to replay, or the literal string 'last'.")
    replay_p.add_argument("--api-key", required=True,
                          help="Provider API key (injected as the appropriate auth header).")

    # ── stats ─────────────────────────────────────────────────────────
    stats_p = sub.add_parser("stats", help="Print statistics for a captures file.")
    stats_p.add_argument("captures", help="JSONL captures file.")

    # ── gui ───────────────────────────────────────────────────────────
    sub.add_parser("gui", help="Launch the graphical user interface.")

    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Helper: load JSONL captures
# ---------------------------------------------------------------------------

def _load_calls(path: Path) -> List[CapturedCall]:
    calls: List[CapturedCall] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                calls.append(CapturedCall.from_dict(json.loads(raw)))
            except (json.JSONDecodeError, KeyError) as exc:
                print(
                    f"Warning: skipping malformed record on line {lineno}: {exc}",
                    file=sys.stderr,
                )
    return calls


# ---------------------------------------------------------------------------
# Sub-command implementations
# ---------------------------------------------------------------------------

def _cmd_live(args: argparse.Namespace) -> int:
    session = CaptureSession(device_serial=args.serial, tag_filter=args.tag)
    print(f"Starting live capture (tag={args.tag!r}). Press Ctrl-C to stop.")
    try:
        session.start()
        deadline = time.monotonic() + args.timeout if args.timeout else None
        for call in session.stream():
            ts = time.strftime("%H:%M:%S", time.localtime(call.timestamp))
            print(
                f"[{ts}] [{call.provider}] {call.method} "
                f"{call.url[:60]!r} → {call.response_status}"
            )
            if deadline and time.monotonic() > deadline:
                print(f"Timeout ({args.timeout}s) reached.")
                break
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        session.stop()
    n = session.export_jsonl(Path(args.output))
    print(f"Exported {n} call(s) to {args.output!r}.")
    return 0


def _cmd_file(args: argparse.Namespace) -> int:
    path = Path(args.logcat)
    if not path.is_file():
        print(f"Error: {path} not found.", file=sys.stderr)
        return 1
    calls = parse_logcat_file(path)
    out = Path(args.output)
    with out.open("w", encoding="utf-8") as fh:
        if args.json:
            json.dump([c.to_dict() for c in calls], fh, indent=2, ensure_ascii=False)
        else:
            for c in calls:
                fh.write(c.to_jsonl() + "\n")
    print(f"Found {len(calls)} LLM call(s) → {out}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    caps_path = Path(args.captures)
    if not caps_path.is_file():
        print(f"Error: {caps_path} not found.", file=sys.stderr)
        return 1
    calls = _load_calls(caps_path)
    if not calls:
        print("No calls found in captures file.", file=sys.stderr)
        return 1
    if args.call_id == "last":
        target: Optional[CapturedCall] = calls[-1]
    else:
        target = next((c for c in calls if c.call_id == args.call_id), None)
    if target is None:
        print(f"call_id {args.call_id!r} not found.", file=sys.stderr)
        return 1
    session = CaptureSession()
    result = session.replay(target, api_key=args.api_key)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    path = Path(args.captures)
    if not path.is_file():
        print(f"Error: {path} not found.", file=sys.stderr)
        return 1
    raw_calls: List[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    raw_calls.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    by_provider: dict = {}
    by_model: dict = {}
    by_status: dict = {}
    for c in raw_calls:
        prov = c.get("provider", "unknown")
        by_provider[prov] = by_provider.get(prov, 0) + 1
        model = (c.get("request_body") or {}).get("model", "unknown")
        by_model[model] = by_model.get(model, 0) + 1
        status = str(c.get("response_status", "?"))
        by_status[status] = by_status.get(status, 0) + 1

    col = 22
    print(f"Total calls : {len(raw_calls)}")
    print("By provider :")
    for k, v in sorted(by_provider.items(), key=lambda x: -x[1]):
        print(f"  {k:<{col}} {v}")
    print("By model    :")
    for k, v in sorted(by_model.items(), key=lambda x: -x[1]):
        print(f"  {k:<{col}} {v}")
    print("By status   :")
    for k, v in sorted(by_status.items(), key=lambda x: -x[1]):
        print(f"  {k:<{col}} {v}")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.  Returns an exit code."""
    args = _parse_args(argv)

    if args.command == "live":
        return _cmd_live(args)
    if args.command == "file":
        return _cmd_file(args)
    if args.command == "replay":
        return _cmd_replay(args)
    if args.command == "stats":
        return _cmd_stats(args)
    if args.command == "gui":
        from .gui import launch_gui
        launch_gui()
        return 0

    print("Specify a subcommand: live, file, replay, stats, gui")
    print("Use --help for usage.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
