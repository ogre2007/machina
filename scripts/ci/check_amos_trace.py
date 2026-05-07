#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load_events(path: Path):
    events = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def has_event(events, *, plugin=None, call=None, path_contains=None):
    for event in events:
        if plugin is not None and event.get("plugin") != plugin:
            continue
        if call is not None and event.get("Call") != call:
            continue
        if path_contains is not None and path_contains not in event.get("Path", ""):
            continue
        return True
    return False


def require(condition, message):
    if not condition:
        print(f"Private-access trace check failed: {message}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_amos_trace.py <trace.jsonl>", file=sys.stderr)
        return 2

    trace_path = Path(sys.argv[1])
    events = load_events(trace_path)
    require(events, "no JSONL events were parsed from emulator output")

    require(
        has_event(
            events,
            plugin="filemon",
            call="open",
            path_contains="/Users/analyst/Library/Application Support/Binance/app-store.json",
        ),
        "sample did not attempt to open Binance wallet data",
    )
    require(
        has_event(
            events,
            plugin="filemon",
            call="read",
            path_contains=None,
        ),
        "sample did not perform any file reads",
    )
    require(
        has_event(
            events,
            plugin="filemon",
            call="open",
            path_contains="/Users/analyst/Library/Application Support/Firefox/Profiles/",
        ),
        "sample did not attempt to open Firefox profile data",
    )
    require(
        has_event(
            events,
            plugin="filemon",
            call="open",
            path_contains="/Users/analyst/.electrum/wallets/",
        ),
        "sample did not attempt to open Electrum wallet data",
    )
    require(
        has_event(
            events,
            plugin="filemon",
            call="open",
            path_contains="/Users/analyst/Library/Application Support/Coinomi/wallets/",
        ),
        "sample did not attempt to open Coinomi wallet data",
    )
    require(
        has_event(
            events,
            plugin="filemon",
            call="_lstat",
            path_contains="/Users/analyst/Library/Application Support/Google/Chrome/",
        ),
        "sample did not probe Chrome profile roots",
    )

    print("Private-access trace check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
