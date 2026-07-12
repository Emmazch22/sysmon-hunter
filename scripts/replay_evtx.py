#!/usr/bin/env python3
"""Replay recorded telemetry into a running engine.

The development loop this exists to enable: write a rule, replay a known-bad
EVTX, see whether it fires. No VM, no Sysmon, no waiting -- which means a rule
can be iterated on in seconds instead of minutes, and the same corpus can be
re-run against every future rule to catch regressions.

Sources:

* .evtx  -- a Windows event log, e.g. one exported from the lab VM, or a sample
            from the EVTX-ATTACK-SAMPLES corpus (each file is one technique).
* .jsonl -- one JSON event per line. What `--dump` writes, and what belongs in
            `backend/tests/fixtures/` as a committed regression corpus.

Usage:
    python scripts/replay_evtx.py --file samples/sysmon.evtx
    python scripts/replay_evtx.py --file samples/lateral_movement.evtx --speed 4
    python scripts/replay_evtx.py --file samples/sysmon.evtx --dump fixtures/lm.jsonl
    python scripts/replay_evtx.py --file fixtures/lm.jsonl --only 1,3,10
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import httpx

# Sysmon's channel name. Anything else in the file (Security, System) is skipped
# unless --all is passed: a Security 4688 has different field names and would be
# silently mis-normalized rather than loudly rejected.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

DEFAULT_URL = "http://localhost:8000/ingest"


def _unwrap(node: Any) -> Any:
    """Flatten the artefacts of XML-to-JSON conversion.

    EVTX parsers turn `<Data Name="Image">C:\\x.exe</Data>` into
    `{"Image": {"#text": "C:\\x.exe"}}`. The engine wants the value, not the
    wrapper, so pull `#text` up wherever it appears.
    """
    if isinstance(node, dict):
        if "#text" in node and len(node) == 1:
            return node["#text"]
        return {key: _unwrap(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_unwrap(item) for item in node]
    return node


def read_evtx(path: Path) -> Iterator[dict[str, Any]]:
    """Yield each record of an .evtx file as a flat Sysmon-style dict."""
    try:
        from evtx import PyEvtxParser
    except ImportError:
        sys.exit(
            "Reading .evtx requires the `evtx` package:\n"
            "    python -m pip install evtx\n"
            "(Or replay a .jsonl fixture instead, which needs no parser.)"
        )

    parser = PyEvtxParser(str(path))

    for record in parser.records_json():
        try:
            document = json.loads(record["data"])
        except (json.JSONDecodeError, KeyError):
            continue  # A corrupt record is skipped, never fatal.

        event = document.get("Event", {})
        system = _unwrap(event.get("System", {}))
        event_data = _unwrap(event.get("EventData", {})) or {}

        if not isinstance(event_data, dict):
            continue

        channel = system.get("Channel", "")
        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("#text")

        yield {
            "channel": channel,
            "winlog": {
                "event_id": int(event_id or 0),
                "computer_name": system.get("Computer", "unknown"),
                "event_data": event_data,
            },
            "@timestamp": system.get("TimeCreated", {}).get("#attributes", {}).get(
                "SystemTime"
            )
            if isinstance(system.get("TimeCreated"), dict)
            else None,
        }


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield each line of a .jsonl fixture as an event."""
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"  ! line {line_number}: {exc}", file=sys.stderr)


def load(path: Path) -> Iterator[dict[str, Any]]:
    """Dispatch on file extension."""
    if path.suffix.lower() == ".evtx":
        return read_evtx(path)
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return read_jsonl(path)
    sys.exit(f"Unsupported file type: {path.suffix}. Expected .evtx or .jsonl")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay EVTX or JSONL telemetry into a running Sysmon Hunter."
    )
    parser.add_argument("--file", required=True, type=Path, help="Path to .evtx or .jsonl")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"Ingest endpoint (default: {DEFAULT_URL})")
    parser.add_argument(
        "--speed",
        type=float,
        default=0.0,
        help="Events per second. 0 (default) sends as fast as the engine accepts, "
        "which is what you want when iterating on a rule. A low value is useful "
        "when watching the console fill up during a demo.",
    )
    parser.add_argument(
        "--only",
        help="Comma-separated EventIDs to send, e.g. 1,3,10. Everything else is skipped.",
    )
    parser.add_argument(
        "--all-channels",
        action="store_true",
        help="Do not filter to the Sysmon channel. Other channels use different "
        "field names and will mostly fail to match anything.",
    )
    parser.add_argument(
        "--dump",
        type=Path,
        help="Write the parsed events to a .jsonl file instead of sending them. "
        "Use this to turn an EVTX into a committed test fixture.",
    )
    parser.add_argument("--limit", type=int, help="Stop after N events.")
    args = parser.parse_args()

    if not args.file.exists():
        sys.exit(f"No such file: {args.file}")

    wanted: set[int] | None = None
    if args.only:
        wanted = {int(value.strip()) for value in args.only.split(",")}

    sink = args.dump.open("w", encoding="utf-8") if args.dump else None
    client = None if sink else httpx.Client(timeout=10.0)

    sent = skipped = failed = 0
    fired: Counter[str] = Counter()
    incidents: set[str] = set()
    delay = 1.0 / args.speed if args.speed > 0 else 0.0

    print(f"Replaying {args.file.name}" + (f" -> {args.dump}" if sink else f" -> {args.url}"))

    try:
        for event in load(args.file):
            channel = event.pop("channel", SYSMON_CHANNEL)
            if not args.all_channels and channel and channel != SYSMON_CHANNEL:
                skipped += 1
                continue

            event_id = event.get("winlog", {}).get("event_id", 0)
            if wanted is not None and event_id not in wanted:
                skipped += 1
                continue

            if sink:
                sink.write(json.dumps(event) + "\n")
                sent += 1
            else:
                try:
                    response = client.post(args.url, json=event)
                    response.raise_for_status()
                    result = response.json()
                except httpx.HTTPError as exc:
                    failed += 1
                    print(f"  ! {exc}", file=sys.stderr)
                    continue

                sent += 1
                for detection in result.get("detections", []):
                    fired[detection["rule_id"]] += 1
                    print(
                        f"  [{detection['severity'].upper():8}] {detection['rule_id']}  "
                        f"{detection['title']}"
                    )
                for incident in result.get("incidents", []):
                    incidents.add(incident["id"])

                if delay:
                    time.sleep(delay)

            if args.limit and sent >= args.limit:
                break

    except KeyboardInterrupt:
        print("\nInterrupted.")
    except httpx.ConnectError:
        sys.exit(f"\nCannot reach {args.url}. Is the engine running?")
    finally:
        if sink:
            sink.close()
        if client:
            client.close()

    print(f"\n{sent} sent, {skipped} skipped, {failed} failed")

    if fired:
        print("\nRules fired:")
        for rule_id, count in fired.most_common():
            print(f"  {rule_id:10} x{count}")
        print(f"\n{len(incidents)} incident(s) raised. Open http://localhost:8000 to triage.")
    elif sent and not sink:
        # Worth calling out loudly: a replay that fires nothing usually means the
        # rule is wrong, not that the sample is clean.
        print("\nNothing fired. Either the corpus is benign, or the rules missed it.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())