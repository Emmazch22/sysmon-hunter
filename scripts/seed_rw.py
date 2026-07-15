#!/usr/bin/env python3
"""Seed one incident spanning a full ransomware kill chain, start to finish.

Where seed_apt.py stops at credential theft and exfil staging, this goes all
the way to impact: initial access through encryption, one continuous process
tree, one incident. Every major phase of a real ransomware playbook is
represented, including the techniques added most recently (WMI persistence,
Squiblydoo, a BYOVD driver load, a PsExec pivot) alongside the classics
(phishing macro, an encoded PowerShell cradle, Mimikatz, shadow-copy
deletion). Two detections -- the WMI consumer registration (EventID 20) and
the unsigned driver load (EventID 6) -- carry no ProcessGuid in real Sysmon
telemetry, so they correctly land as their own single-detection incidents
rather than joining this tree. That is not a seeding bug; it is what an
analyst would actually see.

The story, on HQ-FILES-03:

    explorer.exe
      └─ OUTLOOK.EXE                       phishing delivery
          └─ WINWORD.EXE                   malicious macro document
              └─ cmd.exe                   macro drops to a shell
                  └─ powershell.exe (cradle, encoded)
                      ├─ whoami / net / systeminfo / nltest   recon burst
                      ├─ reg.exe            Defender real-time protection off
                      ├─ regsvr32.exe       Squiblydoo scriptlet (local .sct)
                      ├─ certutil.exe       decodes a smuggled stager
                      ├─ reg.exe            Run-key persistence
                      ├─ mofcomp.exe        stages a WMI subscription
                      ├─ mimikatz.exe       credential theft (real hashes)
                      ├─ rundll32.exe        injected C2, named pipe, beacons out
                      ├─ psexec.exe          lateral pivot toward the DC
                      └─ svchost.exe (masquerading, runs from Temp)
                          ├─ vssadmin.exe    shadow copies deleted
                          ├─ wbadmin.exe     backup catalog deleted
                          ├─ bcdedit.exe     Windows recovery disabled
                          └─ (file writes)   mass rename to .locked + ransom note

    (unlinked to the tree above -- no ProcessGuid in real telemetry)
    WmiEventConsumer registered      persistence, survives reboot
    unsigned driver loaded           BYOVD, blinds EDR before impact

    python scripts/seed_rw.py
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

HOST = "HQ-FILES-03"
USER = "CORP\\d.reyes"
BASE = datetime.now(timezone.utc) - timedelta(minutes=15)


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
        "LogonId": "0x8f21ac",
        "TerminalSessionId": "2",
        "CurrentDirectory": extra.pop("cwd", r"C:\Users\d.reyes\Downloads"),
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
    """A non-process-creation event. No ProcessGuid unless the caller passes
    one -- some Sysmon event types (WMI, driver load) legitimately carry none,
    and faking one would misrepresent what real telemetry looks like."""
    data["UtcTime"] = at(offset)
    return {
        "winlog": {"event_id": eid, "computer_name": HOST, "event_data": data},
        "@timestamp": at(offset),
    }


# GUIDs for the tree
G = {
    "explorer": "{rw-explorer}",
    "outlook": "{rw-outlook}",
    "word": "{rw-word}",
    "cmd": "{rw-cmd}",
    "cradle": "{rw-cradle}",
    "whoami": "{rw-whoami}",
    "net": "{rw-net}",
    "systeminfo": "{rw-systeminfo}",
    "nltest": "{rw-nltest}",
    "reg_defender": "{rw-reg-defender}",
    "regsvr32": "{rw-regsvr32}",
    "certutil": "{rw-certutil}",
    "reg_run": "{rw-reg-run}",
    "mofcomp": "{rw-mofcomp}",
    "mimikatz": "{rw-mimikatz}",
    "rundll": "{rw-rundll}",
    "psexec": "{rw-psexec}",
    "payload": "{rw-payload}",
    "vssadmin": "{rw-vssadmin}",
    "wbadmin": "{rw-wbadmin}",
    "bcdedit": "{rw-bcdedit}",
}


def events() -> list[dict]:
    ev: list[dict] = []

    # --- Initial access (T1566.001): explorer -> Outlook -> Word ---
    ev.append(
        proc(0, G["explorer"], "{rw-boot}", r"C:\Windows\explorer.exe", "explorer.exe",
             pid=4108, ppid=884)
    )
    ev.append(
        proc(3, G["outlook"], G["explorer"],
             r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
             '"OUTLOOK.EXE"', pid=5220, ppid=4108)
    )
    ev.append(
        proc(8, G["word"], G["outlook"],
             r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
             r'"WINWORD.EXE" /n "C:\Users\d.reyes\Downloads\Q3_Invoice_Statement.docm"',
             pid=5960, ppid=5220,
             hashes="SHA256=4b2e8f1a6c9d3e0b7f5a2c8e1d4b7a0c,MD5=c3d4e5f6a7b8c9d0")
    )

    # --- Execution (T1059.001, T1204.002): macro drops a shell, then an
    # encoded PowerShell cradle (SYS-001, SYS-002, SYS-009) ---
    ev.append(
        proc(14, G["cmd"], G["word"], r"C:\Windows\System32\cmd.exe",
             r"cmd.exe /c powershell -w hidden -nop -enc "
             r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
             pid=6100, ppid=5960,
             parent_cmdline=r'"WINWORD.EXE" /n "Q3_Invoice_Statement.docm"')
    )
    ev.append(
        proc(17, G["cradle"], G["cmd"],
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             r"powershell -w hidden -nop -enc "
             r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8A",
             pid=6220, ppid=6100,
             hashes="SHA256=8a1c4e7b2f9d6a3c0e5b8f1a4c7d0e3b")
    )

    # --- Discovery (T1082/T1087/T1018/T1016): four distinct techniques under
    # the cradle -- DSC-001 fires on the fourth ---
    ev.append(proc(22, G["whoami"], G["cradle"], r"C:\Windows\System32\whoami.exe",
                    "whoami /all", pid=6340, ppid=6220))
    # "net user /domain" is account discovery (T1087) -- deliberately not "net
    # group domain admins", which discovery.py classifies as the same
    # technique (T1069) as nltest below, and would collapse two commands into
    # one distinct technique, one short of the four DSC-001 requires.
    ev.append(proc(26, G["net"], G["cradle"], r"C:\Windows\System32\net.exe",
                    "net user /domain", pid=6360, ppid=6220))
    ev.append(proc(30, G["systeminfo"], G["cradle"], r"C:\Windows\System32\systeminfo.exe",
                    "systeminfo", pid=6390, ppid=6220))
    ev.append(proc(34, G["nltest"], G["cradle"], r"C:\Windows\System32\nltest.exe",
                    "nltest /dclist:corp.local", pid=6410, ppid=6220))

    # --- Defense evasion, three ways ---
    # 1. Windows Defender real-time protection disabled (SYS-031).
    ev.append(proc(40, G["reg_defender"], G["cradle"], r"C:\Windows\System32\reg.exe",
                    r"reg add \"HKLM\Software\Policies\Microsoft\Windows Defender\" "
                    r"/v DisableAntiSpyware /t REG_DWORD /d 1 /f", pid=6440, ppid=6220))
    ev.append(raw_event(13, 41, Image=r"C:\Windows\System32\reg.exe",
                          ProcessGuid=G["reg_defender"],
                          TargetObject=r"HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
                          Details="DWORD (0x00000001)"))
    # 2. Squiblydoo: scrobj.dll runs a scriptlet staged locally, no URL in the
    # command line, so this is SYS-074 and deliberately not SYS-003 (SYS-074).
    ev.append(proc(46, G["regsvr32"], G["cradle"], r"C:\Windows\System32\regsvr32.exe",
                    r"regsvr32.exe /s /u /i:C:\Users\d.reyes\AppData\Local\Temp\stage2.sct scrobj.dll",
                    pid=6470, ppid=6220))
    # 3. certutil decodes a base64-smuggled stager (SYS-075).
    ev.append(proc(52, G["certutil"], G["cradle"], r"C:\Windows\System32\certutil.exe",
                    r"certutil.exe -decode C:\Users\d.reyes\AppData\Local\Temp\payload.b64 "
                    r"C:\Users\d.reyes\AppData\Local\Temp\payload.dll",
                    pid=6500, ppid=6220))

    # --- Persistence, two ways ---
    # 1. Registry Run key (SYS-030).
    ev.append(proc(58, G["reg_run"], G["cradle"], r"C:\Windows\System32\reg.exe",
                    r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run "
                    r"/v WindowsUpdateHelper /t REG_SZ "
                    r"/d C:\Users\d.reyes\AppData\Local\Temp\svchost.exe /f",
                    pid=6530, ppid=6220))
    ev.append(raw_event(13, 59, Image=r"C:\Windows\System32\reg.exe",
                          ProcessGuid=G["reg_run"],
                          TargetObject=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper",
                          Details=r"C:\Users\d.reyes\AppData\Local\Temp\svchost.exe"))
    # 2. WMI persistence: command-line staging (SYS-070) followed by the
    # subscription itself (SYS-071, no ProcessGuid -- its own incident).
    ev.append(proc(65, G["mofcomp"], G["cradle"], r"C:\Windows\System32\wbem\mofcomp.exe",
                    r"mofcomp.exe C:\Users\d.reyes\AppData\Local\Temp\persist.mof",
                    pid=6560, ppid=6220))
    ev.append(raw_event(20, 67, Name="WindowsUpdateWatcher", Type="CommandLineEventConsumer",
                          Destination=r"powershell.exe -w hidden -enc "
                          r"U3RhcnQtUHJvY2VzcyBDOlxVc2Vyc1xkLnJleWVzXHN2Y2hvc3QuZXhl"))

    # --- Credential access (T1003.001): Mimikatz, real digests so this
    # enriches to a confirmed-malicious verdict against VirusTotal live ---
    ev.append(proc(73, G["mimikatz"], G["cradle"],
                    r"C:\Users\d.reyes\AppData\Local\Temp\mimikatz.exe",
                    r'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
                    pid=6610, ppid=6220, integrity="High",
                    cwd=r"C:\Users\d.reyes\AppData\Local\Temp",
                    hashes="SHA1=e3b6ea8c46fa831cec6f235a5cf48b38a4ae8d69,"
                    "SHA256=61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1")
    )
    ev.append(raw_event(10, 75, SourceImage=r"C:\Users\d.reyes\AppData\Local\Temp\mimikatz.exe",
                          SourceProcessGuid=G["mimikatz"], ProcessGuid=G["mimikatz"],
                          ParentProcessGuid=G["cradle"], TargetImage=r"C:\Windows\System32\lsass.exe",
                          GrantedAccess="0x1410", User=USER))

    # --- Command and control: injected rundll32 (SYS-008), a named pipe
    # (SYS-060), and a beacon with realistic jitter (BCN-001) ---
    ev.append(proc(82, G["rundll"], G["cradle"], r"C:\Windows\System32\rundll32.exe",
                    "rundll32.exe", pid=6650, ppid=6220))
    ev.append(raw_event(17, 83, Image=r"C:\Windows\System32\rundll32.exe",
                          ProcessGuid=G["rundll"], PipeName=r"\msagent_9c"))
    random.seed(917)
    clock = 88.0
    for _ in range(9):
        ev.append(raw_event(3, clock, Image=r"C:\Windows\System32\rundll32.exe",
                              ProcessGuid=G["rundll"], DestinationIp="91.219.236.18",
                              DestinationPort="443",
                              DestinationHostname="update-cache.msft-cdn-relay.net"))
        clock += 38 * (1 - random.uniform(0, 0.33))

    # --- Lateral movement (T1569.002, T1021.002): this host pivots toward
    # the domain controller (SYS-073) ---
    ev.append(proc(130, G["psexec"], G["cradle"], r"C:\Tools\PsExec.exe",
                    r"PsExec.exe -accepteula \\HQ-DC-01 cmd.exe /c whoami",
                    pid=6700, ppid=6220))

    # --- BYOVD (T1211, T1562.001): an unsigned driver loads to blind EDR
    # right before impact -- no ProcessGuid, its own incident (SYS-077) ---
    ev.append(raw_event(6, 136, ImageLoaded=r"C:\Windows\Temp\gdrv.sys", Signed="false",
                          Hashes="SHA256=5c2b8e1a4f7d0c3b6e9a2c5f8b1e4a7d0c3b6e9a2c5f8b1e4a7d0c3b6e9a2c5f"))

    # --- Impact: the payload itself, masquerading as svchost.exe from a
    # user-writable path (SYS-007), then the point of no return ---
    ev.append(proc(142, G["payload"], G["cradle"],
                    r"C:\Users\d.reyes\AppData\Local\Temp\svchost.exe", "svchost.exe",
                    pid=6740, ppid=6220, integrity="High",
                    hashes="SHA256=d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8"))
    # Shadow copies, the backup catalog, and Windows recovery -- all three
    # match SYS-004, back to back, exactly the sequence that rule's own
    # description calls "a near-universal precursor to encryption".
    ev.append(proc(148, G["vssadmin"], G["payload"], r"C:\Windows\System32\vssadmin.exe",
                    "vssadmin delete shadows /all /quiet", pid=6780, ppid=6740, integrity="High"))
    ev.append(proc(150, G["wbadmin"], G["payload"], r"C:\Windows\System32\wbadmin.exe",
                    "wbadmin delete catalog -quiet", pid=6800, ppid=6740, integrity="High"))
    ev.append(proc(152, G["bcdedit"], G["payload"], r"C:\Windows\System32\bcdedit.exe",
                    "bcdedit /set {default} recoveryenabled no", pid=6820, ppid=6740,
                    integrity="High"))

    # Mass rename to .locked, across the directories a real crypto-locker
    # would prioritise. No single rule fires on this -- the engine has no
    # encryption-speed detector -- but it is exactly what an analyst would
    # see appended to the timeline once the encryptor starts, and it is what
    # actually makes an incident "ransomware" rather than "intrusion".
    targets = [
        r"C:\Users\d.reyes\Documents\Q3_Forecast.xlsx.locked",
        r"C:\Users\d.reyes\Documents\Board_Minutes.docx.locked",
        r"C:\Users\d.reyes\Desktop\Payroll_2026.xlsx.locked",
        r"C:\Shares\Finance\AP_Ledger.xlsx.locked",
        r"C:\Shares\Finance\Vendor_Contracts.pdf.locked",
        r"C:\Shares\HR\Employee_Records.xlsx.locked",
    ]
    for i, path in enumerate(targets):
        ev.append(raw_event(11, 156 + i * 2, Image=r"C:\Users\d.reyes\AppData\Local\Temp\svchost.exe",
                              ProcessGuid=G["payload"], TargetFilename=path))

    # The ransom note, dropped last.
    ev.append(raw_event(11, 170, Image=r"C:\Users\d.reyes\AppData\Local\Temp\svchost.exe",
                          ProcessGuid=G["payload"],
                          TargetFilename=r"C:\Users\d.reyes\Desktop\HOW_TO_RECOVER_FILES.txt"))

    return ev


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed one incident spanning a full ransomware kill chain."
    )
    parser.add_argument("--url", default="http://localhost:8000/ingest")
    parser.add_argument("--delay", type=float, default=0.12)
    args = parser.parse_args()

    all_events = events()
    print(f"Seeding ransomware kill chain on {HOST}: {len(all_events)} events\n")

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
                    print(f"  [{d['severity'].upper():8}] {d['rule_id']:8} {d['title']}")
                if args.delay:
                    time.sleep(args.delay)
    except httpx.ConnectError:
        sys.exit(f"\nCannot reach {args.url}. Is the engine running?")

    print("\nRules fired:")
    for rule_id, count in sorted(fired.items()):
        print(f"  {rule_id:10} x{count}")
    print(
        f"\nOpen http://localhost:8000 and expand the {HOST} incidents "
        "(the main chain, plus the two orphaned WMI/driver detections)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
