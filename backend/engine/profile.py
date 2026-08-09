"""Incident behavior profiling.

Turns an incident's detections into a readable account of what the malware did,
ordered along the kill chain: "Gained execution through a phishing macro,
performed host reconnaissance across 4 techniques, stole credentials from LSASS,
established persistence via a Run key, and beaconed to C2 every ~43s."

This is the difference between "23 detections fired" and "here is what happened".
An analyst writing up an incident, or a report reader who is not going to expand
every detection, gets the story in a paragraph.

How it works: detections are grouped by the ATT&CK tactic each technique serves
(the *why* of an action), the tactics are ordered by where they fall in an
intrusion, and each present tactic becomes one phrase -- enriched with the
specific detail the detections carry (the beacon interval, the recon breadth,
the registry key). It reports what was observed; it does not speculate about
intent beyond what the telemetry shows.
"""

from __future__ import annotations

from typing import Any

# Technique -> tactic. The tactic is what an action is *for*, which is what makes
# a readable narrative: "stole credentials", not "opened a handle to lsass.exe".
TECHNIQUE_TACTIC: dict[str, str] = {
    "T1566": "initial-access",
    "T1566.001": "initial-access",
    "T1204": "execution",
    "T1204.002": "execution",
    "T1204.001": "execution",
    "T1204.004": "execution",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1027": "execution",
    "T1105": "command-and-control",
    "T1218": "defense-evasion",
    "T1218.011": "defense-evasion",
    "T1218.002": "defense-evasion",
    "T1036.005": "defense-evasion",
    "T1059.005": "execution",
    "T1059.007": "execution",
    "T1562.001": "defense-evasion",
    "T1685": "defense-evasion",
    "T1547.001": "persistence",
    "T1546.012": "persistence",
    "T1003.001": "credential-access",
    "T1552.001": "credential-access",
    "T1003": "credential-access",
    "T1087": "discovery",
    "T1082": "discovery",
    "T1016": "discovery",
    "T1033": "discovery",
    "T1069": "discovery",
    "T1018": "discovery",
    "T1057": "discovery",
    "T1049": "discovery",
    "T1046": "discovery",  # SCN-001 network scan detector
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1573": "command-and-control",
    "T1571": "command-and-control",
    "T1055": "defense-evasion",
    "T1490": "impact",
    # Added when the SYS-093..123 rule batches (scheduled tasks, hive dumps,
    # lateral movement, exfiltration tooling, and more) turned out to have
    # shipped with no entry here at all -- see TestRuleCorpusTechniquesResolve
    # in tests/test_profile.py, which now fails the build if this ever
    # happens again for a technique the rule corpus actually declares.
    "T1190": "initial-access",
    "T1047": "execution",
    "T1569.002": "execution",
    "T1070.001": "defense-evasion",
    "T1070.004": "defense-evasion",
    "T1127.001": "defense-evasion",
    "T1134": "defense-evasion",
    "T1140": "defense-evasion",
    "T1197": "defense-evasion",
    "T1202": "defense-evasion",
    "T1211": "defense-evasion",
    "T1216": "defense-evasion",
    "T1548.002": "defense-evasion",
    "T1562.004": "defense-evasion",
    "T1558.003": "credential-access",
    "T1482": "discovery",
    "T1021.001": "lateral-movement",
    "T1021.002": "lateral-movement",
    "T1021.006": "lateral-movement",
    "T1563.002": "lateral-movement",
    "T1550.002": "lateral-movement",
    "T1550.003": "lateral-movement",
    "T1053.005": "persistence",
    "T1098": "persistence",
    "T1136.001": "persistence",
    "T1505.003": "persistence",
    "T1543.003": "persistence",
    "T1546.003": "persistence",
    "T1546.015": "persistence",
    "T1560.001": "collection",
    "T1113": "collection",
    "T1115": "collection",
    "T1074": "collection",
    "T1119": "collection",
    "T1090.001": "command-and-control",
    "T1219": "command-and-control",
    "T1102": "command-and-control",
    "T1567.002": "exfiltration",
    "T1486": "impact",
    "T1489": "impact",
    "T1491.001": "impact",
    "T1485": "impact",
    "T1531": "impact",
    "T1484.001": "privilege-escalation",
    "T1484.002": "privilege-escalation",
    "T1611": "privilege-escalation",
    "T1552.004": "credential-access",
    "T1552.005": "credential-access",
    "T1021.003": "lateral-movement",
    # SYS-124..131.
    "T1568": "command-and-control",
    "T1070.006": "defense-evasion",
    "T1564.004": "defense-evasion",
    "T1006": "defense-evasion",
    # SYS-132..150.
    "T1218.008": "defense-evasion",
    "T1218.014": "defense-evasion",
    "T1555.003": "credential-access",
    "T1555": "credential-access",
    "T1083": "discovery",
    "T1518.001": "discovery",
    "T1048": "exfiltration",
    "T1558.004": "credential-access",
    # SYS-175..190.
    "T1546.008": "persistence",
    "T1547.004": "persistence",
    "T1547.005": "persistence",
    "T1547.014": "persistence",
    "T1136.002": "persistence",
    "T1562.002": "defense-evasion",
    "T1562.009": "defense-evasion",
    "T1036.007": "defense-evasion",
    "T1204.003": "execution",
    "T1003.004": "credential-access",
    "T1003.005": "credential-access",
    "T1558.001": "credential-access",
    "T1552.002": "credential-access",
    "T1552.006": "credential-access",
    "T1021.004": "lateral-movement",
    "T1090.003": "command-and-control",
    "T1560.002": "collection",
    # SYS-191..196.
    "T1562.006": "defense-evasion",
    "T1112": "defense-evasion",
    "T1564.001": "defense-evasion",
    # SYS-197..199.
    "T1574.001": "defense-evasion",
    "T1574.002": "defense-evasion",
    "T1553.004": "defense-evasion",
}

# The order tactics fall in an intrusion. The narrative follows this, not the
# order detections happened to fire, so it reads as a kill chain even when the
# telemetry arrived out of sequence.
TACTIC_ORDER = [
    "initial-access",
    "execution",
    "privilege-escalation",
    "defense-evasion",
    "discovery",
    "lateral-movement",
    "credential-access",
    "persistence",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def _tactic_for(technique: str) -> str | None:
    """Look up a technique's kill-chain phase, falling back to its parent
    technique when the exact sub-technique is not listed above.

    Mirrors `AttackLookup.get()` (engine/attack.py) and
    `models/schemas.py`'s `_tactic_for()`: without the fallback, a rule
    shipping a sub-technique ID not spelled out here (there will always be
    one eventually -- MITRE adds them faster than this table gets updated)
    silently contributes no phase at all, and an incident whose only
    technique is that sub-technique gets no behavior profile. See
    `schemas.py`'s note on why this table and that one are intentionally
    different groupings of the same techniques, not copies of each other.
    """
    tactic = TECHNIQUE_TACTIC.get(technique)
    if tactic is not None:
        return tactic
    if "." in technique:
        return TECHNIQUE_TACTIC.get(technique.split(".")[0])
    return None


def _phrase_for_tactic(
    tactic: str,
    detections: list[dict[str, Any]],
) -> str | None:
    """Build one narrative phrase for a tactic from its detections.

    Each branch pulls the specific detail that makes the phrase concrete rather
    than generic -- the actual beacon interval, the count of distinct recon
    techniques, the registry key touched. A phrase with a number in it is
    evidence; a phrase without one is a label.
    """
    rule_ids = {d["rule_id"] for d in detections}
    techniques = {t for d in detections for t in d.get("attack", [])}

    if tactic == "initial-access":
        # T1190 (exploiting a public-facing application) is not phishing --
        # saying so would misdescribe the incident's actual entry point, not
        # just generalize it.
        if "T1190" in techniques:
            return "gained initial access by exploiting a public-facing application"
        return "gained initial access through a phishing document"

    if tactic == "execution":
        if any(r == "SYS-002" or r == "SYS-009" for r in rule_ids):
            return "executed an obfuscated PowerShell payload in memory"
        if "SYS-035" in rule_ids:
            return "executed an encoded script via the Windows Script Host"
        if "T1204.003" in techniques:
            return "executed a payload mounted from a downloaded ISO or IMG disk image"
        return "executed a suspicious payload"

    if tactic == "privilege-escalation":
        if "T1611" in techniques:
            return "escaped a privileged container to reach the underlying host"
        if {"T1484.001", "T1484.002"} & techniques:
            return "escalated privileges by abusing Group Policy or a domain trust"
        return "escalated privileges"

    if tactic == "defense-evasion":
        details = []
        if "SYS-031" in rule_ids:
            details.append("disabled Windows Defender")
        if "SYS-008" in rule_ids:
            details.append("used rundll32 as a signed C2 host")
        if "SYS-003" in rule_ids:
            details.append("staged a payload with a living-off-the-land binary")
        if "SYS-007" in rule_ids:
            details.append("masqueraded as a system process")
        if "SYS-034" in rule_ids:
            details.append("ran a malicious .cpl disguised as a document")
        if "SYS-036" in rule_ids:
            details.append("used rundll32 to launch a script host")
        if "SYS-037" in rule_ids:
            details.append("executed a payload via rundll32 url.dll handlers")
        if "T1562.009" in techniques:
            details.append("rebooted into Safe Mode to bypass security tooling")
        if "T1562.002" in techniques:
            details.append("disabled Windows event logging")
        if "T1036.007" in techniques:
            details.append("masqueraded a payload behind a double file extension")
        return (
            "evaded defenses (" + ", ".join(details) + ")"
            if details
            else "took steps to evade defenses"
        )

    if tactic == "discovery":
        # Pull the recon breadth straight from the discovery detection's evidence.
        for d in detections:
            count = (d.get("evidence") or {}).get("distinct_techniques")
            if count:
                return (
                    f"performed host reconnaissance across {count} distinct techniques"
                )
        return "performed host reconnaissance"

    if tactic == "credential-access":
        if "SYS-038" in rule_ids:
            return "harvested IIS application-pool credentials via appcmd"
        if "T1558.001" in techniques:
            return "forged a Kerberos golden ticket to impersonate a privileged account"
        if {"T1003.004", "T1003.005"} & techniques:
            return "dumped LSA secrets or cached domain credentials from memory"
        if "T1552.006" in techniques:
            return "harvested cleartext credentials from Group Policy Preferences"
        if "T1552.002" in techniques:
            return "recovered a plaintext autologon password from the registry"
        return "accessed credential material from LSASS memory"

    if tactic == "persistence":
        if "SYS-030" in rule_ids:
            return "established persistence via a registry Run key"
        if "SYS-050" in rule_ids:
            return "established persistence via the Startup folder"
        if "T1053.005" in techniques:
            return "established persistence via a scheduled task"
        if "T1543.003" in techniques:
            return "established persistence via a new Windows service"
        if {"T1546.003", "T1546.015"} & techniques:
            return "established persistence via an event-triggered execution hook"
        if "T1546.008" in techniques:
            return "backdoored a Windows accessibility feature for SYSTEM access at logon"
        if {"T1547.004", "T1547.005", "T1547.014"} & techniques:
            return "established persistence via a Winlogon, LSA, or Active Setup registry hook"
        if "T1136.002" in techniques:
            return "created a new domain account for standing access"
        return "established persistence"

    if tactic == "lateral-movement":
        if "T1563.002" in techniques:
            return "hijacked an existing RDP session to move laterally"
        if "T1021.004" in techniques:
            return "moved laterally over SSH using a private key"
        return "moved laterally to another host on the network"

    if tactic == "collection":
        return "staged and archived data ahead of exfiltration"

    if tactic == "command-and-control":
        # The beacon detection carries the interval -- the single most useful
        # number in a C2 phrase.
        for d in detections:
            interval = (d.get("evidence") or {}).get("median_interval_seconds")
            if interval:
                return (
                    f"established C2, beaconing to a remote host every ~{interval:.0f}s"
                )
        if "SYS-060" in rule_ids:
            return "established C2 over a named pipe matching a known framework default"
        if "T1090.003" in techniques:
            return "routed C2 traffic through Tor or a multi-hop anonymizing proxy"
        return "communicated with a remote command-and-control host"

    if tactic == "exfiltration":
        return "exfiltrated data to an external service"

    if tactic == "impact":
        if "SYS-004" in rule_ids:
            return "inhibited recovery by deleting volume shadow copies (ransomware precursor)"
        return "carried out destructive actions on the host"

    return None


def build_profile(
    incident: dict[str, Any], detections: list[dict[str, Any]]
) -> dict[str, Any]:
    """Produce a behavior profile: an ordered list of phases and a summary line.

    Returns both a structured `phases` list (tactic + phrase + the techniques and
    rules behind it, so the UI can make each phase expandable) and a single
    `summary` sentence for the top of a report or an at-a-glance read.
    """
    # Group detections by the tactic their techniques serve.
    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for detection in detections:
        tactics_here = {_tactic_for(t) for t in detection.get("attack", [])}
        tactics_here.discard(None)
        for tactic in tactics_here:
            by_tactic.setdefault(tactic, []).append(detection)

    phases: list[dict[str, Any]] = []
    for tactic in TACTIC_ORDER:
        if tactic not in by_tactic:
            continue
        phrase = _phrase_for_tactic(tactic, by_tactic[tactic])
        if not phrase:
            continue
        techniques = sorted(
            {
                t
                for d in by_tactic[tactic]
                for t in d.get("attack", [])
                if TECHNIQUE_TACTIC.get(t) == tactic
            }
        )
        rules = sorted({d["rule_id"] for d in by_tactic[tactic]})
        phases.append(
            {
                "tactic": tactic.replace("-", " "),
                "phrase": phrase,
                "techniques": techniques,
                "rules": rules,
            }
        )

    summary = _summarize(incident, phases)
    return {"summary": summary, "phases": phases}


def _summarize(incident: dict[str, Any], phases: list[dict[str, Any]]) -> str:
    """Stitch the phase phrases into one sentence.

    Reads as: "On HOST, the activity <phrase>, <phrase>, and <phrase>." An empty
    incident gets an honest fallback rather than an invented story.
    """
    host = incident.get("host", "the host")

    if not phases:
        return f"Suspicious activity on {host} with no clearly profiled behavior."

    phrases = [p["phrase"] for p in phases]
    if len(phrases) == 1:
        body = phrases[0]
    else:
        body = ", ".join(phrases[:-1]) + f", and {phrases[-1]}"

    return f"On {host}, the activity {body}."
