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
    "T1059": "execution",
    "T1059.001": "execution",
    "T1027": "execution",
    "T1105": "command-and-control",
    "T1218": "defense-evasion",
    "T1218.011": "defense-evasion",
    "T1036.005": "defense-evasion",
    "T1562.001": "defense-evasion",
    "T1685": "defense-evasion",
    "T1547.001": "persistence",
    "T1546.012": "persistence",
    "T1003.001": "credential-access",
    "T1087": "discovery",
    "T1082": "discovery",
    "T1016": "discovery",
    "T1033": "discovery",
    "T1069": "discovery",
    "T1018": "discovery",
    "T1057": "discovery",
    "T1049": "discovery",
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1573": "command-and-control",
    "T1571": "command-and-control",
    "T1055": "defense-evasion",
    "T1490": "impact",
}

# The order tactics fall in an intrusion. The narrative follows this, not the
# order detections happened to fire, so it reads as a kill chain even when the
# telemetry arrived out of sequence.
TACTIC_ORDER = [
    "initial-access",
    "execution",
    "defense-evasion",
    "discovery",
    "credential-access",
    "persistence",
    "command-and-control",
    "impact",
]


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

    if tactic == "initial-access":
        return "gained initial access through a phishing document"

    if tactic == "execution":
        if any(r == "SYS-002" or r == "SYS-009" for r in rule_ids):
            return "executed an obfuscated PowerShell payload in memory"
        return "executed a suspicious payload"

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
        return "accessed credential material from LSASS memory"

    if tactic == "persistence":
        if "SYS-030" in rule_ids:
            return "established persistence via a registry Run key"
        if "SYS-050" in rule_ids:
            return "established persistence via the Startup folder"
        return "established persistence"

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
        return "communicated with a remote command-and-control host"

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
        tactics_here = {TECHNIQUE_TACTIC.get(t) for t in detection.get("attack", [])}
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
