"""Key indicators.

An incident carries the answers to the questions an analyst asks first -- who
was compromised, what to block, what to clean up, did privileges escalate -- but
they are scattered one-per-detection. This consolidates them into a single
summary an analyst (or an IR lead reading the report) can act on without opening
every detection.

Everything here is derived from the detections that are already stored; nothing
new is collected.
"""

from __future__ import annotations

from typing import Any

# Integrity levels ordered low to high, so a rise across the incident can be
# detected -- Medium -> High is a privilege escalation worth calling out.
_INTEGRITY_ORDER = ["untrusted", "low", "medium", "high", "system"]


def build_indicators(detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Consolidate the incident's actionable indicators from its detections.

    Returns a dict of lists/values the UI and report render directly:
    users, C2 destinations, file hashes, registry persistence, and whether the
    integrity level rose during the incident.
    """
    users: list[str] = []
    destinations: list[dict[str, str]] = []
    hashes: list[dict[str, str]] = []
    registry_keys: list[str] = []
    integrity_seen: list[str] = []

    for det in detections:
        forensics = det.get("forensics") or {}

        user = forensics.get("user")
        if user and user not in users:
            users.append(user)

        ip = forensics.get("destination_ip")
        if ip:
            dest = {
                "ip": ip,
                "port": str(forensics.get("destination_port", "")),
                "hostname": forensics.get("destination_hostname", ""),
            }
            if dest not in destinations:
                destinations.append(dest)

        raw_hashes = forensics.get("hashes")
        if raw_hashes:
            # Pull the strongest hash (SHA256) plus the image it belongs to, so
            # the analyst has a clean IOC to pivot on.
            parsed = _parse_hashes(raw_hashes)
            sha256 = parsed.get("sha256")
            entry = {
                "image": _basename(det.get("image")),
                "sha256": sha256 or "",
                "all": raw_hashes,
            }
            if sha256 and not any(h["sha256"] == sha256 for h in hashes):
                hashes.append(entry)

        reg = forensics.get("registry_key")
        if reg and reg not in registry_keys:
            registry_keys.append(reg)

        integ = forensics.get("integrity_level")
        if integ:
            integrity_seen.append(integ.lower())

    # Privilege escalation: did the integrity level rise from its lowest to a
    # higher one during the incident?
    escalation = _detect_escalation(integrity_seen)

    return {
        "users": users,
        "destinations": destinations,
        "hashes": hashes,
        "registry_persistence": registry_keys,
        "privilege_escalation": escalation,
    }


def _detect_escalation(integrity_seen: list[str]) -> dict[str, str] | None:
    """Return {from, to} if integrity rose during the incident, else None."""
    ranks = [
        (_INTEGRITY_ORDER.index(i), i) for i in integrity_seen if i in _INTEGRITY_ORDER
    ]
    if len(ranks) < 2:
        return None
    lowest = min(ranks, key=lambda r: r[0])
    highest = max(ranks, key=lambda r: r[0])
    if highest[0] > lowest[0]:
        return {"from": lowest[1], "to": highest[1]}
    return None


def _parse_hashes(raw: str) -> dict[str, str]:
    """Parse Sysmon's 'SHA256=...,MD5=...' hash field into a dict."""
    out: dict[str, str] = {}
    for part in raw.split(","):
        if "=" in part:
            algo, digest = part.split("=", 1)
            out[algo.strip().lower()] = digest.strip()
    return out


def _basename(path: str | None) -> str:
    if not path:
        return "unknown"
    return path.replace("/", "\\").split("\\")[-1]
