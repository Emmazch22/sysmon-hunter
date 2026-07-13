"""Incident and detection search.

Gives an analyst one box to find things in. Two modes in one query, mixed
freely:

    mimikatz                      free text: match anywhere
    host:FIN-WS-07                a field filter
    powershell severity:critical  both at once

Free text matches across everything an analyst might remember about an
incident -- a process name, a fragment of a command line, a hash, a rule id, the
title. Field filters (host:, severity:, technique:, rule:, user:) narrow
precisely. An incident matches if any of its detections match, so searching a
command-line fragment surfaces the whole incident it belongs to, not an orphaned
detection.

The parser is deliberately small and predictable. A SOC analyst under pressure
needs a search box whose behaviour they can guess, not a query language they have
to learn -- so `field:value` filters and everything-else-is-text is the whole
grammar.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any

# Recognized field filters and the incident/detection attribute each maps to.
# Anything not in this set is treated as free text, so a stray colon in a command
# line does not silently become a broken filter.
FIELD_FILTERS = {
    "host",
    "severity",
    "technique",  # matches an ATT&CK id, exact or prefix
    "rule",  # matches a rule id
    "user",  # matches the forensic user field
    "actionable",  # true/false
}


@dataclass
class Query:
    """A parsed search query: field filters plus free-text terms."""

    text_terms: list[str] = field(default_factory=list)
    filters: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.text_terms and not self.filters


def parse_query(raw: str) -> Query:
    """Split a raw query string into field filters and free-text terms.

    Uses shell-style tokenizing so a quoted phrase stays together:
    `"encoded command"` is one term, not two. A malformed quote falls back to a
    plain split rather than erroring -- a search box must never reject input.
    """
    raw = (raw or "").strip()
    if not raw:
        return Query(raw=raw)

    try:
        # posix=False keeps Windows backslashes intact, so a path like
        # C:\Windows\Temp survives as one searchable token.
        tokens = shlex.split(raw, posix=False)
    except ValueError:
        tokens = raw.split()

    query = Query(raw=raw)
    for token in tokens:
        # posix=False leaves surrounding quotes on a quoted phrase; drop them.
        if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
            token = token[1:-1]
        if ":" in token:
            key, _, value = token.partition(":")
            key = key.lower()
            if key in FIELD_FILTERS and value:
                query.filters[key] = value.lower()
                continue
        # Not a recognized filter -> free text.
        query.text_terms.append(token.lower())

    return query


def _detection_haystack(detection: dict[str, Any]) -> str:
    """All the free-text-searchable content of one detection, lowercased.

    Everything an analyst might type to find this detection goes in here: the
    rule, the title, the processes, the command line, the hashes, the user. One
    string means one substring search rather than a dozen field checks.
    """
    forensics = detection.get("forensics") or {}
    parts = [
        detection.get("rule_id", ""),
        detection.get("title", ""),
        detection.get("image", "") or "",
        detection.get("parent_image", "") or "",
        detection.get("command_line", "") or "",
        detection.get("host", ""),
        forensics.get("user", ""),
        forensics.get("hashes", ""),
        forensics.get("destination_ip", ""),
        forensics.get("destination_hostname", ""),
        forensics.get("registry_key", ""),
        forensics.get("target_image", ""),
        " ".join(detection.get("attack", [])),
    ]
    return " ".join(str(p) for p in parts).lower()


def _detection_matches(detection: dict[str, Any], query: Query) -> bool:
    """Does one detection satisfy every part of the query?

    All terms and all filters must hold (AND). An analyst narrowing a search
    expects each word they add to *reduce* the results, not widen them.
    """
    haystack = _detection_haystack(detection)

    for term in query.text_terms:
        if term not in haystack:
            return False

    forensics = detection.get("forensics") or {}
    for key, value in query.filters.items():
        if key == "host":
            if value not in detection.get("host", "").lower():
                return False
        elif key == "severity":
            if detection.get("severity", "").lower() != value:
                return False
        elif key == "rule":
            if value not in detection.get("rule_id", "").lower():
                return False
        elif key == "technique":
            techniques = [t.lower() for t in detection.get("attack", [])]
            # Prefix match, so `technique:t1003` finds T1003.001 too.
            if not any(t.startswith(value) for t in techniques):
                return False
        elif key == "user":
            if value not in str(forensics.get("user", "")).lower():
                return False

    return True


def _incident_field_match(incident: dict[str, Any], query: Query) -> bool:
    """Check incident-level filters that do not need the detections.

    `severity:` and `actionable:` are properties of the incident as a whole, so
    they are checked here against the incident, letting an all-detection scan be
    skipped when the incident itself is already excluded.
    """
    if "severity" in query.filters:
        if incident.get("severity", "").lower() != query.filters["severity"]:
            return False
    if "actionable" in query.filters:
        want = query.filters["actionable"] in ("true", "yes", "1")
        if bool(incident.get("actionable")) != want:
            return False
    if "host" in query.filters:
        if query.filters["host"] not in incident.get("host", "").lower():
            return False
    return True


def _detection_level_filters(query: Query) -> bool:
    """True if the query has filters that only a detection can satisfy."""
    return bool({k for k in query.filters if k in {"rule", "technique", "user"}})


@dataclass
class SearchHit:
    """One incident that matched, with the detections that matched inside it."""

    incident: dict[str, Any]
    matched_detections: list[dict[str, Any]]
    match_count: int


def search_incidents(
    incidents: list[dict[str, Any]],
    detections_by_incident: dict[str, list[dict[str, Any]]],
    query: Query,
) -> list[SearchHit]:
    """Return incidents matching the query, each with its matching detections.

    An incident is a hit if it passes the incident-level filters AND at least one
    of its detections matches the full query. The matched detections travel with
    the hit so the UI can show *why* it matched -- highlighting the command line
    that contained the search term, rather than making the analyst hunt for it.
    """
    hits: list[SearchHit] = []

    for incident in incidents:
        if not _incident_field_match(incident, query):
            continue

        detections = detections_by_incident.get(incident["id"], [])

        # A severity/actionable/host-only query with no text or detection-level
        # filters matches the incident wholesale -- no need to find a detection.
        detection_level = query.text_terms or {
            k for k in query.filters if k in {"rule", "technique", "user"}
        }
        if not detection_level:
            hits.append(SearchHit(incident, detections, len(detections)))
            continue

        matched = [d for d in detections if _detection_matches(d, query)]

        # Free text also matches the incident's title and process chain, so a
        # process that appears in the tree (w3wp.exe, PSEXESVC.exe) but did not
        # itself fire a rule is still findable. Field filters still require a
        # detection, since they describe detection-level attributes.
        if not matched and query.text_terms and not _detection_level_filters(query):
            incident_text = (
                incident.get("title", "") + " " + " ".join(incident.get("chain", []))
            ).lower()
            if all(term in incident_text for term in query.text_terms):
                hits.append(SearchHit(incident, detections, 0))
                continue

        if matched:
            hits.append(SearchHit(incident, matched, len(matched)))

    # Most matches first: an incident where the term appears ten times is more
    # likely what the analyst wants than one where it appears once.
    hits.sort(key=lambda h: h.match_count, reverse=True)
    return hits
