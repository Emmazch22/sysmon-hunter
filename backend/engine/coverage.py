"""ATT&CK coverage report and MITRE Navigator layer export.

Every other view in this project answers "what happened" -- this one answers
"what could we never have seen". A rule corpus that has grown for months by
reacting to real intrusions and EVTX samples accumulates coverage the way
sediment accumulates: wherever the current happened to flow, not according to
any plan. This module makes that shape visible, by counting how many rules
(YAML rules plus the two statistical detectors) raise each ATT&CK technique,
and exporting the result as a MITRE ATT&CK Navigator layer -- open it at
https://mitre-attack.github.io/attack-navigator/ and every technique is
colored by how well it is covered, red for zero rules through green for
several. That is a prioritized worklist for the next rule to write, not just
a report.

Two data sources, two honesty levels:

  * `attack_index.json` (scripts/fetch_attack.py) is the full Enterprise
    technique catalog -- every technique, regardless of whether this project
    covers it. With it, the report is a true gap analysis: a technique with
    zero rules still appears, colored red.
  * `attack_data.json` (backend/engine/attack.py) only contains techniques
    already referenced by a rule or detector, by design (see that module's
    docstring). Without the index, this module falls back to it, but the
    result is necessarily partial -- it can rank what is covered against
    itself, but it cannot show a technique nobody has ever written a rule
    for, because that technique was filtered out before this code ever runs.

A missing index file is a warning, not a crash, matching `engine/attack.py`'s
own precedent: better a partial report than a coverage endpoint that refuses
to start because an optional data file has not been generated yet.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from backend.config import BASE_DIR
from backend.engine.attack import attack_lookup
from backend.engine.beacon import BEACON_TECHNIQUES
from backend.engine.discovery import DISCOVERY_SIGNATURES
from backend.engine.rule_loader import rule_store

log = logging.getLogger(__name__)

ATTACK_INDEX_PATH = BASE_DIR / "backend" / "data" / "attack_index.json"

# Every technique ID the statistical detectors can raise, independent of the
# rule corpus. Read from each detector's own source of truth -- the beacon
# detector's fixed pair, and discovery's per-signature table (the table, not
# `discovery.DISCOVERY_TECHNIQUES`, since that constant is a legacy summary
# that has drifted behind the table it was meant to describe and no longer
# includes every technique the table actually matches) -- rather than
# hand-copying either list here a third time, which is exactly how the
# `DISCOVERY_TECHNIQUES` drift happened in the first place.
DETECTOR_TECHNIQUES: frozenset[str] = frozenset(BEACON_TECHNIQUES) | frozenset(
    technique_id for technique_id, _label, _pattern in DISCOVERY_SIGNATURES
)

# MITRE ATT&CK Navigator layer format, v4.5. `navigator` must be >= "4.9.0"
# per the spec; this is the minimum version known to render every field this
# module emits.
NAVIGATOR_VERSION = "4.9.0"
LAYER_VERSION = "4.5"

# Red (uncovered) through green (well covered) -- the same gradient MITRE's
# own example layers use, so a layer from this project looks native next to
# any other layer an analyst has open.
GRADIENT_COLORS = ["#ff6666", "#ffe766", "#8ec843"]


def _load_full_index(path: Path = ATTACK_INDEX_PATH) -> dict[str, dict[str, Any]]:
    """Load the full Enterprise technique catalog. Missing file is a warning,
    not a crash -- see module docstring."""
    if not path.exists():
        log.warning(
            "ATT&CK full index not found at %s -- run scripts/fetch_attack.py. "
            "Coverage report will only show techniques this project already "
            "references, not a full gap analysis.",
            path,
        )
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to load ATT&CK index: %s", exc)
        return {}


def rule_counts_by_technique() -> dict[str, int]:
    """How many rules (YAML rules plus statistical detectors) raise each
    ATT&CK technique. A technique this project cannot detect at all is
    simply absent from the returned dict -- the caller decides how to
    represent "zero", since that differs between the full gap view and the
    partial referenced-only view (see `build_report`)."""
    counts: dict[str, int] = {}
    for rule in rule_store.all:
        for technique_id in rule.attack:
            counts[technique_id] = counts.get(technique_id, 0) + 1
    for technique_id in DETECTOR_TECHNIQUES:
        counts[technique_id] = counts.get(technique_id, 0) + 1
    return counts


def build_report(*, index_path: Path = ATTACK_INDEX_PATH) -> dict[str, Any]:
    """The coverage report: every technique this project can detect, plus --
    when the full index is present -- every technique it cannot, so the
    uncovered techniques are as visible as the covered ones.

    `partial` tells the caller (and, via the Navigator layer's description,
    the analyst) which case they are looking at: `False` means every
    Enterprise technique is represented; `True` means only techniques this
    project already references are, because `attack_index.json` was not
    found.
    """
    counts = rule_counts_by_technique()
    full_index = _load_full_index(index_path)
    partial = not full_index

    techniques: list[dict[str, Any]] = []
    seen: set[str] = set()

    for technique_id, entry in full_index.items():
        techniques.append(
            {
                "id": technique_id,
                "name": entry.get("name", ""),
                "tactics": entry.get("tactics", []),
                "rule_count": counts.get(technique_id, 0),
            }
        )
        seen.add(technique_id)

    # A rule can reference a technique the index does not have an entry for
    # -- a brand-new sub-technique the index predates, or (in the partial
    # case) simply because there is no index at all. Surface it anyway
    # rather than silently dropping real coverage from the report.
    for technique_id, count in counts.items():
        if technique_id in seen:
            continue
        cached = attack_lookup.get(technique_id) or {}
        techniques.append(
            {
                "id": technique_id,
                "name": cached.get("name", ""),
                "tactics": cached.get("tactics", []),
                "rule_count": count,
            }
        )

    techniques.sort(key=lambda t: t["id"])
    covered = sum(1 for t in techniques if t["rule_count"] > 0)

    return {
        "partial": partial,
        "total_techniques": len(techniques),
        "covered_techniques": covered,
        "uncovered_techniques": len(techniques) - covered,
        "techniques": techniques,
    }


def build_navigator_layer(report: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Render a coverage report as a MITRE ATT&CK Navigator layer (v4.5).

    Score is the rule count itself, not a normalized 0-1 value -- an analyst
    scanning the layer benefits more from seeing "3 rules" than from a
    dimensionless fraction, and the gradient's `maxValue` still stretches to
    fit whatever the busiest technique's count turns out to be.
    """
    if report is None:
        report = build_report()

    max_count = max((t["rule_count"] for t in report["techniques"]), default=0)

    techniques = [
        {
            "techniqueID": t["id"],
            "score": t["rule_count"],
            "comment": (
                f"{t['rule_count']} rule(s)/detector(s)"
                if t["rule_count"]
                else "No rule coverage"
            ),
            "enabled": True,
        }
        for t in report["techniques"]
    ]

    description = (
        "Auto-generated by Sysmon Hunter from the active rule corpus and "
        "statistical detectors. Score is the number of rules/detectors that "
        "raise each technique; 0 (red) means no coverage."
    )
    if report["partial"]:
        description += (
            " PARTIAL VIEW: backend/data/attack_index.json was not found, "
            "so only techniques this project already references are shown "
            "-- run scripts/fetch_attack.py for a full gap analysis against "
            "every Enterprise technique."
        )

    return {
        "name": "Sysmon Hunter Rule Coverage",
        "versions": {"navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,  # descending by score -- gaps and hot-spots surface first
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": True,
            "aggregateFunction": "average",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": GRADIENT_COLORS,
            "minValue": 0,
            "maxValue": max_count if max_count else 1,
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
    }
