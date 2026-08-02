"""Aggregate statistics for the console's stats dashboard.

Everything here reads already-persisted rows (`db.stats_incident_rows` /
`db.stats_detection_rows`) and tallies them in Python. SQLite has no clean way
to "group by calendar day" over a timezone-aware timestamp, and the row counts
involved are a single collector's lifetime of incidents/detections -- small
enough that pulling the narrow column set and counting in Python is simpler
and just as fast as fighting the database into doing it, the same call this
project already made for `engine/noise.py`'s similarity scoring.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.engine.attack import attack_lookup
from backend.models import db

DEFAULT_DAYS = 14
MAX_DAYS = 90
TOP_N = 10


def _day_key(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).date().isoformat()


async def build_stats(days: int = DEFAULT_DAYS) -> dict[str, Any]:
    """Build the full stats payload for `GET /stats`.

    `days` bounds the incidents-per-day series only -- the severity, top-rule,
    and top-technique tallies always cover every incident/detection on
    record, since "which rule fires most" is a question about the whole
    corpus's behavior, not a recent window.
    """
    days = max(1, min(days, MAX_DAYS))

    incident_rows = await db.stats_incident_rows()
    detection_rows = await db.stats_detection_rows()

    # --- incidents per day, last `days` days, zero-filled ---
    today = datetime.now(timezone.utc).date()
    day_series = [(today - timedelta(days=offset)).isoformat() for offset in range(days - 1, -1, -1)]
    per_day: Counter[str] = Counter()
    for _severity, _status, _actionable, first_seen in incident_rows:
        per_day[_day_key(first_seen)] += 1
    incidents_per_day = [{"date": d, "count": per_day.get(d, 0)} for d in day_series]

    # --- severity distribution, across every incident ever recorded ---
    severity_order = ["info", "low", "medium", "high", "critical"]
    severity_counts: Counter[str] = Counter(sev for sev, _, _, _ in incident_rows)
    severity_distribution = [
        {"severity": s, "count": severity_counts.get(s, 0)} for s in severity_order
    ]

    # --- status breakdown ---
    status_counts: Counter[str] = Counter(st for _, st, _, _ in incident_rows)
    actionable_open = sum(
        1 for _, st, actionable, _ in incident_rows if st == "open" and actionable
    )

    # --- top rules by detection count ---
    rule_counts: Counter[str] = Counter()
    rule_titles: dict[str, str] = {}
    technique_counts: Counter[str] = Counter()
    for rule_id, title, attack, _matched_at in detection_rows:
        rule_counts[rule_id] += 1
        rule_titles.setdefault(rule_id, title)
        for technique_id in attack or []:
            technique_counts[technique_id] += 1

    top_rules = [
        {"rule_id": rule_id, "title": rule_titles.get(rule_id, rule_id), "count": count}
        for rule_id, count in rule_counts.most_common(TOP_N)
    ]

    top_techniques = []
    for technique_id, count in technique_counts.most_common(TOP_N):
        entry = attack_lookup.get(technique_id)
        top_techniques.append(
            {
                "technique_id": technique_id,
                "name": entry["name"] if entry else technique_id,
                "count": count,
            }
        )

    return {
        "range_days": days,
        "totals": {
            "incidents": len(incident_rows),
            "detections": len(detection_rows),
            "open": status_counts.get("open", 0),
            "actionable_open": actionable_open,
            "closed": status_counts.get("closed", 0),
            "false_positive": status_counts.get("false_positive", 0),
        },
        "incidents_per_day": incidents_per_day,
        "severity_distribution": severity_distribution,
        "top_rules": top_rules,
        "top_techniques": top_techniques,
    }
