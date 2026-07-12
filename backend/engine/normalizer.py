"""Transport-to-domain translation.

Everything that knows what Winlogbeat's JSON looks like lives in this file. The
rest of the engine only ever sees an `Event`. When a second collector is added
later (raw EVTX replay, a Kafka consumer, an agent of our own), it plugs in here
and nothing downstream changes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.models.schemas import Event, utcnow

# Sysmon field name -> Event attribute. Only fields the engine reasons about are
# promoted; everything else stays reachable through Event.raw.
FIELD_MAP: dict[str, str] = {
    "Image": "image",
    "ParentImage": "parent_image",
    "CommandLine": "command_line",
    "ParentCommandLine": "parent_command_line",
    "ProcessGuid": "process_guid",
    "ParentProcessGuid": "parent_process_guid",
    "ProcessId": "process_id",
    "User": "user",
    # Sysmon EventID 8/10 describe a *target* process. Mapping it onto `image`
    # would be wrong -- the target is not the actor -- so these stay in raw and
    # rules address them by their Sysmon names (TargetImage, SourceImage).
}


def _parse_timestamp(value: Any) -> datetime:
    """Parse an event timestamp, defaulting to now if it is missing or malformed.

    Sysmon writes UtcTime as "2026-07-12 15:55:20.123"; Winlogbeat adds an ISO-8601
    "@timestamp". Both are accepted. A bad timestamp must never drop an event --
    losing telemetry is worse than mis-dating it by milliseconds.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, str):
        candidate = value.strip().replace("Z", "+00:00")
        # Sysmon's UtcTime is space-separated rather than ISO's "T".
        if " " in candidate and "T" not in candidate:
            candidate = candidate.replace(" ", "T", 1)
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return utcnow()


def _extract_host(payload: dict[str, Any], winlog: dict[str, Any]) -> str:
    """Find the hostname across the several places collectors put it."""
    host = payload.get("host")
    if isinstance(host, dict) and host.get("name"):
        return str(host["name"])
    if winlog.get("computer_name"):
        return str(winlog["computer_name"])
    if isinstance(host, str) and host:
        return host
    return "unknown"


def normalize(payload: dict[str, Any]) -> Event:
    """Translate an inbound JSON payload into an `Event`.

    Accepts three shapes, so the same endpoint serves the collector, the EVTX
    replay script and a hand-written curl during rule development:

    1. Winlogbeat:  {"winlog": {"event_id": 1, "event_data": {...}}}
    2. Nested:      {"event_id": 1, "event_data": {...}}
    3. Flat:        {"EventID": 1, "Image": "...", "ParentImage": "..."}
    """
    winlog = payload.get("winlog") or payload
    data: dict[str, Any] = winlog.get("event_data") or {}

    # Flat shape: the Sysmon fields sit at the top level with no envelope.
    if not data and any(key in payload for key in FIELD_MAP):
        data = payload

    fields: dict[str, Any] = {
        target: data[sysmon_field]
        for sysmon_field, target in FIELD_MAP.items()
        if data.get(sysmon_field) is not None
    }

    # ProcessId arrives as a string from some collectors. A non-numeric value is
    # dropped rather than raising: the PID is not load-bearing anywhere.
    if "process_id" in fields:
        try:
            fields["process_id"] = int(fields["process_id"])
        except (TypeError, ValueError):
            fields.pop("process_id")

    raw_event_id = (
        winlog.get("event_id")
        or payload.get("EventID")
        or data.get("EventID")
        or 0
    )
    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError):
        event_id = 0

    return Event(
        event_id=event_id,
        timestamp=_parse_timestamp(payload.get("@timestamp") or data.get("UtcTime")),
        host=_extract_host(payload, winlog),
        raw=data,
        **fields,
    )