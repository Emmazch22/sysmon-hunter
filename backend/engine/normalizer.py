from datetime import datetime, timezone
from typing import Any

from backend.models.schemas import Event

# mapeo campo Sysmon -> campo normalizado
FIELD_MAP = {
    "Image": "image",
    "ParentImage": "parent_image",
    "CommandLine": "command_line",
    "ParentCommandLine": "parent_command_line",
    "ProcessGuid": "process_guid",
    "ParentProcessGuid": "parent_process_guid",
    "ProcessId": "process_id",
    "User": "user",
}


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def normalize(payload: dict[str, Any]) -> Event:
    """Acepta el JSON de Winlogbeat o un dict plano de prueba."""
    winlog = payload.get("winlog", payload)
    data = winlog.get("event_data", winlog.get("event_data", {})) or {}

    # tolerar payloads planos (utiles para tests y replay_evtx)
    if not data and "EventID" in payload:
        data = payload

    fields: dict[str, Any] = {}
    for sysmon_field, target in FIELD_MAP.items():
        if sysmon_field in data:
            fields[target] = data[sysmon_field]

    if "process_id" in fields:
        try:
            fields["process_id"] = int(fields["process_id"])
        except (TypeError, ValueError):
            fields.pop("process_id")

    event_id = int(
        winlog.get("event_id") or payload.get("EventID") or data.get("EventID") or 0
    )

    return Event(
        event_id=event_id,
        timestamp=_parse_ts(payload.get("@timestamp") or data.get("UtcTime")),
        host=(
            winlog.get("computer_name")
            or payload.get("host", {}).get("name", "unknown")
            if isinstance(payload.get("host"), dict)
            else "unknown"
        ),
        raw=data,
        **fields,
    )