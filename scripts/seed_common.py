"""Shared building blocks for the seed_*.py demo/fixture scripts.

seed_apt.py, seed_rw.py, and seed_full_coverage.py each tell a different
story, but all three build the same *shape* of event stream: a process tree
of Winlogbeat/Sysmon-formatted JSON, POSTed one at a time to a running
engine's /ingest endpoint. Each one had grown its own copy of the same three
helpers (at(), proc(), raw_event()) and the same posting loop in main(),
drifting slightly apart each time a bug got fixed in one copy and not the
others. This module is the one copy.

seed_demo.py is deliberately left out: it builds several unrelated hosts in
a single run via a flatter event() helper that never grew a proc()/raw_event()
split, so folding it in here would mean forcing a different script's shape
onto it rather than removing real duplication.

Import as a sibling module (`from seed_common import ...`), the way these
scripts are actually run -- `python scripts/seed_apt.py` puts `scripts/` on
sys.path, not the repo root, so this is not a package-relative import.
"""

from __future__ import annotations

import random
import sys
import time
from datetime import datetime, timedelta
from typing import Any

import httpx


class EventFactory:
    """Builds process-creation (EventID 1) and raw Sysmon events for one
    host/user/base-time, the fields a seed script's `events()` list-builder
    calls over and over.

    ParentImage is filled in automatically from an earlier proc() call for
    the same guid, unless the caller passes one explicitly. Several rules
    (SYS-001, SYS-005, SYS-036, SYS-039, SYS-079, SYS-088, SYS-089, SYS-090)
    key on ParentImage, so a script that forgot to pass it by hand used to
    end up with a demo that could not fire them -- this is the fix for that,
    generalized from seed_full_coverage.py's version, which was the one copy
    of the three that already had it.
    """

    def __init__(
        self,
        host: str,
        user: str,
        base: datetime,
        logon_id: str,
        default_cwd: str,
    ) -> None:
        self.host = host
        self.user = user
        self.base = base
        self.logon_id = logon_id
        self.default_cwd = default_cwd
        self._image_by_guid: dict[str, str] = {}

    def at(self, offset: float) -> str:
        """ISO timestamp `offset` seconds after this factory's base time."""
        return (self.base + timedelta(seconds=offset)).isoformat()

    def proc(
        self,
        offset: float,
        guid: str,
        parent_guid: str,
        image: str,
        cmdline: str,
        **extra: Any,
    ) -> dict:
        """A process-creation event (EventID 1) with full forensic fields."""
        self._image_by_guid[guid] = image
        data = {
            "Image": image,
            "ProcessGuid": guid,
            "ParentProcessGuid": parent_guid,
            "CommandLine": cmdline,
            "User": extra.pop("user", self.user),
            "UtcTime": self.at(offset),
            "IntegrityLevel": extra.pop("integrity", "Medium"),
            "ProcessId": str(extra.pop("pid", random.randint(2000, 9000))),
            "ParentProcessId": str(extra.pop("ppid", random.randint(2000, 9000))),
            "LogonId": self.logon_id,
            "TerminalSessionId": "2",
            "CurrentDirectory": extra.pop("cwd", self.default_cwd),
        }
        parent_image = extra.pop("parent_image", None) or self._image_by_guid.get(
            parent_guid
        )
        if parent_image:
            data["ParentImage"] = parent_image
        if "hashes" in extra:
            data["Hashes"] = extra.pop("hashes")
        if "parent_cmdline" in extra:
            data["ParentCommandLine"] = extra.pop("parent_cmdline")
        data.update(extra)
        return {
            "winlog": {"event_id": 1, "computer_name": self.host, "event_data": data},
            "@timestamp": self.at(offset),
        }

    def raw_event(self, eid: int, offset: float, **data: Any) -> dict:
        """A non-process-creation event. No ProcessGuid unless the caller
        passes one -- some Sysmon event types (WMI, driver load) legitimately
        carry none, and faking one would misrepresent what real telemetry
        looks like."""
        data["UtcTime"] = self.at(offset)
        return {
            "winlog": {"event_id": eid, "computer_name": self.host, "event_data": data},
            "@timestamp": self.at(offset),
        }


def post_events(
    events: list[dict], url: str, delay: float
) -> tuple[dict[str, int], set[str]]:
    """POST every event in order, printing each detection as it fires.

    Returns (rule_id -> fire count, distinct incident ids seen). Callers
    layer their own summary on top -- a coverage check against an expected
    rule set, a "did this stay one incident" assertion, or nothing at all --
    rather than this shared loop trying to guess what each script cares about.
    """
    fired: dict[str, int] = {}
    incident_ids: set[str] = set()
    try:
        with httpx.Client(timeout=10.0) as client:
            for i, evt in enumerate(events, 1):
                try:
                    result = client.post(url, json=evt).json()
                except httpx.HTTPError as exc:
                    print(f"  ! event {i}: {exc}", file=sys.stderr)
                    continue
                for d in result.get("detections", []):
                    fired[d["rule_id"]] = fired.get(d["rule_id"], 0) + 1
                    print(
                        f"  [{d['severity'].upper():8}] {d['rule_id']:8} {d['title']}"
                    )
                for inc in result.get("incidents", []):
                    incident_ids.add(inc["id"])
                if delay:
                    time.sleep(delay)
    except httpx.ConnectError:
        sys.exit(f"\nCannot reach {url}. Is the engine running?")
    return fired, incident_ids
