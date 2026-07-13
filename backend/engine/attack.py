"""ATT&CK technique lookup.

Serves the technique descriptions the console shows when an analyst clicks a
technique chip. Data comes from a local JSON built by scripts/fetch_attack.py
from MITRE's official STIX dataset -- see that script for why the console does
not query MITRE directly.

The file is loaded once at import and held in memory. It is tens of kilobytes
and never changes at runtime, so there is nothing to gain from re-reading it per
request and a per-request disk read to lose.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from backend.config import BASE_DIR

log = logging.getLogger(__name__)

ATTACK_DATA_PATH = BASE_DIR / "backend" / "data" / "attack_data.json"


class AttackLookup:
    """In-memory ATT&CK technique lookup, keyed by technique ID."""

    def __init__(self) -> None:
        self._techniques: dict[str, dict[str, Any]] = {}

    def load(self, path: Path = ATTACK_DATA_PATH) -> int:
        """Load the technique data. Missing file is a warning, not a crash.

        If the file is absent the console simply shows no descriptions -- the
        rest of the app is unaffected. Better a missing tooltip than a backend
        that will not start because an optional data file was not generated.
        """
        if not path.exists():
            log.warning(
                "ATT&CK data not found at %s -- run scripts/fetch_attack.py. "
                "Technique descriptions will be unavailable.",
                path,
            )
            return 0

        try:
            self._techniques = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Failed to load ATT&CK data: %s", exc)
            return 0

        log.info("Loaded %d ATT&CK techniques", len(self._techniques))
        return len(self._techniques)

    def get(self, technique_id: str) -> Optional[dict[str, Any]]:
        """One technique by ID (exact match), or None.

        A sub-technique like T1059.001 falls back to its parent T1059 when the
        sub-technique itself is not in the set: the parent's description is still
        useful context, and it avoids a dead click on a chip we raised but did
        not ship data for.
        """
        technique = self._techniques.get(technique_id)
        if technique is not None:
            return technique

        if "." in technique_id:
            parent_id = technique_id.split(".")[0]
            parent = self._techniques.get(parent_id)
            if parent is not None:
                return {**parent, "note": f"Parent technique of {technique_id}"}

        return None

    @property
    def count(self) -> int:
        return len(self._techniques)


attack_lookup = AttackLookup()
