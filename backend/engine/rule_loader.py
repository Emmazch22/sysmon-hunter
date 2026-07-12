"""Rule loading and indexing.

Rules are content, not code: they live in `rules/` as YAML and are reloadable
without a restart. The store indexes them by EventID because the alternative --
evaluating every rule against every event -- gets expensive fast. At a few
hundred rules and a busy endpoint, that difference is the whole latency budget.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

import yaml
from pydantic import ValidationError

from backend.models.schemas import Rule

log = logging.getLogger(__name__)


class RuleStore:
    """Holds the active rule set, indexed by the EventID each rule applies to."""

    def __init__(self) -> None:
        self._by_event_id: dict[int, list[Rule]] = defaultdict(list)
        self._all: list[Rule] = []
        self._errors: list[str] = []

    def load(self, rules_dir: Path) -> int:
        """Load every .yml/.yaml under `rules_dir`, recursively.

        A malformed rule is logged and skipped, never fatal. One bad file must
        not take the whole detection engine offline -- that would turn a typo
        into an outage, and an outage into blind spots.

        Returns the number of rules successfully loaded.
        """
        self._by_event_id.clear()
        self._all.clear()
        self._errors.clear()

        paths = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))

        for path in paths:
            try:
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                self._record_error(path, f"invalid YAML: {exc}")
                continue

            if not document:
                continue  # Empty file, e.g. a placeholder. Not an error.

            try:
                rule = Rule(**document)
            except ValidationError as exc:
                self._record_error(path, f"schema violation: {exc.error_count()} issue(s)")
                continue

            if not rule.enabled:
                log.debug("Rule %s is disabled, skipping", rule.id)
                continue

            self._by_event_id[rule.event_id].append(rule)
            self._all.append(rule)

        log.info(
            "Loaded %d rules across %d event types (%d rejected)",
            len(self._all),
            len(self._by_event_id),
            len(self._errors),
        )
        return len(self._all)

    def _record_error(self, path: Path, reason: str) -> None:
        message = f"{path.name}: {reason}"
        self._errors.append(message)
        log.error("Rejected rule %s", message)

    def for_event(self, event_id: int) -> list[Rule]:
        """Rules that apply to this EventID. Empty list if none do."""
        return self._by_event_id.get(event_id, [])

    @property
    def all(self) -> list[Rule]:
        """Every active rule."""
        return list(self._all)

    @property
    def errors(self) -> list[str]:
        """Rules rejected during the last load. Surfaced on /health so a broken
        rule is visible rather than silently absent."""
        return list(self._errors)

    @property
    def coverage(self) -> dict[int, int]:
        """Rule count per EventID. Useful for spotting telemetry we collect but
        have written no detections for."""
        return {event_id: len(rules) for event_id, rules in self._by_event_id.items()}


# Module-level singleton. The engine has exactly one rule set at a time.
rule_store = RuleStore()