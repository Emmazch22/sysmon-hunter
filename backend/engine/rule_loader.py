import logging
from collections import defaultdict
from pathlib import Path

import yaml

from backend.models.schemas import Rule

log = logging.getLogger(__name__)


class RuleStore:
    """Carga reglas YAML y las indexa por EventID."""

    def __init__(self) -> None:
        self._by_event_id: dict[int, list[Rule]] = defaultdict(list)
        self._all: list[Rule] = []

    def load(self, rules_dir: Path) -> int:
        self._by_event_id.clear()
        self._all.clear()

        for path in sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml")):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                if not raw:
                    continue
                rule = Rule(**raw)
                if not rule.enabled:
                    continue
                self._by_event_id[rule.event_id].append(rule)
                self._all.append(rule)
            except Exception as exc:
                log.error("Regla invalida %s: %s", path.name, exc)

        log.info("Cargadas %d reglas", len(self._all))
        return len(self._all)

    def for_event(self, event_id: int) -> list[Rule]:
        return self._by_event_id.get(event_id, [])

    @property
    def all(self) -> list[Rule]:
        return list(self._all)


rule_store = RuleStore()