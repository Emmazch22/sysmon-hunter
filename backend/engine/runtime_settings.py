"""Runtime-editable settings.

Everything in `config.py` is read once from the environment at startup and
frozen for the process's life -- that is the right default for most tunables,
which an operator sets once and rarely revisits. A small number of settings
need to change without a restart, reachable live from the console instead of
a `.env` file: the behavior-baseline toggle is the first.

This module is the bridge: `load()` reads the database (falling back to the
`config.py` default the first time a setting has never been written), and the
setter writes through to the database and updates the in-memory value in the
same call, so the very next event sees the change -- no polling, no restart.
"""

from __future__ import annotations

import logging

from backend.config import settings
from backend.models import db

log = logging.getLogger(__name__)

_BEHAVIOR_BASELINE_KEY = "behavior_baseline_enabled"


class RuntimeSettings:
    """In-memory mirror of the `settings` table, checked on the hot path."""

    def __init__(self) -> None:
        # Mirrors config.py's default until load() reads the database, so a
        # settings check before startup finishes still returns something sane.
        self.behavior_baseline_enabled: bool = settings.behavior_baseline_enabled

    async def load(self) -> None:
        """Read every runtime setting from the database. Called once at
        startup, after the database is confirmed migrated."""
        stored = await db.get_setting(
            _BEHAVIOR_BASELINE_KEY,
            default="true" if settings.behavior_baseline_enabled else "false",
        )
        self.behavior_baseline_enabled = stored == "true"

    async def set_behavior_baseline_enabled(self, value: bool) -> None:
        """Flip the behavior-baseline detector on or off, effective
        immediately and persisted across restarts."""
        await db.set_setting(_BEHAVIOR_BASELINE_KEY, "true" if value else "false")
        self.behavior_baseline_enabled = value
        log.info("Behavior baseline detector %s", "enabled" if value else "disabled")

    def as_dict(self) -> dict[str, bool]:
        """Everything a settings endpoint needs to report. A dict, not a
        model, so a new runtime setting is one more key here -- no schema to
        update."""
        return {"behavior_baseline_enabled": self.behavior_baseline_enabled}


# Module-level singleton, loaded once at startup (see main.py's lifespan).
runtime_settings = RuntimeSettings()
