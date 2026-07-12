"""Application settings.

Every tunable lives here so the engine's behaviour can be changed from a `.env`
file without touching code. The correlation knobs in particular are meant to be
tuned per environment: a noisy lab needs a higher score threshold than a quiet
production endpoint.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root: the directory that contains `backend/`, `rules/`, `frontend/`.
BASE_DIR = Path(__file__).resolve().parent.parent

# Created eagerly so SQLite has somewhere to write on first boot.
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    """Runtime configuration, overridable via environment variables or `.env`."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="HUNTER_")

    app_name: str = "Sysmon Hunter"
    host: str = "0.0.0.0"
    port: int = 8000

    # --- Storage ---
    rules_dir: Path = BASE_DIR / "rules"
    db_url: str = f"sqlite+aiosqlite:///{DATA_DIR / 'hunter.db'}"

    # --- Correlation ---
    # Detections that share a process-tree root within this window are grouped
    # into the same incident. Too wide and unrelated activity merges together;
    # too narrow and a slow-moving attack chain gets split apart.
    correlation_window_minutes: int = 10

    # Cumulative severity score at which an incident is promoted to "active".
    # See SEVERITY_SCORE in models/schemas.py for the per-severity weights.
    incident_score_threshold: int = 12

    # How long a process node stays in memory after it is last seen. Bounds the
    # in-memory process tree so a long-running server does not grow without end.
    process_ttl_minutes: int = 120


settings = Settings()