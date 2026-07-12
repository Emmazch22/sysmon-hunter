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

    # --- Beaconing ---
    # Periodicity detection over Sysmon EventID 3. See engine/beacon.py for why
    # these defaults are what they are; they are the knobs most worth tuning
    # against real traffic, because the difference between "finds Cobalt Strike"
    # and "flags every browser" lives entirely in this block.
    beacon_enabled: bool = True

    # Connections needed before a verdict. Five intervals is the fewest that can
    # distinguish rhythm from coincidence -- below that, two random connections
    # a minute apart look exactly like a beacon.
    beacon_min_connections: int = 6

    # Regularity floor, 0.0 to 1.0. At 0.75 a 60s beacon with Cobalt Strike's
    # default 37% jitter still scores ~0.85 and is caught, while genuinely
    # irregular traffic is not. Raise it if the console fills with noise; lower
    # it only if you are willing to read that noise.
    beacon_regularity_threshold: float = 0.75

    # Interval bounds, in seconds. Faster than the floor is a streaming
    # connection; slower than the ceiling is indistinguishable from a scheduled
    # task on timing alone.
    beacon_min_interval_seconds: float = 5.0
    beacon_max_interval_seconds: float = 3600.0

    beacon_window_minutes: int = 120
    beacon_cooldown_minutes: int = 30

    # Processes whose periodic traffic is expected. Every entry here is a place
    # an implant can hide by naming itself correctly, so keep the list short and
    # prefer raising the regularity threshold instead.
    beacon_excluded_images: list[str] = [
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "svchost.exe",
        "onedrive.exe",
        "teams.exe",
        "slack.exe",
    ]

    # --- Discovery burst ---
    # Detection of reconnaissance clusters over Sysmon EventID 1. See
    # engine/discovery.py. Counts *distinct* recon techniques per process tree,
    # so a script repeating one command never trips it -- only genuine variety
    # does.
    discovery_enabled: bool = True

    # Distinct recon techniques within the window that constitute a burst. Four
    # is where an administrator's occasional diagnostic use becomes methodical
    # host enumeration.
    discovery_min_distinct: int = 4
    discovery_window_minutes: int = 5
    discovery_cooldown_minutes: int = 15


settings = Settings()
