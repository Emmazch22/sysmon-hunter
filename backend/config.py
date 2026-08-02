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

    # --- Auth ---
    # Shared secret for the API, checked against the X-API-Key header (see
    # backend/api/auth.py). Empty by default so a fresh checkout keeps working
    # with zero setup -- the console is meant to run on a trusted network out
    # of the box. Set HUNTER_API_KEY once the server is reachable from
    # anywhere you would not want reading detections or POSTing to /ingest.
    api_key: str = ""

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

    # --- Noise heuristic ---
    # How similar (0.0-1.0, weighted Jaccard across rule IDs, ATT&CK
    # techniques, root process, and process chain) an open incident must be
    # to a past false positive before the console flags it. See
    # engine/noise.py for the weighting rationale. Lower this if the console
    # under-flags real recurring noise; raise it if analysts start ignoring
    # the badge because it fires on coincidental overlap.
    noise_similarity_threshold: float = 0.6

    # --- IOC enrichment ---
    # Both are optional. With neither set, enrichment still runs and simply
    # reports every provider as unavailable -- the feature degrades, it does not
    # break. Set via HUNTER_ABUSEIPDB_API_KEY / HUNTER_VIRUSTOTAL_API_KEY, or a
    # .env file. Never commit real keys.
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""

    # How long an indicator's reputation is cached. An hour is well within the
    # window where reputation is stable, and keeps a curious analyst from
    # spending the daily quota re-checking the same IP.
    enrichment_cache_ttl_seconds: int = 3600

    # --- Operations ---
    # One JSON object per log line instead of the human-readable text format,
    # for log aggregators (CloudWatch, Loki, the ELK stack) that expect
    # structured records rather than a format string to parse back apart.
    # Off by default: a fresh checkout run by hand from a terminal wants the
    # readable format, not JSON scrolling past.
    log_json: bool = False

    # Requests per second a single client (by source IP) may POST to
    # /ingest before getting a 429, refilled continuously (a token bucket,
    # not a fixed window). 0 disables the limiter entirely -- the default,
    # since a single trusted collector on an internal network has no
    # obvious reason to be throttled by the server it is feeding. Set this
    # once /ingest is reachable from anywhere a misbehaving or malicious
    # sender could otherwise flood it.
    ingest_rate_limit_per_second: float = 0
    # Burst allowance above the steady-state rate -- lets a collector that
    # was briefly offline catch up on a backlog without being throttled the
    # moment it reconnects.
    ingest_rate_limit_burst: float = 50


settings = Settings()
