# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Setup (Python 3.11+):

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m alembic upgrade head       # required before first run -- see Gotchas
```

Run the server:

```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
# Console:  http://localhost:8000
# API docs: http://localhost:8000/api/docs
```

Tests:

```bash
python -m pytest                                   # full suite
python -m pytest tests/test_beacon.py               # one file
python -m pytest tests/test_beacon.py::TestBeaconDetection::test_clean_periodic_beacon_is_caught -v   # one test
python -m pytest tests/test_rules.py -k SYS-041     # rules matching a pattern
```

No `@pytest.mark.asyncio` needed on async tests -- `pytest.ini` sets `asyncio_mode = auto`.

Populate demo data:

```bash
python scripts/seed_apt.py    # one deep multi-stage intrusion
python scripts/seed_demo.py   # varied incidents across the kill chain
python scripts/seed_rw.py     # a full ransomware chain
```

Replay a real Sysmon `.evtx` (e.g. from EVTX-ATTACK-SAMPLES):

```bash
pip install evtx
python scripts/replay_evtx.py --file samples/some_sample.evtx
```

Regenerate the PDF manual (writes `Sysmon_Hunter_Manual.pdf` to the **current working directory**, not `docs/` -- run from repo root, then move it into `docs/`):

```bash
python scripts/build_manual.py
mv Sysmon_Hunter_Manual.pdf docs/Sysmon_Hunter_Manual.pdf
```

Docker: `docker compose up --build` (self-migrates on start, health-checks `/health`).

## Architecture

Every event, from any source (`/ingest`, the EVTX replay script, or a test), takes one path through `backend/engine/pipeline.py`'s `Pipeline.process()`:

```
normalize -> ProcessTree.observe -> match rules + statistical detectors -> IncidentEngine.correlate -> persist (SQLite) -> broadcast (WebSocket)
```

The pipeline has no dependency on FastAPI or HTTP, which is what lets the same code run under `/ingest`, the replay script, and pytest with no server at all.

**Rule engine.** Detection rules are YAML under `rules/`, loaded recursively by `backend/engine/rule_loader.py` and indexed by `event_id` -- the subdirectory names (`process_creation/`, `registry/`, `network/`, etc.) are purely organizational and never consulted by the loader. `backend/engine/matcher.py` implements a small, hand-written Sigma-like matcher: a detection field spec is `field`, `field|operator`, or `field|operator|not`, operators are `equals` (default), `contains`, `startswith`, `endswith`, `re`, matching is case-insensitive, and `condition: all`/`any` controls AND/OR across fields. `Event.get(field)` (`backend/models/schemas.py`) checks normalized attributes first (`image`, `command_line`, `process_guid`, ...) and falls back to the raw Winlogbeat/Sysmon dict, so a rule can reference either a normalized field or an exotic raw one (e.g. `TargetObject`, `QueryName`) by name without the matcher caring which.

**Statistical detectors.** Two detectors run alongside the rule engine, not instead of it, each producing an ordinary `Detection` that flows through the same correlation/scoring/persistence path as a rule match: `BeaconDetector` (`backend/engine/beacon.py`, rule id prefix `BCN-`) finds periodic C2 over Sysmon EventID 3 using median/MAD rather than mean/stddev so jitter doesn't defeat it; `DiscoveryDetector` (`backend/engine/discovery.py`, prefix `DSC-`) flags a burst of *distinct* ATT&CK discovery techniques (not raw execution count) within one process tree. The `BCN-`/`DSC-` rule-id prefix convention is how the frontend (`detectionIcon()` in `frontend/static/console.js`) and the incident-titling logic (`_SIGNATURE_RULES` in `schemas.py`) tell a statistical finding from a YAML rule match.

**Correlation.** `backend/engine/correlator.py`'s `ProcessTree` keys everything on Sysmon's `ProcessGuid`, never PID -- Windows recycles PIDs aggressively, so a PID-keyed tree would graft an unrelated later process onto a malicious parent's identity. `IncidentEngine` groups detections that share a process-tree root within a correlation window into one `Incident`. Incident severity scoring is deliberately non-linear (`SEVERITY_SCORE` / `SCORE_BANDS` in `schemas.py`) so a single critical detection can outrank several mediums combined. Incident `title` and the kill-chain narrative (`backend/engine/profile.py`) are derived properties, computed fresh from the incident's current detections every time they're read, never stored.

**Persistence.** `backend/models/db.py`, SQLAlchemy 2.0 async + aiosqlite. Alembic (`migrations/`) is the sole owner of schema changes -- `init_db()` only inspects the database at startup and verifies the tables Alembic should have created actually exist; it never creates or alters anything itself. A missing migration fails startup immediately with an explicit instruction rather than failing later at the first query with a "no such column" error far from its cause.

**API layer.** `backend/api/` has one router module per concern (`ingest`, `detections`, `incidents`, `attack`, `enrich`, `report`, `search`, `notes`, `status`, `admin`, `ws`, `serializers`), all wired up in `backend/main.py`'s `lifespan()`, which also loads the rule store and the local ATT&CK STIX dataset (`backend/engine/attack.py`) at startup and starts a periodic sweep (`Pipeline.sweep()`) that closes idle incidents and prunes expired process-tree nodes.

**Frontend.** Plain HTML/CSS/vanilla JS under `frontend/`, no build step, served directly by FastAPI: `console.html` (incident queue + live feed), `incident.html` (full incident page), `tree.html` (full-screen pan/zoom explorer for a process tree or timeline). All three fetch the JSON API and share a WebSocket (`/ws`) for live pushes of new detections/incidents.

**Config.** `backend/config.py` uses `pydantic-settings` with `env_prefix="HUNTER_"` -- every environment variable must carry that prefix (e.g. `HUNTER_DB_URL`, not `DB_URL`).

## Gotchas

- `init_db()` raises `RuntimeError: Database is not migrated` if the schema is behind. This is intentional, not a bug -- run `python -m alembic upgrade head` and restart.
- Rule subdirectories under `rules/` are cosmetic; a rule's `event_id` field, not its file path, determines when it's evaluated.
- `README.md`'s version header, `backend/main.py`'s `FastAPI(version=...)`, and the `VERSION`/test-count strings in `scripts/build_manual.py` are kept in sync by hand -- there is no single source of truth to bump.
- Every shipped detection rule has a matching true-positive and true-negative case in `tests/test_rules.py`; this is a project convention, not enforced by any tooling.
- `tests/conftest.py`'s `tmp_db` fixture builds an isolated on-disk SQLite schema via `Base.metadata.create_all` (not Alembic), so a new ORM model in `db.py` is immediately usable in tests without a migration needing to be exercised in test setup.
