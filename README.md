# Sysmon Hunter

A real-time detection engine for Windows Sysmon telemetry. It ingests events
from an endpoint, matches them against ATT&CK-mapped rules, reconstructs the
process tree to correlate related detections into incidents, and detects C2
beaconing statistically — all streamed to a live analyst console.

This is a detection-engineering project: the interesting part is not that it
matches rules, but *what it does with a match*. A lone "PowerShell ran an
encoded command" is a lead. The same detection sitting under a `WINWORD.EXE`
root, next to an outbound connection on a fixed timer, is an incident an analyst
should look at now. Turning the first into the second is the whole point.

---

## What it does

- **Rule-based detection** — YAML rules with Sigma-compatible matching
  semantics, indexed by Sysmon EventID so only relevant rules run per event.
- **Process-tree correlation** — reconstructs parent/child ancestry from
  Sysmon's `ProcessGuid`, so detections that share a root become one incident
  with the full chain: `WINWORD.EXE → cmd.exe → powershell.exe`.
- **Statistical beacon detection** — finds periodic C2 callbacks that no
  single-event rule can see, and survives the jitter every modern C2 applies.
- **Non-linear incident scoring** — a single critical outweighs several
  mediums; incidents can outrank their worst individual rule.
- **Live console** — a dark SOC dashboard that leads with the incident triage
  queue and streams new detections over WebSocket.
- **Offline replay** — replay real `.evtx` files or JSONL fixtures into the
  engine, so rules can be developed and regression-tested without a VM.

---

## Pipeline

Every event, whatever produced it, takes one path:

```
                    Winlogbeat / EVTX replay / curl
                                 │
                                 ▼
                        POST /ingest  (thin: hands off, holds no logic)
                                 │
                                 ▼
            ┌─────────────────  Pipeline  ─────────────────┐
            │                                              │
            ▼                                              │
      normalize()          Winlogbeat JSON → Event.        │
            │              Transport knowledge stops here. │
            ▼                                              │
     ProcessTree.observe() Every event feeds the tree,     │
            │              not just suspicious ones — a     │
            │              malicious process's ancestors    │
            │              are all benign.                  │
            ▼                                              │
     ┌──────┴───────┐                                      │
     ▼              ▼                                      │
  evaluate()   BeaconDetector.observe()                    │
  rule match   statistical periodicity                     │
     │              │                                      │
     └──────┬───────┘                                      │
            ▼                                              │
   IncidentEngine.correlate()   group by process-tree      │
            │                    root within a time window │
            ▼                                              │
      persist (SQLite)  +  broadcast (WebSocket)           │
            │                                              │
            └──────────────────────────────────────────────┘
                                 │
                                 ▼
                         Analyst console
```

The pipeline is deliberately independent of HTTP. It runs identically under the
`/ingest` endpoint, the EVTX replay script, and pytest with no server at all —
which is what makes the whole thing testable.

---

## Design decisions

The choices below are the ones that separate this from a `grep` over event logs.
Each is enforced by a test named after it.

### Correlation keys on GUID, never PID

Windows recycles process IDs aggressively. A PID-keyed tree will graft a
malicious child onto whatever unrelated process happened to inherit its parent's
PID — inventing an attack chain that never existed. Sysmon's `ProcessGuid` is
unique across reboots and PID reuse, so the tree is keyed on `(host, guid)`.

The tree is also scoped per host: two machines beaconing to the same C2 are two
findings, and a GUID collision across hosts must never merge their trees.

### The tree observes everything, not just detections

If only rule-matching processes entered the tree, the ancestry chain would be
full of holes and `WINWORD.EXE` — which never triggers a rule — would never
appear as the root of a phishing chain. So every process-creation event is
recorded, and the chain is reconstructed from that complete picture.

### Incident scoring is non-linear

Severity weights are `info:1, low:3, medium:5, high:8, critical:14`. The jump to
critical is deliberate: one LSASS access matters more than three
suspicious-path executions. Incidents accumulate these scores and are banded
back into a severity, so **two HIGH detections (16) read as CRITICAL** — an
incident can be worse than any single rule that composes it. If it could not,
there would be no reason to score incidents at all.

Promotion to "needs triage" has three independent triggers: the score crosses a
threshold, *or* any critical detection lands, *or* three detections stack in one
tree. Volume in a single chain is itself a signal.

### Beaconing is statistical, not a rule

A rule matches one event; a beacon only exists across dozens. A single outbound
connection to port 443 is the most ordinary event on a Windows host — the signal
is the *rhythm*, and rhythm lives in the intervals between events.

Two choices make it work on real traffic:

- **Regularity, not equality.** Every modern C2 applies jitter — Cobalt
  Strike's default reduces a 60-second sleep by up to 37% at random. A detector
  demanding equal intervals finds nothing. This one scores regularity as
  `1 − (MAD / median)` and catches a 37%-jitter beacon at ~0.92.
- **Median and MAD, not mean and standard deviation.** A live session produces
  outliers constantly — the operator interacts, the host sleeps, a callback
  retries late. One 400-second gap in a 60-second beacon wrecks a
  standard-deviation score and loses the channel. The median barely notices.

Two false-positive filters, both surfaced by tests against real page-load and
browsing traffic, keep it quiet: a minimum observation span (a beacon persists;
a page-load burst is dense but brief) and a maximum interval ratio (no jittered
beacon swings across two orders of magnitude).

### Detections and incidents persist; the process tree does not

Detections are evidence and incidents are findings — both must still be there
tomorrow morning, so they go to SQLite. The process tree is a live working set
whose value decays in minutes, so it stays in memory and is pruned on a timer.

### One serializer, two paths

The console loads history from SQLite over REST and receives live updates over
WebSocket. Both emit the identical JSON shape from a single serializer, so a
rendered row cannot tell which path it arrived on — a class of "works on refresh,
breaks on live push" bug that simply cannot occur.

---

## Project layout

```
sysmon-hunter/
├── backend/
│   ├── main.py              FastAPI app, lifespan, background sweep loop
│   ├── config.py            all tunables (correlation window, beacon knobs…)
│   ├── api/
│   │   ├── ingest.py        POST /ingest — the one door for all telemetry
│   │   ├── detections.py    GET /detections
│   │   ├── incidents.py     GET /incidents, /incidents/{id}
│   │   ├── ws.py            WebSocket broadcast to the console
│   │   └── serializers.py   single source of truth for wire formats
│   ├── engine/
│   │   ├── normalizer.py    Winlogbeat/EVTX JSON → Event (transport boundary)
│   │   ├── rule_loader.py   load + index YAML rules by EventID
│   │   ├── matcher.py       Sigma-compatible rule evaluation
│   │   ├── correlator.py    ProcessTree + IncidentEngine
│   │   ├── beacon.py        statistical C2 beacon detection
│   │   └── pipeline.py      orchestrates the full path
│   └── models/
│       ├── schemas.py       domain models (Event, Detection, Incident…)
│       └── db.py            async SQLAlchemy persistence
├── rules/                   YAML detection rules, by EventID
├── frontend/dashboard.html  the analyst console (single file, no build step)
├── scripts/replay_evtx.py   replay EVTX/JSONL into the engine
└── tests/                   55 tests: matcher, correlator, beacon, normalizer
```

---

## Getting started

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1

pip install fastapi "uvicorn[standard]" sqlalchemy aiosqlite \
            pydantic-settings pyyaml python-dateutil

python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

- Console: <http://localhost:8000>
- API docs: <http://localhost:8000/api/docs>
- Health: <http://localhost:8000/health>

### Send a test event

From the Swagger UI at `/api/docs`, or with curl, POST an Office-spawns-shell
event to `/ingest` and watch it land in the console:

```json
{
  "winlog": {
    "event_id": 1,
    "event_data": {
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
      "CommandLine": "cmd.exe /c powershell -w hidden -enc SQBFAFgA..."
    }
  }
}
```

### Replay real telemetry

Point the replay script at an `.evtx` — one exported from a lab VM, or a sample
from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
where each file is one ATT&CK technique:

```bash
pip install evtx
python scripts/replay_evtx.py --file samples/lateral_movement.evtx

# freeze a capture as a committed regression fixture (no engine needed to replay it)
python scripts/replay_evtx.py --file samples/lm.evtx --dump tests/fixtures/lm.jsonl
python scripts/replay_evtx.py --file tests/fixtures/lm.jsonl
```

---

## Tests

```bash
pip install pytest
python -m pytest            # 55 tests
```

The suite is worth reading as documentation: each design decision above has a
test named for it. The negative tests in `test_beacon.py` — human browsing,
page-load bursts, streaming connections — are the ones that decide whether the
beacon detector is usable on a real network, and they are where two real design
bugs were caught during development.

---

## Lab setup

To generate live telemetry rather than replaying it:

- A Windows VM with [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
  and a config such as [SwiftOnSecurity's](https://github.com/SwiftOnSecurity/sysmon-config)
  or [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular).
- [Winlogbeat](https://www.elastic.co/beats/winlogbeat) shipping the Sysmon
  channel to `POST /ingest`.
- [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) to fire
  the ATT&CK technique behind each rule and confirm it triggers — the detection-
  engineering loop: write rule → fire atomic → confirm → freeze as a fixture.

---

## Roadmap

- Discovery-burst correlation (recon commands stacking in one process tree)
- Beacon evidence panel in the console (interval, jitter, regularity)
- Expanded rule corpus (LOLBins, registry persistence, shadow-copy deletion)
- Alembic migrations for schema evolution

---

## Notes

Built as a hands-on threat-detection research project. The engine is designed
for a single collector; scaling to many would mean moving the queue to Redis and
the store to Postgres, both of which are isolated behind small interfaces
(`config.db_url`, and the pipeline's queue abstraction) precisely so that change
touches one file each.