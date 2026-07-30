#!/usr/bin/env python3
"""Build the local ATT&CK technique lookup and the full technique index.

The console lets an analyst click any ATT&CK technique to read its description.
That description comes from MITRE's official STIX dataset -- but the console must
not fetch it live, for three reasons:

  * The full enterprise bundle is ~35 MB. Shipping it to a browser on every page
    load, or even caching it, is absurd for the handful of techniques this
    project actually references.
  * GitHub's raw endpoint has no CORS guarantee and no uptime guarantee. A SOC
    console that breaks because a third-party host is slow is a bad console.
  * The set of techniques we care about is fixed -- it is exactly the ones our
    rules and detectors emit. There is no reason to carry the other 800+.

So this script runs once (and again whenever the rules change), pulls the
official dataset, and writes two files:

  * backend/data/attack_data.json -- name, description, tactics, and a MITRE
    URL, keyed by ATT&CK ID, but only for the techniques this project's rules
    and detectors actually reference. This is what the console's technique
    modal reads (see engine/attack.py).

  * backend/data/attack_index.json -- id, name, and tactics only (no
    description, no URL) for *every* non-deprecated Enterprise technique,
    referenced or not. Dropping the description is what keeps this file two
    orders of magnitude smaller than the full bundle while still being able
    to answer "which techniques exist that we have no rule for at all" --
    the question `attack_data.json` alone cannot answer, since it was
    filtered down to only what we already cover before that question could
    even be asked. This is what the coverage/gap report reads (see
    engine/coverage.py); without it, that report can only compare rules
    against each other, never against the techniques nobody has written a
    rule for yet.

    python scripts/fetch_attack.py

Both outputs land in backend/data/.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

# The official MITRE CTI repository, Enterprise domain, STIX 2.0 bundle. This is
# the same source the ATT&CK website and Navigator are built from.
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
OUTPUT = BACKEND_DIR / "data" / "attack_data.json"
INDEX_OUTPUT = BACKEND_DIR / "data" / "attack_index.json"

# Techniques the statistical detectors emit. Rules declare their own techniques
# in YAML; the beacon and discovery engines do not, so their techniques are
# listed here to make sure they end up in the lookup too.
DETECTOR_TECHNIQUES = {
    "T1071.001",
    "T1573",  # beacon
    "T1087",
    "T1082",
    "T1016",
    "T1033",
    "T1069",
    "T1018",
    "T1057",
    "T1049",  # discovery
}


def collect_referenced_ids() -> set[str]:
    """Every ATT&CK ID the project can raise, gathered from the rule corpus."""
    import yaml  # local import so the script's core has no hard dependency

    ids: set[str] = set(DETECTOR_TECHNIQUES)
    for path in RULES_DIR.rglob("*.yml"):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if document:
            ids.update(document.get("attack", []))
    return ids


def download_stix() -> list[dict]:
    """Fetch the official STIX bundle and return its objects."""
    print(f"Fetching ATT&CK dataset from {STIX_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(STIX_URL, timeout=120) as response:
        bundle = json.loads(response.read())
    return bundle["objects"]


def build_lookup(objects: list[dict], wanted: set[str]) -> dict[str, dict]:
    """Index the wanted techniques by ATT&CK ID, keeping only what the UI needs.

    A STIX attack-pattern carries far more than a description -- kill-chain
    phases, data sources, permissions, contributors. The console needs the name,
    the ID, a URL back to MITRE, and the prose. Carrying the rest would bloat the
    file for no benefit.
    """
    lookup: dict[str, dict] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        attack_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break

        if attack_id is None or attack_id not in wanted:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        lookup[attack_id] = {
            "id": attack_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", "").strip(),
            "tactics": tactics,
            "url": url,
        }

    return lookup


def build_full_index(objects: list[dict]) -> dict[str, dict]:
    """Index every non-deprecated Enterprise technique by ATT&CK ID, keeping
    only id/name/tactics.

    This is `build_lookup` without the `wanted` filter and without
    description/url -- deliberately, on both counts. Not filtering is the
    entire point: the coverage report needs to know a technique exists even
    when nothing in this project has ever referenced it, which is exactly
    what `build_lookup`'s `wanted` set excludes by construction. Dropping
    description/url keeps the always-loaded full catalog small; a technique
    the report finds "uncovered" only needs its name and tactics to render
    on a Navigator layer or in a gap list, not its prose (an analyst who
    wants that can already click through to MITRE).
    """
    index: dict[str, dict] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break

        if attack_id is None:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        index[attack_id] = {
            "id": attack_id,
            "name": obj.get("name", ""),
            "tactics": tactics,
        }

    return index


def main() -> int:
    wanted = collect_referenced_ids()
    print(f"Project references {len(wanted)} techniques", file=sys.stderr)

    objects = download_stix()
    lookup = build_lookup(objects, wanted)
    index = build_full_index(objects)

    missing = wanted - set(lookup)
    if missing:
        # A referenced technique with no entry means a typo in a rule, or a
        # technique that MITRE has since deprecated. Worth surfacing loudly.
        print(
            f"WARNING: no ATT&CK data for: {', '.join(sorted(missing))}",
            file=sys.stderr,
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(lookup, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote {len(lookup)} techniques to {OUTPUT}", file=sys.stderr)

    INDEX_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    INDEX_OUTPUT.write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Wrote {len(index)} techniques to {INDEX_OUTPUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
