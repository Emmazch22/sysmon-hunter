"""ATT&CK lookup and endpoint.

The lookup is what backs the clickable technique chips. These tests pin the two
behaviours the console depends on: a known technique resolves, and a
sub-technique falls back to its parent rather than dead-ending.
"""

from __future__ import annotations

import pytest
from backend.engine.attack import AttackLookup

# A tiny fixture dataset, so the test does not depend on the generated file or a
# network fetch. The shape mirrors what scripts/fetch_attack.py writes.
SAMPLE = {
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters.",
        "tactics": ["execution"],
        "url": "https://attack.mitre.org/techniques/T1059",
    },
    "T1003.001": {
        "id": "T1003.001",
        "name": "LSASS Memory",
        "description": "Adversaries may access credentials in LSASS.",
        "tactics": ["credential-access"],
        "url": "https://attack.mitre.org/techniques/T1003/001",
    },
}


@pytest.fixture
def lookup(tmp_path) -> AttackLookup:
    import json

    path = tmp_path / "attack_data.json"
    path.write_text(json.dumps(SAMPLE), encoding="utf-8")
    store = AttackLookup()
    store.load(path)
    return store


def test_known_technique_resolves(lookup: AttackLookup) -> None:
    technique = lookup.get("T1059")
    assert technique is not None
    assert technique["name"] == "Command and Scripting Interpreter"


def test_subtechnique_falls_back_to_parent(lookup: AttackLookup) -> None:
    """A sub-technique we did not ship data for resolves to its parent, so the
    chip is never a dead click."""
    technique = lookup.get("T1059.999")
    assert technique is not None
    assert technique["id"] == "T1059"
    assert "note" in technique  # flagged as a parent fallback


def test_unknown_technique_returns_none(lookup: AttackLookup) -> None:
    assert lookup.get("T9999") is None


def test_missing_data_file_is_not_fatal(tmp_path) -> None:
    """An absent data file must not crash the lookup -- the console simply shows
    no descriptions."""
    store = AttackLookup()
    count = store.load(tmp_path / "does_not_exist.json")
    assert count == 0
    assert store.get("T1059") is None
