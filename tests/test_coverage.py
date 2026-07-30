"""ATT&CK coverage report and Navigator layer export.

`engine/coverage.py` has two personalities: a full gap analysis when
`attack_index.json` is present, and a partial "only what we already cover"
view when it is not. Both must produce a valid report and a valid Navigator
layer -- the whole point of the graceful-degradation design is that a
missing optional file changes *how much* the report shows, never *whether*
it works.
"""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from backend.engine import coverage
from tests.conftest import make_rule


class _StubRuleStore:
    """A drop-in for `rule_loader.rule_store` with a fixed rule list, so
    coverage tests do not depend on the project's real (and constantly
    growing) rule corpus."""

    def __init__(self, rules):
        self._rules = list(rules)

    @property
    def all(self):
        return list(self._rules)


class _StubAttackLookup:
    """A drop-in for `engine.attack.attack_lookup` that returns nothing --
    coverage tests care about IDs and rule counts, not MITRE prose, and a
    lookup with no data still has to degrade to empty name/tactics rather
    than raise."""

    def get(self, technique_id):
        return None


FULL_INDEX = {
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"]},
    "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"]},
    "T1071.001": {"id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"]},
    "T1573": {"id": "T1573", "name": "Encrypted Channel", "tactics": ["command-and-control"]},
}


@pytest.fixture(autouse=True)
def _stub_detector_and_lookup(monkeypatch):
    """Every test in this module gets a fixed, minimal set of detector
    techniques (rather than the project's real ten) and a lookup that never
    resolves, so assertions can be exact instead of "at least these"."""
    monkeypatch.setattr(coverage, "DETECTOR_TECHNIQUES", frozenset({"T1071.001", "T1573"}))
    monkeypatch.setattr(coverage, "attack_lookup", _StubAttackLookup())


def _index_file(tmp_path, data=FULL_INDEX):
    path = tmp_path / "attack_index.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestRuleCountsByTechnique:
    def test_counts_yaml_rule_references(self, monkeypatch):
        rules = [
            make_rule(rule_id="R1", attack=["T1059"]),
            make_rule(rule_id="R2", attack=["T1059", "T1003"]),
        ]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))

        counts = coverage.rule_counts_by_technique()

        assert counts["T1059"] == 2
        assert counts["T1003"] == 1

    def test_includes_detector_techniques_even_with_no_rules(self, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))

        counts = coverage.rule_counts_by_technique()

        assert counts["T1071.001"] == 1
        assert counts["T1573"] == 1

    def test_rule_and_detector_on_the_same_technique_both_count(self, monkeypatch):
        rules = [make_rule(rule_id="R1", attack=["T1071.001"])]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))

        counts = coverage.rule_counts_by_technique()

        assert counts["T1071.001"] == 2  # one rule + one detector

    def test_a_technique_with_zero_coverage_is_simply_absent(self, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        counts = coverage.rule_counts_by_technique()
        assert "T1003" not in counts


class TestBuildReportFullIndex:
    def test_uncovered_technique_appears_with_zero_count(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        index_path = _index_file(tmp_path)

        report = coverage.build_report(index_path=index_path)

        assert report["partial"] is False
        by_id = {t["id"]: t for t in report["techniques"]}
        assert by_id["T1003"]["rule_count"] == 0
        assert by_id["T1071.001"]["rule_count"] == 1  # detector-covered

    def test_covered_and_uncovered_counts_are_consistent(self, tmp_path, monkeypatch):
        rules = [make_rule(rule_id="R1", attack=["T1059"])]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))
        index_path = _index_file(tmp_path)

        report = coverage.build_report(index_path=index_path)

        # T1059, T1071.001, T1573 covered; T1003 uncovered, out of 4 total.
        assert report["total_techniques"] == 4
        assert report["covered_techniques"] == 3
        assert report["uncovered_techniques"] == 1

    def test_rule_referencing_technique_missing_from_index_still_surfaces(self, tmp_path, monkeypatch):
        """A rule can reference a technique newer than the committed index.
        That is real coverage -- it must not be silently dropped just
        because the index has not been regenerated yet."""
        rules = [make_rule(rule_id="R1", attack=["T1999.001"])]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))
        index_path = _index_file(tmp_path)

        report = coverage.build_report(index_path=index_path)

        by_id = {t["id"]: t for t in report["techniques"]}
        assert by_id["T1999.001"]["rule_count"] == 1
        assert report["total_techniques"] == 5  # 4 in the index + the surprise


class TestBuildReportPartialFallback:
    def test_missing_index_file_produces_partial_report(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        missing_path = tmp_path / "does_not_exist.json"

        report = coverage.build_report(index_path=missing_path)

        assert report["partial"] is True
        # Only what this project already references -- the two stubbed
        # detector techniques, nothing MITRE-catalog-wide.
        ids = {t["id"] for t in report["techniques"]}
        assert ids == {"T1071.001", "T1573"}

    def test_partial_report_still_counts_correctly(self, tmp_path, monkeypatch):
        rules = [make_rule(rule_id="R1", attack=["T1059"])]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))
        missing_path = tmp_path / "does_not_exist.json"

        report = coverage.build_report(index_path=missing_path)

        by_id = {t["id"]: t for t in report["techniques"]}
        assert by_id["T1059"]["rule_count"] == 1
        assert report["uncovered_techniques"] == 0  # nothing uncovered is even listed

    def test_corrupt_index_file_degrades_to_partial_not_a_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        bad_path = tmp_path / "attack_index.json"
        bad_path.write_text("{not valid json", encoding="utf-8")

        report = coverage.build_report(index_path=bad_path)

        assert report["partial"] is True


class TestBuildNavigatorLayer:
    def test_layer_has_required_top_level_fields(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        report = coverage.build_report(index_path=_index_file(tmp_path))

        layer = coverage.build_navigator_layer(report)

        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert layer["name"]
        assert isinstance(layer["techniques"], list)

    def test_technique_count_matches_report(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        report = coverage.build_report(index_path=_index_file(tmp_path))

        layer = coverage.build_navigator_layer(report)

        assert len(layer["techniques"]) == len(report["techniques"])
        ids = {t["techniqueID"] for t in layer["techniques"]}
        assert ids == {t["id"] for t in report["techniques"]}

    def test_score_mirrors_rule_count(self, tmp_path, monkeypatch):
        rules = [make_rule(rule_id="R1", attack=["T1059"]), make_rule(rule_id="R2", attack=["T1059"])]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))
        report = coverage.build_report(index_path=_index_file(tmp_path))

        layer = coverage.build_navigator_layer(report)

        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
        assert entry["score"] == 2
        assert "2 rule" in entry["comment"]

    def test_uncovered_technique_scores_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        report = coverage.build_report(index_path=_index_file(tmp_path))

        layer = coverage.build_navigator_layer(report)

        entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1003")
        assert entry["score"] == 0
        assert entry["comment"] == "No rule coverage"

    def test_gradient_max_stretches_to_busiest_technique(self, tmp_path, monkeypatch):
        rules = [make_rule(rule_id=f"R{i}", attack=["T1059"]) for i in range(5)]
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore(rules))
        report = coverage.build_report(index_path=_index_file(tmp_path))

        layer = coverage.build_navigator_layer(report)

        assert layer["gradient"]["maxValue"] == 5
        assert layer["gradient"]["minValue"] == 0

    def test_empty_report_still_produces_a_valid_layer(self):
        empty_report = {
            "partial": True,
            "total_techniques": 0,
            "covered_techniques": 0,
            "uncovered_techniques": 0,
            "techniques": [],
        }

        layer = coverage.build_navigator_layer(empty_report)

        assert layer["techniques"] == []
        assert layer["gradient"]["maxValue"] == 1  # never equal to minValue

    def test_partial_report_notes_it_in_the_description(self):
        partial_report = {
            "partial": True,
            "total_techniques": 0,
            "covered_techniques": 0,
            "uncovered_techniques": 0,
            "techniques": [],
        }

        layer = coverage.build_navigator_layer(partial_report)

        assert "PARTIAL" in layer["description"]

    def test_build_navigator_layer_with_no_argument_builds_its_own_report(self, tmp_path, monkeypatch):
        monkeypatch.setattr(coverage, "rule_store", _StubRuleStore([]))
        monkeypatch.setattr(coverage, "ATTACK_INDEX_PATH", tmp_path / "does_not_exist.json")

        layer = coverage.build_navigator_layer()

        assert isinstance(layer["techniques"], list)


class TestCoverageEndpoints:
    async def test_coverage_report_endpoint_returns_json(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/attack/coverage")
                assert r.status_code == 200
                body = r.json()
                assert "partial" in body
                assert "techniques" in body
                assert isinstance(body["techniques"], list)

    async def test_navigator_endpoint_downloads_a_valid_layer(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/attack/coverage/navigator")
                assert r.status_code == 200
                assert r.headers["content-type"].startswith("application/json")
                assert "sysmon-hunter-coverage.navigator.json" in r.headers["content-disposition"]

                layer = r.json()
                assert layer["domain"] == "enterprise-attack"
                assert layer["versions"]["layer"] == "4.5"

    async def test_coverage_route_is_not_shadowed_by_technique_lookup(self, tmp_db) -> None:
        """A single-segment '/attack/coverage' must resolve to the coverage
        report, not fall into '/attack/{technique_id}' and 404 as an unknown
        technique named "coverage"."""
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/attack/coverage")
                assert r.status_code == 200
