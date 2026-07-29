"""STIX export: the conversion contract and the API that exposes it.

Mirrors tests/test_report.py's shape (plain serialized incident/detection
dicts, no DB) for the pure conversion tests, plus one endpoint test that goes
through the real /ingest pipeline so the STIX bundle is checked against data
that actually flowed through normalize -> match -> correlate -> persist, not
just a hand-built fixture.
"""

from __future__ import annotations

import json

from httpx import ASGITransport, AsyncClient

from backend.engine.stix_export import build_stix_bundle
from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity


def _incident(**overrides) -> dict:
    base = {
        "id": "abc123",
        "title": "Ransomware activity chain on HQ-FILES-03",
        "host": "HQ-FILES-03",
        "severity": "critical",
        "score": 345,
        "classification": "ransomware",
        "techniques": ["T1490"],
        "first_seen": "2026-07-28T22:12:12+00:00",
        "last_seen": "2026-07-28T22:12:18+00:00",
        "chain": ["explorer.exe", "vssadmin.exe"],
    }
    base.update(overrides)
    return base


def _detection(**overrides) -> dict:
    base = {
        "rule_id": "SYS-004",
        "title": "Volume shadow copies deleted",
        "severity": "critical",
        "attack": ["T1490"],
        "image": r"C:\Windows\System32\vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
        "matched_at": "2026-07-28T22:12:16+00:00",
        "evidence": {},
        "forensics": {},
    }
    base.update(overrides)
    return base


class TestBundleStructure:
    def test_bundle_is_json_serializable_and_well_formed(self) -> None:
        bundle = build_stix_bundle(_incident(), [_detection()])
        text = json.dumps(bundle)  # must not raise
        assert json.loads(text) == bundle
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")

    def test_every_object_has_a_typed_id_and_spec_version(self) -> None:
        bundle = build_stix_bundle(_incident(), [_detection()])
        for obj in bundle["objects"]:
            assert obj["id"].startswith(f"{obj['type']}--")
            assert obj["spec_version"] == "2.1"

    def test_contains_exactly_one_identity_and_one_report(self) -> None:
        bundle = build_stix_bundle(_incident(), [_detection()])
        types = [o["type"] for o in bundle["objects"]]
        assert types.count("identity") == 1
        assert types.count("report") == 1
        assert bundle["objects"][-1]["type"] == "report"  # report ties everything together, listed last

    def test_report_object_refs_covers_every_other_object(self) -> None:
        bundle = build_stix_bundle(_incident(), [_detection()])
        report = bundle["objects"][-1]
        other_ids = {o["id"] for o in bundle["objects"][:-1]}
        assert set(report["object_refs"]) == other_ids

    def test_report_carries_incident_identity(self) -> None:
        bundle = build_stix_bundle(_incident(), [_detection()])
        report = bundle["objects"][-1]
        assert report["name"] == "Ransomware activity chain on HQ-FILES-03"
        assert report["labels"] == ["critical", "ransomware"]
        assert report["external_references"] == [
            {"source_name": "sysmon-hunter", "external_id": "abc123"}
        ]

    def test_no_classification_omits_that_label(self) -> None:
        bundle = build_stix_bundle(_incident(classification=None), [_detection()])
        report = bundle["objects"][-1]
        assert report["labels"] == ["critical"]


class TestIdDeterminism:
    def test_same_incident_id_twice_gets_the_same_report_id(self) -> None:
        first = build_stix_bundle(_incident(), [_detection()])
        second = build_stix_bundle(_incident(), [_detection()])
        first_report = next(o for o in first["objects"] if o["type"] == "report")
        second_report = next(o for o in second["objects"] if o["type"] == "report")
        assert first_report["id"] == second_report["id"]

    def test_same_technique_across_two_incidents_gets_the_same_attack_pattern_id(self) -> None:
        a = build_stix_bundle(_incident(id="inc-a"), [_detection()])
        b = build_stix_bundle(_incident(id="inc-b"), [_detection()])
        a_pattern = next(o for o in a["objects"] if o["type"] == "attack-pattern")
        b_pattern = next(o for o in b["objects"] if o["type"] == "attack-pattern")
        assert a_pattern["id"] == b_pattern["id"]

    def test_the_bundle_id_itself_is_not_stable(self) -> None:
        """The bundle is a transport container, not a real-world entity --
        unlike everything inside it, its own id is not meant to be looked up
        again, so it is random rather than content-derived."""
        first = build_stix_bundle(_incident(), [_detection()])
        second = build_stix_bundle(_incident(), [_detection()])
        assert first["id"] != second["id"]


class TestAttackPatterns:
    def test_one_attack_pattern_per_distinct_technique(self) -> None:
        bundle = build_stix_bundle(_incident(techniques=["T1490", "T1486"]), [_detection()])
        patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        assert {p["external_references"][0]["external_id"] for p in patterns} == {"T1490", "T1486"}

    def test_no_techniques_means_no_attack_pattern_objects(self) -> None:
        bundle = build_stix_bundle(_incident(techniques=[]), [_detection()])
        assert not [o for o in bundle["objects"] if o["type"] == "attack-pattern"]

    def test_unknown_technique_still_produces_a_minimal_valid_object(self) -> None:
        """A technique absent from the local ATT&CK dataset must not be
        dropped -- the ID itself is never lost, only the enrichment."""
        bundle = build_stix_bundle(_incident(techniques=["T9999"]), [_detection()])
        pattern = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
        assert pattern["name"] == "T9999"
        assert pattern["external_references"][0]["external_id"] == "T9999"
        assert "description" not in pattern


class TestIndicators:
    def test_c2_destination_produces_ip_and_domain_indicators(self) -> None:
        det = _detection(forensics={
            "destination_ip": "91.219.236.18",
            "destination_port": "443",
            "destination_hostname": "update-cache.esrf-cdn-relay.net",
        })
        bundle = build_stix_bundle(_incident(), [det])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        patterns = {i["pattern"] for i in indicators}
        assert "[ipv4-addr:value = '91.219.236.18']" in patterns
        assert "[domain-name:value = 'update-cache.esrf-cdn-relay.net']" in patterns

    def test_ipv6_destination_uses_the_ipv6_object_type(self) -> None:
        det = _detection(forensics={"destination_ip": "fe80::1"})
        bundle = build_stix_bundle(_incident(), [det])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["pattern"] == "[ipv6-addr:value = 'fe80::1']"

    def test_file_hash_produces_a_sha256_indicator(self) -> None:
        det = _detection(forensics={"hashes": "MD5=x,SHA256=8a1c4e7b2f9d6a3c0e5b8f1a4c7d0e3b"})
        bundle = build_stix_bundle(_incident(), [det])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["pattern"] == "[file:hashes.SHA256 = '8a1c4e7b2f9d6a3c0e5b8f1a4c7d0e3b']"

    def test_hash_without_sha256_produces_no_indicator(self) -> None:
        """Only SHA256 is trusted as a pivot -- MD5-only telemetry (rare, but
        real) must not silently produce a weaker indicator than it claims."""
        det = _detection(forensics={"hashes": "MD5=onlythis"})
        bundle = build_stix_bundle(_incident(), [det])
        assert not [o for o in bundle["objects"] if o["type"] == "indicator"]

    def test_registry_persistence_produces_a_registry_key_indicator(self) -> None:
        det = _detection(forensics={
            "registry_key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil"
        })
        bundle = build_stix_bundle(_incident(), [det])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["pattern"] == (
            r"[windows-registry-key:key = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil']"
        )

    def test_duplicate_indicators_across_detections_collapse_to_one(self) -> None:
        """Two detections hitting the same C2 IP must not produce two
        indicator objects for it -- see the module docstring."""
        dets = [
            _detection(forensics={"destination_ip": "1.2.3.4"}),
            _detection(rule_id="SYS-021", forensics={"destination_ip": "1.2.3.4"}),
        ]
        bundle = build_stix_bundle(_incident(), dets)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1

    def test_no_forensics_means_no_indicator_objects(self) -> None:
        bundle = build_stix_bundle(_incident(), [_detection(forensics={})])
        assert not [o for o in bundle["objects"] if o["type"] == "indicator"]

    def test_pattern_values_are_escaped_for_quotes_and_backslashes(self) -> None:
        det = _detection(forensics={"registry_key": r"HKLM\Software\It's\Evil"})
        bundle = build_stix_bundle(_incident(), [det])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["pattern"] == r"[windows-registry-key:key = 'HKLM\\Software\\It\'s\\Evil']"


class TestEdgeCases:
    def test_handles_incident_with_no_detections(self) -> None:
        bundle = build_stix_bundle(_incident(), [])
        assert bundle["type"] == "bundle"
        types = [o["type"] for o in bundle["objects"]]
        assert types == ["identity", "attack-pattern", "report"]

    def test_missing_timestamps_do_not_raise(self) -> None:
        bundle = build_stix_bundle(_incident(first_seen=None, last_seen=None), [_detection()])
        report = bundle["objects"][-1]
        assert report["created"].endswith("Z")


class TestStixEndpoint:
    async def test_download_returns_a_valid_bundle(self, tmp_db) -> None:
        from backend.main import app

        inc = Incident(id="stix-ep-1", host="WS-01", root_guid="g-stix-ep-1", score=14)
        inc.add(Detection(
            rule_id="SYS-004",
            title="Volume shadow copies deleted",
            severity=Severity.CRITICAL,
            attack=["T1490"],
            event=Event(
                event_id=1,
                host="WS-01",
                image=r"C:\Windows\System32\vssadmin.exe",
                raw={"DestinationIp": "1.2.3.4"},
            ),
        ))
        await db.upsert_incident(inc, actionable=True)
        await db.save_detection(inc.detections[0])

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents/stix-ep-1/stix")
                assert r.status_code == 200
                assert r.headers["content-type"].startswith("application/json")
                assert "stix-ep-1.stix.json" in r.headers["content-disposition"]

                body = r.json()
                assert body["type"] == "bundle"
                report = next(o for o in body["objects"] if o["type"] == "report")
                assert report["external_references"][0]["external_id"] == "stix-ep-1"
                assert any(o["type"] == "indicator" for o in body["objects"])

    async def test_unknown_incident_404s(self, tmp_db) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents/ghost/stix")
                assert r.status_code == 404
