"""Incident behavior profiling.

The profile turns detections into a kill-chain narrative. These tests pin the
two things that make it trustworthy: phases come out in intrusion order (not the
order detections fired), and the phrases carry the specific evidence (beacon
interval, recon breadth) rather than generic labels.
"""

from __future__ import annotations

from backend.engine.profile import build_profile


def _det(rule_id, attack, evidence=None):
    return {
        "rule_id": rule_id,
        "attack": attack,
        "evidence": evidence or {},
        "title": "",
    }


class TestPhaseOrdering:
    def test_phases_follow_kill_chain_not_fire_order(self) -> None:
        """C2 fired first in the data, execution last -- the profile must still
        put execution before C2, because that is the intrusion order."""
        incident = {"host": "WS-01"}
        detections = [
            _det("BCN-001", ["T1071.001"], {"median_interval_seconds": 45}),  # C2
            _det("SYS-002", ["T1059.001"]),  # execution
        ]
        profile = build_profile(incident, detections)
        tactics = [p["tactic"] for p in profile["phases"]]
        assert tactics.index("execution") < tactics.index("command and control")


class TestEvidenceInPhrases:
    def test_beacon_phrase_carries_the_interval(self) -> None:
        incident = {"host": "WS-01"}
        detections = [_det("BCN-001", ["T1071.001"], {"median_interval_seconds": 43})]
        profile = build_profile(incident, detections)
        c2 = next(p for p in profile["phases"] if "command" in p["tactic"])
        assert "43s" in c2["phrase"]

    def test_discovery_phrase_carries_the_technique_count(self) -> None:
        incident = {"host": "WS-01"}
        detections = [_det("DSC-001", ["T1033", "T1082"], {"distinct_techniques": 4})]
        profile = build_profile(incident, detections)
        disc = next(p for p in profile["phases"] if p["tactic"] == "discovery")
        assert "4 distinct" in disc["phrase"]

    def test_credential_access_is_named(self) -> None:
        incident = {"host": "WS-01"}
        detections = [_det("SYS-041", ["T1003.001"])]
        profile = build_profile(incident, detections)
        assert any("LSASS" in p["phrase"] for p in profile["phases"])


class TestSummary:
    def test_summary_stitches_phrases_with_host(self) -> None:
        incident = {"host": "FIN-WS-07"}
        detections = [
            _det("SYS-002", ["T1059.001"]),
            _det("SYS-041", ["T1003.001"]),
        ]
        summary = build_profile(incident, detections)["summary"]
        assert summary.startswith("On FIN-WS-07,")
        assert "and" in summary  # two phrases joined

    def test_empty_incident_has_honest_fallback(self) -> None:
        """No profilable detections must not invent a story."""
        profile = build_profile({"host": "WS-01"}, [])
        assert profile["phases"] == []
        assert "no clearly profiled behavior" in profile["summary"]

    def test_full_intrusion_reads_as_a_chain(self) -> None:
        """The APT-style incident should profile every stage in order."""
        incident = {"host": "WKSTN-04"}
        detections = [
            _det("SYS-001", ["T1566.001"]),
            _det("SYS-002", ["T1059.001"]),
            _det("DSC-001", ["T1033"], {"distinct_techniques": 4}),
            _det("SYS-041", ["T1003.001"]),
            _det("SYS-030", ["T1547.001"]),
            _det("BCN-001", ["T1071.001"], {"median_interval_seconds": 35}),
        ]
        tactics = [p["tactic"] for p in build_profile(incident, detections)["phases"]]
        assert tactics == [
            "initial access",
            "execution",
            "discovery",
            "credential access",
            "persistence",
            "command and control",
        ]
