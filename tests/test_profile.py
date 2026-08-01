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


class TestPrivilegeEscalationPhase:
    """Regression test: T1484.001/.002 (GPO/domain-trust abuse) resolved to
    "privilege-escalation" in TECHNIQUE_TACTIC from the session that added
    them, but that tactic was missing from TACTIC_ORDER and had no
    _phrase_for_tactic branch -- so the phase silently vanished from every
    profile and summary instead of erroring, the same class of bug
    TestRuleCorpusTechniquesResolve below cannot catch (it only proves the
    technique resolves to *some* tactic name, not that the tactic actually
    produces a phase)."""

    def test_gpo_abuse_produces_a_privilege_escalation_phase(self) -> None:
        incident = {"host": "WS-01"}
        detections = [_det("SYS-165", ["T1484.001"])]
        profile = build_profile(incident, detections)
        assert any(p["tactic"] == "privilege escalation" for p in profile["phases"])

    def test_container_escape_produces_a_privilege_escalation_phase(self) -> None:
        incident = {"host": "WS-01"}
        detections = [_det("SYS-174", ["T1611"])]
        profile = build_profile(incident, detections)
        phase = next(p for p in profile["phases"] if p["tactic"] == "privilege escalation")
        assert "container" in phase["phrase"]

    def test_privilege_escalation_falls_between_execution_and_defense_evasion(self) -> None:
        incident = {"host": "WS-01"}
        detections = [
            _det("SYS-002", ["T1059.001"]),
            _det("SYS-165", ["T1484.001"]),
            _det("SYS-031", ["T1685"]),
        ]
        tactics = [p["tactic"] for p in build_profile(incident, detections)["phases"]]
        assert tactics == ["execution", "privilege escalation", "defense evasion"]


class TestSubTechniqueFallback:
    def test_unlisted_subtechnique_falls_back_to_parent_phase(self) -> None:
        """T1055.001 (mavinject) is not spelled out in TECHNIQUE_TACTIC, only
        the bare T1055 is -- the phase must still appear via the parent."""
        incident = {"host": "WS-01"}
        detections = [_det("SYS-111", ["T1055.001"])]
        profile = build_profile(incident, detections)
        assert profile["phases"], "unlisted sub-technique produced no phase at all"


class TestRuleCorpusTechniquesResolve:
    """Same guardrail as test_titles.py's, for this module's independent
    technique->phase table: every technique a shipped rule declares must
    resolve to a phase here too, or that rule's incidents get no behavior
    profile at all."""

    def test_every_declared_technique_resolves_to_a_tactic(self) -> None:
        from backend.config import settings
        from backend.engine.profile import _tactic_for
        from backend.engine.rule_loader import RuleStore

        store = RuleStore()
        store.load(settings.rules_dir)
        assert not store.errors, f"rules failed to load: {store.errors}"

        techniques = {t for rule in store.all for t in rule.attack}
        unresolved = {t for t in techniques if _tactic_for(t) is None}
        assert not unresolved, (
            f"technique(s) with no phase mapping, even via parent fallback: "
            f"{sorted(unresolved)} -- add them to TECHNIQUE_TACTIC in "
            f"backend/engine/profile.py"
        )
