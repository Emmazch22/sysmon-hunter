"""Incident titling.

The title is derived from contents, never stored input, so these tests assert
the mapping from what an incident contains to how it reads. The cases mirror the
real scenarios the demo seed produces.
"""

from __future__ import annotations

from backend.models.schemas import Detection, Event, Incident, Severity


def incident_with(rules_and_techniques, host="WS-01") -> Incident:
    """Build an incident from (rule_id, [techniques]) pairs."""
    inc = Incident(host=host, root_guid="g")
    for rule_id, techniques in rules_and_techniques:
        inc.add(
            Detection(
                rule_id=rule_id,
                title="x",
                severity=Severity.HIGH,
                attack=techniques,
                event=Event(event_id=1),
            )
        )
    return inc


class TestNarratives:
    def test_phishing_to_reconnaissance(self) -> None:
        inc = incident_with(
            [
                ("SYS-001", ["T1566.001"]),  # delivery
                ("SYS-002", ["T1059.001"]),  # execution
                ("DSC-001", ["T1087", "T1082"]),  # discovery
            ],
            host="FIN-WS-07",
        )
        assert inc.title == "Phishing to reconnaissance on FIN-WS-07"

    def test_phishing_execution_chain(self) -> None:
        inc = incident_with(
            [
                ("SYS-001", ["T1566.001"]),
                ("SYS-002", ["T1059.001"]),
            ]
        )
        assert inc.title == "Phishing execution chain on WS-01"

    def test_credential_access_with_c2(self) -> None:
        inc = incident_with(
            [
                ("SYS-041", ["T1003.001"]),
                ("BCN-001", ["T1071.001"]),
            ]
        )
        assert inc.title == "Credential access with C2 on WS-01"


class TestSignatureRules:
    def test_shadow_copy_deletion_is_ransomware_prep(self) -> None:
        inc = incident_with([("SYS-004", ["T1490"])], host="HR-WS-03")
        assert inc.title == "Ransomware preparation on HR-WS-03"

    def test_lsass_access_is_credential_theft(self) -> None:
        inc = incident_with([("SYS-041", ["T1003.001"])])
        assert inc.title == "Credential theft on WS-01"

    def test_beacon_alone_is_c2_beacon(self) -> None:
        inc = incident_with([("BCN-001", ["T1071.001", "T1573"])])
        assert inc.title == "C2 beacon on WS-01"


class TestFallbacks:
    def test_single_tactic_is_named_readably(self) -> None:
        inc = incident_with([("SYS-030", ["T1547.001"])])  # persistence only
        assert inc.title == "Persistence on WS-01"

    def test_title_updates_as_detections_land(self) -> None:
        """The title is derived, so it changes as the incident grows -- a lone
        execution becomes a phishing chain once delivery is added."""
        inc = incident_with([("SYS-002", ["T1059.001"])])
        assert "execution" in inc.title.lower()
        inc.add(
            Detection(
                rule_id="SYS-001",
                title="x",
                severity=Severity.HIGH,
                attack=["T1566.001"],
                event=Event(event_id=1),
            )
        )
        assert inc.title == "Phishing execution chain on WS-01"

    def test_empty_incident_has_a_safe_title(self) -> None:
        inc = Incident(host="WS-01", root_guid="g")
        assert inc.title == "Suspicious activity on WS-01"


class TestSubTechniqueFallback:
    """A rule that ships a sub-technique ID not spelled out in
    `_TECHNIQUE_TACTIC` must still resolve to its parent's tactic, not vanish
    from the title entirely. T1055.001 (mavinject) is a real shipped case:
    only the bare T1055 is listed."""

    def test_unlisted_subtechnique_falls_back_to_parent_tactic(self) -> None:
        inc = incident_with([("SYS-111", ["T1055.001"])])  # process injection
        assert inc.title == "Process injection on WS-01"

    def test_unlisted_subtechnique_of_an_unlisted_parent_is_still_safe(self) -> None:
        """No fabricated tactic when neither the sub-technique nor its parent
        is known -- falls all the way to the generic, honest title."""
        inc = incident_with([("SYS-999", ["T9999.001"])])
        assert inc.title == "Suspicious activity on WS-01"


class TestCorrelationChains:
    """`_CORRELATION_CHAINS` names a specific multi-stage story from rule-ID
    co-occurrence and outranks both the tactic narratives and the signature
    rules above -- these tests pin that priority and the per-chain
    thresholds (e.g. the credential-theft chain requires *two* distinct
    rules, not just one, so it reads as a campaign rather than a single
    lead)."""

    def test_ransomware_chain_needs_both_prep_and_encryption_evidence(self) -> None:
        # SYS-004 alone is still just the existing "Ransomware preparation"
        # signature-rule title (see TestSignatureRules above) -- the chain
        # only completes once encryption evidence lands too.
        inc = incident_with([("SYS-004", ["T1490"])], host="HR-WS-03")
        assert inc.classification is None
        assert inc.title == "Ransomware preparation on HR-WS-03"

        inc.add(
            Detection(
                rule_id="SYS-081",
                title="x",
                severity=Severity.CRITICAL,
                attack=["T1486"],
                event=Event(event_id=11),
            )
        )
        assert inc.classification == "ransomware"
        assert inc.title == "Ransomware activity chain on HR-WS-03"

    def test_credential_theft_campaign_needs_two_distinct_rules(self) -> None:
        # A single credential-access rule is a lead, not a campaign -- the
        # existing "Credential theft" signature-rule title still applies.
        inc = incident_with([("SYS-041", ["T1003.001"])])
        assert inc.classification is None
        assert inc.title == "Credential theft on WS-01"

        inc.add(
            Detection(
                rule_id="SYS-135",
                title="x",
                severity=Severity.HIGH,
                attack=["T1555.003"],
                event=Event(event_id=11),
            )
        )
        assert inc.classification == "credential-theft-campaign"
        assert inc.title == "Credential theft campaign on WS-01"

    def test_office_to_powershell_chain(self) -> None:
        inc = incident_with(
            [
                ("SYS-001", ["T1566.001", "T1059"]),
                ("SYS-009", ["T1059.001", "T1105"]),
            ],
            host="FIN-WS-07",
        )
        assert inc.classification == "office-to-powershell"
        assert inc.title == "Office to PowerShell infection chain on FIN-WS-07"

    def test_no_chain_matches_leaves_classification_none(self) -> None:
        inc = incident_with([("SYS-030", ["T1547.001"])])
        assert inc.classification is None


class TestRuleCorpusTechniquesResolve:
    """Guardrail: every technique any shipped rule actually declares must
    resolve to a tactic here (directly or via the sub-technique fallback).
    A rule shipped with a technique this table has never heard of, at any
    granularity, silently produces an untitled incident -- this is the same
    kind of gap `test_every_rule_has_a_test_case` in test_rules.py closes
    for missing validation cases, applied to title coverage instead."""

    def test_every_declared_technique_resolves_to_a_tactic(self) -> None:
        from backend.config import settings
        from backend.engine.rule_loader import RuleStore
        from backend.models.schemas import _tactic_for

        store = RuleStore()
        store.load(settings.rules_dir)
        assert not store.errors, f"rules failed to load: {store.errors}"

        techniques = {t for rule in store.all for t in rule.attack}
        unresolved = {t for t in techniques if _tactic_for(t) is None}
        assert not unresolved, (
            f"technique(s) with no tactic mapping, even via parent fallback: "
            f"{sorted(unresolved)} -- add them to _TECHNIQUE_TACTIC in "
            f"backend/models/schemas.py"
        )
