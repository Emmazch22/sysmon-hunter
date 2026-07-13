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
