"""Key indicator consolidation.

The panel answers an analyst's first questions -- who, what to block, what to
clean, did privileges rise -- from data spread across the detections. These
tests pin the consolidation logic, especially the privilege-escalation detection.
"""

from __future__ import annotations

from backend.engine.indicators import build_indicators


def _det(**forensics):
    return {
        "rule_id": "X",
        "image": forensics.pop("image", "x.exe"),
        "forensics": forensics,
    }


class TestIndicators:
    def test_deduplicates_users_and_destinations(self) -> None:
        dets = [
            _det(user="CORP\\a", destination_ip="1.2.3.4", destination_port="443"),
            _det(user="CORP\\a", destination_ip="1.2.3.4", destination_port="443"),
        ]
        ind = build_indicators(dets)
        assert ind["users"] == ["CORP\\a"]
        assert len(ind["destinations"]) == 1

    def test_extracts_sha256_from_hash_field(self) -> None:
        dets = [_det(image="mimikatz.exe", hashes="SHA1=abc,SHA256=deadbeef")]
        ind = build_indicators(dets)
        assert ind["hashes"][0]["sha256"] == "deadbeef"
        assert ind["hashes"][0]["image"] == "mimikatz.exe"

    def test_detects_privilege_escalation(self) -> None:
        """Medium -> High integrity across the incident is an escalation."""
        dets = [_det(integrity_level="Medium"), _det(integrity_level="High")]
        esc = build_indicators(dets)["privilege_escalation"]
        assert esc == {"from": "medium", "to": "high"}

    def test_no_escalation_when_integrity_is_flat(self) -> None:
        dets = [_det(integrity_level="Medium"), _det(integrity_level="Medium")]
        assert build_indicators(dets)["privilege_escalation"] is None

    def test_collects_registry_persistence(self) -> None:
        dets = [_det(registry_key="HKCU\\...\\Run\\Evil")]
        assert build_indicators(dets)["registry_persistence"] == [
            "HKCU\\...\\Run\\Evil"
        ]

    def test_empty_incident_yields_empty_indicators(self) -> None:
        ind = build_indicators([])
        assert ind["users"] == [] and ind["hashes"] == []
        assert ind["privilege_escalation"] is None
