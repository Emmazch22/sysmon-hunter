"""Incident report and forensic extraction.

The report is verified by generating a real PDF and confirming the forensic
context an analyst needs actually reaches it -- who ran the process, with what
privileges, and the hashes for pivoting.
"""

from __future__ import annotations

from backend.api.serializers import _forensics
from backend.engine.report import build_incident_report


class TestForensicExtraction:
    def test_pulls_investigation_fields_from_raw(self) -> None:
        raw = {
            "Image": "cmd.exe",
            "User": "CORP\\rlopez",
            "IntegrityLevel": "Medium",
            "Hashes": "SHA256=ABC",
            "ProcessId": "4812",
            "CommandLine": "cmd /c evil",
        }
        forensics = _forensics(raw)
        assert forensics["user"] == "CORP\\rlopez"
        assert forensics["integrity_level"] == "Medium"
        assert forensics["hashes"] == "SHA256=ABC"
        assert forensics["process_id"] == "4812"

    def test_only_present_fields_are_returned(self) -> None:
        """A network event carries no hashes; the block must not invent empty
        keys for fields the event did not have."""
        raw = {"DestinationIp": "1.2.3.4", "DestinationPort": "443"}
        forensics = _forensics(raw)
        assert forensics == {"destination_ip": "1.2.3.4", "destination_port": "443"}
        assert "hashes" not in forensics

    def test_empty_raw_yields_empty_forensics(self) -> None:
        assert _forensics({}) == {}


class TestReportGeneration:
    def _incident(self) -> dict:
        return {
            "id": "abc123",
            "title": "Phishing execution chain on FIN-WS-07",
            "host": "FIN-WS-07",
            "severity": "critical",
            "score": 22,
            "detection_count": 2,
            "chain": ["WINWORD.EXE", "cmd.exe"],
            "techniques": ["T1566.001", "T1059"],
            "first_seen": "2026-07-13T14:00:00",
            "last_seen": "2026-07-13T14:01:00",
        }

    def _detections(self) -> list[dict]:
        return [
            {
                "rule_id": "SYS-001",
                "title": "Office spawned a shell",
                "severity": "high",
                "command_line": "cmd /c powershell -enc AAAA",
                "matched_at": "2026-07-13T14:00:00",
                "forensics": {
                    "user": "CORP\\rlopez",
                    "integrity_level": "Medium",
                    "process_id": "4812",
                    "hashes": "SHA256=ABC",
                },
                "evidence": {},
            },
            {
                "rule_id": "SYS-041",
                "title": "LSASS access",
                "severity": "critical",
                "command_line": None,
                "matched_at": "2026-07-13T14:01:00",
                "forensics": {"user": "CORP\\rlopez", "target_image": "lsass.exe"},
                "evidence": {},
            },
        ]

    def test_produces_a_valid_pdf(self) -> None:
        pdf = build_incident_report(self._incident(), self._detections())
        assert pdf.startswith(b"%PDF"), "output must be a PDF"
        assert len(pdf) > 1500, "a real report has substance"

    def test_handles_incident_with_no_detections(self) -> None:
        """An empty incident must still render, not crash -- defensive, since the
        report can be requested at any point in an incident's life."""
        pdf = build_incident_report(self._incident(), [])
        assert pdf.startswith(b"%PDF")

    def test_handles_beacon_evidence(self) -> None:
        """A beacon detection carries evidence rather than a command line; the
        report renders that block too."""
        detections = [
            {
                "rule_id": "BCN-001",
                "title": "C2 beacon",
                "severity": "critical",
                "command_line": None,
                "matched_at": "2026-07-13T14:00:00",
                "forensics": {"destination_ip": "185.234.72.19"},
                "evidence": {
                    "median_interval_seconds": 45,
                    "regularity": 0.93,
                    "connections": 8,
                },
            }
        ]
        pdf = build_incident_report(self._incident(), detections)
        assert pdf.startswith(b"%PDF")
