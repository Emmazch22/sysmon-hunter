"""Search: query parsing and incident matching.

The behaviour an analyst relies on: field filters narrow precisely, free text
matches anywhere, adding a term reduces results (AND), and an empty query returns
nothing rather than everything.
"""

from __future__ import annotations

from backend.engine.search import parse_query, search_incidents


class TestQueryParsing:
    def test_free_text_only(self) -> None:
        q = parse_query("mimikatz lsass")
        assert q.text_terms == ["mimikatz", "lsass"]
        assert q.filters == {}

    def test_field_filters(self) -> None:
        q = parse_query("host:FIN-WS-07 severity:critical")
        assert q.filters == {"host": "fin-ws-07", "severity": "critical"}
        assert q.text_terms == []

    def test_mixed(self) -> None:
        q = parse_query("powershell technique:t1003")
        assert q.text_terms == ["powershell"]
        assert q.filters == {"technique": "t1003"}

    def test_quoted_phrase_stays_together(self) -> None:
        q = parse_query('"encoded command"')
        assert q.text_terms == ["encoded command"]

    def test_unknown_prefix_is_free_text(self) -> None:
        """A colon that is not a known filter (like one in a path) must not
        silently become a broken filter -- it is treated as text."""
        q = parse_query(r"path C:\Windows\Temp")
        # "path" is text; the C:\... token has an unknown prefix so it is text too.
        assert "path" in q.text_terms
        assert q.filters == {}

    def test_empty_query(self) -> None:
        assert parse_query("").is_empty
        assert parse_query("   ").is_empty

    def test_command_line_filter_parses(self) -> None:
        q = parse_query("command_line:encodedcommand")
        assert q.filters == {"command_line": "encodedcommand"}
        assert q.text_terms == []


def _incident(id, host, severity, actionable=True):
    return {
        "id": id,
        "host": host,
        "severity": severity,
        "actionable": actionable,
        "title": f"Incident {id}",
        "techniques": [],
        "chain": [],
    }


def _detection(rule_id, **kw):
    return {
        "rule_id": rule_id,
        "title": kw.get("title", ""),
        "severity": kw.get("severity", "high"),
        "attack": kw.get("attack", []),
        "host": kw.get("host", "WS-01"),
        "image": kw.get("image", ""),
        "parent_image": None,
        "command_line": kw.get("command_line", ""),
        "forensics": kw.get("forensics", {}),
    }


class TestSearch:
    def _fixture(self):
        incidents = [
            _incident("i1", "FIN-WS-07", "critical"),
            _incident("i2", "DEV-WS-11", "high"),
        ]
        detections = {
            "i1": [
                _detection(
                    "SYS-006",
                    image=r"C:\Temp\mimikatz.exe",
                    command_line="mimikatz sekurlsa::logonpasswords",
                    attack=["T1003.001"],
                    host="FIN-WS-07",
                    forensics={"user": "CORP\\rlopez", "hashes": "SHA256=ABC"},
                ),
                _detection(
                    "SYS-041",
                    title="LSASS access",
                    severity="critical",
                    attack=["T1003.001"],
                    host="FIN-WS-07",
                ),
            ],
            "i2": [
                _detection(
                    "BCN-001",
                    title="C2 beacon",
                    attack=["T1071.001"],
                    host="DEV-WS-11",
                    forensics={"destination_ip": "45.132.192.68"},
                ),
            ],
        }
        return incidents, detections

    def test_free_text_finds_by_command_line(self) -> None:
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("mimikatz"))
        assert len(hits) == 1
        assert hits[0].incident["id"] == "i1"

    def test_free_text_finds_by_hash(self) -> None:
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("abc"))
        assert len(hits) == 1
        assert hits[0].incident["id"] == "i1"

    def test_host_filter(self) -> None:
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("host:DEV-WS-11"))
        assert [h.incident["id"] for h in hits] == ["i2"]

    def test_technique_prefix_match(self) -> None:
        """technique:t1003 must find T1003.001."""
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("technique:t1003"))
        assert hits[0].incident["id"] == "i1"

    def test_terms_are_anded(self) -> None:
        """Adding a term narrows: 'mimikatz beacon' matches neither incident,
        since no single detection has both."""
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("mimikatz beacon"))
        assert hits == []

    def test_text_plus_filter(self) -> None:
        incidents, detections = self._fixture()
        hits = search_incidents(
            incidents, detections, parse_query("lsass severity:critical")
        )
        assert hits[0].incident["id"] == "i1"

    def test_severity_filter_matches_incident_wholesale(self) -> None:
        """A severity-only query needs no detection match -- it filters the
        incident directly, and returns all its detections."""
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("severity:high"))
        assert [h.incident["id"] for h in hits] == ["i2"]

    def test_no_match_returns_empty(self) -> None:
        incidents, detections = self._fixture()
        assert search_incidents(incidents, detections, parse_query("nonexistent")) == []

    def test_command_line_filter_matches(self) -> None:
        incidents, detections = self._fixture()
        hits = search_incidents(
            incidents, detections, parse_query("command_line:sekurlsa")
        )
        assert [h.incident["id"] for h in hits] == ["i1"]

    def test_command_line_filter_is_scoped_to_the_command_line(self) -> None:
        """Unlike free text, command_line: must not fall back to the title --
        that scoping is the entire reason to use it over a bare search term."""
        incidents, detections = self._fixture()
        # "beacon" is in i2's title ("C2 beacon") but not in any command line.
        assert search_incidents(
            incidents, detections, parse_query("command_line:beacon")
        ) == []
        assert search_incidents(incidents, detections, parse_query("beacon"))

    def test_hits_carry_matched_detections(self) -> None:
        """A hit reports which detections matched, so the UI can show why."""
        incidents, detections = self._fixture()
        hits = search_incidents(incidents, detections, parse_query("mimikatz"))
        assert len(hits[0].matched_detections) == 1
        assert hits[0].matched_detections[0]["rule_id"] == "SYS-006"
