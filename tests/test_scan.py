"""Network scan detection.

The design commitment under test: breadth, not volume. A process hammering one
destination is not a scan no matter how many times it connects; a process
touching many distinct destinations, even a modest number of times each, is.
The false-positive tests are the ones that matter for production use -- any
detector can find an obvious nmap sweep.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.engine.scan import ScanDetector
from backend.models.schemas import Event, Severity

BASE = datetime(2026, 7, 12, 10, 0, 0, tzinfo=timezone.utc)


def connection(
    offset_seconds: float,
    destination_ip: str = "10.0.0.5",
    destination_port: str = "445",
    image: str = r"C:\Windows\System32\cmd.exe",
    host: str = "LAB-WIN11",
    guid: str = "{scan-proc}",
) -> Event:
    """One Sysmon EventID 3, at a given offset from the base time."""
    return Event(
        event_id=3,
        host=host,
        image=image,
        process_guid=guid,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        raw={"DestinationIp": destination_ip, "DestinationPort": destination_port},
    )


def feed(detector: ScanDetector, connections: list[Event]):
    """Push a sequence of connection events; return the last detection, if any."""
    result = None
    for event in connections:
        found = detector.observe(event)
        if found is not None:
            result = found
    return result


@pytest.fixture
def detector() -> ScanDetector:
    """Production defaults, so the tests exercise what actually ships."""
    return ScanDetector(
        min_distinct_ips=10,
        min_distinct_ports=15,
        window=timedelta(minutes=5),
        cooldown=timedelta(minutes=15),
        excluded_images=["chrome.exe", "svchost.exe"],
    )


class TestPortScan:
    def test_many_ports_on_one_host_is_a_port_scan(
        self, detector: ScanDetector
    ) -> None:
        """The textbook vertical case: nmap -p1-1000 against one box."""
        connections = [
            connection(i * 2, destination_ip="10.0.0.5", destination_port=str(1000 + i))
            for i in range(15)
        ]
        detection = feed(detector, connections)

        assert detection is not None
        assert detection.rule_id == "SCN-001"
        assert detection.evidence["distinct_ports"] == 15
        assert detection.evidence["distinct_ips"] == 1
        assert "port scan" in detection.title
        assert "T1046" in detection.attack
        assert "T1018" not in detection.attack

    def test_fires_as_soon_as_the_threshold_is_crossed(
        self, detector: ScanDetector
    ) -> None:
        """The point of live detection: do not wait for the scan to finish."""
        connections = [
            connection(i, destination_ip="10.0.0.5", destination_port=str(2000 + i))
            for i in range(14)
        ]
        assert feed(detector, connections) is None  # 14 ports, one short

        detection = detector.observe(
            connection(14, destination_ip="10.0.0.5", destination_port="2014")
        )
        assert detection is not None
        assert detection.evidence["distinct_ports"] == 15


class TestHostSweep:
    def test_many_hosts_on_one_port_is_a_sweep(self, detector: ScanDetector) -> None:
        """The textbook horizontal case: an SMB sweep across a subnet."""
        connections = [
            connection(i * 2, destination_ip=f"10.0.0.{i}", destination_port="445")
            for i in range(10)
        ]
        detection = feed(detector, connections)

        assert detection is not None
        assert detection.evidence["distinct_ips"] == 10
        assert detection.evidence["distinct_ports"] == 1
        assert "host sweep" in detection.title
        assert "T1046" in detection.attack
        assert "T1018" in detection.attack
        assert detection.severity is Severity.HIGH


class TestCombinedScan:
    def test_both_thresholds_crossed_flags_both_techniques(
        self, detector: ScanDetector
    ) -> None:
        """A scanner that sweeps hosts and ports at once is both shapes, not
        whichever one happened to be checked first.

        The detector alerts the instant either threshold is crossed, so to
        observe both crossing together the host axis is held at 9 distinct
        IPs (reusing the 9th) until the final connection, which introduces
        the 10th IP at the same moment the 15th distinct port appears.
        """
        connections = [
            connection(
                i,
                destination_ip=f"10.0.0.{min(i, 8)}" if i < 14 else "10.0.0.9",
                destination_port=str(3000 + i),
            )
            for i in range(15)
        ]
        detection = feed(detector, connections)

        assert detection is not None
        assert detection.evidence["distinct_ips"] == 10
        assert detection.evidence["distinct_ports"] == 15
        assert "network scan" in detection.title
        assert set(detection.attack) == {"T1046", "T1018"}

    def test_severity_escalates_on_a_later_alert_with_doubled_breadth(self) -> None:
        """The first alert always lands right at the threshold -- breadth
        grows by at most one distinct destination per connection, so it
        cannot already be double on the very event that first crosses the
        bar. Escalation shows up on a *subsequent* alert, once the process
        keeps going and its accumulated breadth (still within the window)
        passes double the threshold.

        The cooldown is long enough that the second batch of 15 ports
        accumulates silently -- no alert re-fires mid-batch -- and only the
        final, post-cooldown reconnection (to an already-seen port, so it adds
        no new breadth of its own) triggers the second verdict, carrying the
        full doubled count.
        """
        detector = ScanDetector(
            min_distinct_ports=15,
            window=timedelta(minutes=30),
            cooldown=timedelta(minutes=5),
        )
        first = feed(
            detector,
            [
                connection(i, destination_ip="10.0.0.5", destination_port=str(4000 + i))
                for i in range(15)
            ],
        )
        assert first is not None
        assert first.severity is Severity.HIGH

        # 15 more distinct ports, all well within the 5-minute cooldown that
        # started at the first alert (offset ~14s) -- these accumulate breadth
        # without re-alerting.
        silent = feed(
            detector,
            [
                connection(20 + i, destination_ip="10.0.0.5", destination_port=str(5000 + i))
                for i in range(15)
            ],
        )
        assert silent is None

        # Past the cooldown, a reconnection to an already-seen port adds no
        # new breadth but is enough to re-run the assessment.
        second = detector.observe(
            connection(320, destination_ip="10.0.0.5", destination_port="5014")
        )
        assert second is not None
        assert second.evidence["distinct_ports"] == 30
        assert second.severity is Severity.CRITICAL


class TestEvidence:
    def test_evidence_lets_an_analyst_judge_the_call(
        self, detector: ScanDetector
    ) -> None:
        connections = [
            connection(i, destination_ip="10.0.0.5", destination_port=str(5000 + i))
            for i in range(15)
        ]
        detection = feed(detector, connections)

        assert detection is not None
        evidence = detection.evidence
        assert evidence["distinct_pairs"] == 15
        assert len(evidence["sample_destinations"]) <= 10
        assert "10.0.0.5:5000" in evidence["sample_destinations"]
        assert evidence["image"] == "cmd.exe"
        assert "span_seconds" in evidence


class TestFalsePositives:
    """The tests that decide whether this is usable on a real network."""

    def test_too_few_distinct_destinations_is_not_a_scan(
        self, detector: ScanDetector
    ) -> None:
        connections = [
            connection(i, destination_ip="10.0.0.5", destination_port=str(6000 + i))
            for i in range(5)
        ]
        assert feed(detector, connections) is None

    def test_repeated_connections_to_one_destination_never_score_as_a_scan(
        self, detector: ScanDetector
    ) -> None:
        """Volume, no breadth. A keep-alive loop must stay silent no matter how
        many times it fires."""
        connections = [connection(i * 10) for i in range(50)]
        assert feed(detector, connections) is None

    def test_a_handful_of_stable_destinations_is_not_a_scan(
        self, detector: ScanDetector
    ) -> None:
        """A service polling its usual handful of dependencies repeatedly must
        not accumulate into a false positive just because it runs for a while."""
        destinations = [(f"10.0.0.{i}", "443") for i in range(4)]
        connections = [
            connection(i * 5, destination_ip=ip, destination_port=port)
            for i in range(40)
            for ip, port in [destinations[i % len(destinations)]]
        ]
        assert feed(detector, connections) is None

    def test_excluded_process_is_skipped(self, detector: ScanDetector) -> None:
        """Chrome's connection pool touches many hosts and ports all day. It is
        on the exclusion list -- which is a liability, not a feature, and is
        why that list stays short."""
        connections = [
            connection(i, destination_ip=f"10.0.0.{i}", destination_port="443", image="chrome.exe")
            for i in range(15)
        ]
        assert feed(detector, connections) is None


class TestWindowing:
    def test_destinations_outside_the_window_do_not_accumulate(
        self, detector: ScanDetector
    ) -> None:
        """A slow trickle -- one new destination every few minutes -- must
        never add up into a phantom scan. Each new connection ages out the
        ones that fell outside the window before it."""
        connections = [
            connection(i * 90, destination_ip="10.0.0.5", destination_port=str(7000 + i))
            for i in range(15)  # 90s apart: 14 * 90s = 21 minutes, window is 5
        ]
        assert feed(detector, connections) is None


class TestStateManagement:
    def test_cooldown_suppresses_repeat_alerts(self, detector: ScanDetector) -> None:
        """A scan in progress alerts once, not on every further connection."""
        connections = [
            connection(i, destination_ip="10.0.0.5", destination_port=str(8000 + i))
            for i in range(40)
        ]
        alerts = sum(1 for event in connections if detector.observe(event) is not None)
        assert alerts == 1

    def test_prune_drops_idle_scans(self) -> None:
        detector = ScanDetector(window=timedelta(minutes=5))
        feed(
            detector,
            [
                connection(i, destination_ip="10.0.0.5", destination_port=str(9000 + i))
                for i in range(5)
            ],
        )
        assert detector.tracked_scans == 1

        removed = detector.prune(now=BASE + timedelta(hours=1))
        assert removed == 1
        assert detector.tracked_scans == 0

    def test_scans_are_scoped_per_host(self, detector: ScanDetector) -> None:
        """Two hosts each doing light port probing are not one scan spanning
        both."""
        connections = [
            connection(i, destination_ip="10.0.0.5", destination_port=str(1000 + i), host="WS-01")
            for i in range(5)
        ] + [
            connection(i, destination_ip="10.0.0.5", destination_port=str(2000 + i), host="WS-02")
            for i in range(5)
        ]
        feed(detector, connections)
        assert detector.tracked_scans == 2

    def test_scans_are_scoped_per_process(self, detector: ScanDetector) -> None:
        """Two unrelated processes on one host each touching a few
        destinations must not be pooled into one process's fan-out."""
        connections = [
            connection(i, destination_ip="10.0.0.5", destination_port=str(1000 + i), guid="{p1}")
            for i in range(5)
        ] + [
            connection(i, destination_ip="10.0.0.5", destination_port=str(2000 + i), guid="{p2}")
            for i in range(5)
        ]
        feed(detector, connections)
        assert detector.tracked_scans == 2

    def test_out_of_window_destination_can_still_be_reobserved(
        self, detector: ScanDetector
    ) -> None:
        """Aging out is per-destination, not a hard reset -- a destination
        touched again after falling out of the window is simply re-added."""
        detector.observe(connection(0, destination_ip="10.0.0.5", destination_port="1"))
        # Push the clock far enough that the first destination ages out on
        # the next observation, then confirm the scan can still accumulate
        # fresh breadth from that point.
        connections = [
            connection(400 + i, destination_ip="10.0.0.5", destination_port=str(2000 + i))
            for i in range(15)
        ]
        detection = feed(detector, connections)
        assert detection is not None
        assert detection.evidence["distinct_ports"] == 15
