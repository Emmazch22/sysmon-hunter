"""Beacon detection.

The tests that matter here are the negative ones. Any detector can find a
perfectly periodic connection; the question that decides whether this is usable
in production is whether it stays quiet on the traffic a normal workstation
generates all day.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from backend.engine.beacon import BeaconDetector, regularity
from backend.models.schemas import Event, Severity

BASE = datetime(2026, 7, 12, 10, 0, 0, tzinfo=timezone.utc)


def connection(
    offset_seconds: float,
    image: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    destination_ip: str = "185.234.72.19",
    destination_port: str = "443",
    host: str = "LAB-WIN11",
    guid: str = "{beacon-proc}",
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


def feed(detector: BeaconDetector, offsets: list[float], **kwargs):
    """Push a sequence of connections in and return the last detection, if any."""
    result = None
    for offset in offsets:
        found = detector.observe(connection(offset, **kwargs))
        if found is not None:
            result = found
    return result


@pytest.fixture
def detector() -> BeaconDetector:
    """Production defaults, so the tests exercise what actually ships."""
    return BeaconDetector(
        min_connections=6,
        regularity_threshold=0.75,
        min_interval_seconds=5.0,
        max_interval_seconds=3600.0,
        excluded_images=["chrome.exe", "svchost.exe"],
    )


class TestRegularityScore:
    def test_identical_intervals_score_one(self) -> None:
        assert regularity([60.0] * 8) == 1.0

    def test_human_traffic_scores_near_zero(self) -> None:
        """Browsing has no rhythm. The score must reflect that, or every
        threshold above it is meaningless."""
        assert regularity([3, 180, 12, 4, 900, 7, 45]) < 0.3

    def test_burst_does_not_score_as_a_beacon(self) -> None:
        """Many connections in the same instant give a median interval of zero.
        Treating that divide-by-zero as perfect regularity would make every
        noisy application look like C2 -- so it scores zero, not one."""
        assert regularity([0, 0, 0, 0, 0]) == 0.0

    def test_score_is_bounded(self) -> None:
        assert 0.0 <= regularity([1, 500, 2, 900]) <= 1.0


class TestBeaconDetection:
    def test_clean_periodic_beacon_is_caught(self, detector: BeaconDetector) -> None:
        """A 60-second interval with no jitter: an implant with sleep set and
        jitter forgotten. The easiest possible case, and the floor of what the
        detector must do."""
        detection = feed(detector, [i * 60 for i in range(8)])

        assert detection is not None
        assert detection.rule_id == "BCN-001"
        assert detection.evidence["median_interval_seconds"] == 60.0
        assert detection.evidence["regularity"] == 1.0
        assert detection.severity is Severity.CRITICAL

    def test_cobalt_strike_default_jitter_is_caught(
        self, detector: BeaconDetector
    ) -> None:
        """The case the whole design exists for.

        Cobalt Strike's default reduces a 60-second sleep by up to 37% at random,
        so callbacks land anywhere in 38-60s. A detector that demands equal
        intervals finds nothing here. This one must.
        """
        random.seed(1337)  # Deterministic: a flaky beacon test is worse than none.
        offsets, clock = [], 0.0
        for _ in range(12):
            offsets.append(clock)
            clock += 60 * (1 - random.uniform(0, 0.37))

        detection = feed(detector, offsets)

        assert detection is not None, "37% jitter must not defeat the detector"
        assert 0.75 <= detection.evidence["regularity"] < 1.0
        assert 38 <= detection.evidence["median_interval_seconds"] <= 60

    def test_beacon_survives_an_operator_interacting(
        self, detector: BeaconDetector
    ) -> None:
        """A real session is not uninterrupted. The operator runs a command, the
        host sleeps, a callback retries late -- and one 400-second gap appears in
        an otherwise clean 60-second rhythm.

        This is exactly why the score uses the median absolute deviation and not
        the standard deviation: that single outlier would wreck a stddev-based
        score and lose a live C2 channel.
        """
        offsets = [i * 60 for i in range(6)]
        offsets.append(offsets[-1] + 400)  # operator interaction
        offsets += [offsets[-1] + i * 60 for i in range(1, 6)]

        assert feed(detector, offsets) is not None

    def test_evidence_lets_an_analyst_judge_the_call(
        self, detector: BeaconDetector
    ) -> None:
        """ "Beacon detected" is an assertion. An assertion does not survive
        contact with a false positive, so the numbers ship with the finding."""
        detection = feed(detector, [i * 45 for i in range(8)])

        assert detection is not None
        evidence = detection.evidence
        assert evidence["destination"] == "185.234.72.19:443"
        # The detector fires as soon as it is confident -- at the sixth
        # connection, the moment it crosses min_connections -- rather than
        # waiting for more. Detecting a live C2 channel early is the point.
        assert evidence["connections"] == 6
        assert evidence["median_interval_seconds"] == 45.0
        assert "jitter_seconds" in evidence
        assert "regularity" in evidence


class TestFalsePositives:
    """The tests that decide whether this is usable on a real network."""

    def test_human_browsing_is_ignored(self, detector: BeaconDetector) -> None:
        """Irregular, bursty, unpredictable. If this fires, the detector is
        useless -- an analyst will mute it within a day."""
        offsets = [0, 3, 8, 190, 195, 200, 890, 1400, 1405, 2000]
        assert feed(detector, offsets, image=r"C:\Program Files\app\reader.exe") is None

    def test_too_few_connections_is_not_yet_a_verdict(
        self, detector: BeaconDetector
    ) -> None:
        """Two connections a minute apart look exactly like a beacon and are
        almost always a coincidence. Rhythm needs repetitions to exist."""
        assert feed(detector, [0, 60, 120]) is None

    def test_streaming_connection_is_not_a_beacon(
        self, detector: BeaconDetector
    ) -> None:
        """Sub-second chatter is a video call or a websocket, not C2."""
        assert feed(detector, [i * 0.5 for i in range(20)]) is None

    def test_excluded_process_is_skipped(self, detector: BeaconDetector) -> None:
        """Chrome polls endpoints on a timer all day. It is on the exclusion
        list -- which is a liability, not a feature, and is why that list stays
        short."""
        assert (
            feed(detector, [i * 60 for i in range(12)], image=r"C:\chrome.exe") is None
        )

    def test_same_process_to_different_destinations_does_not_merge(
        self, detector: BeaconDetector
    ) -> None:
        """Alternating connections to two hosts must not be pooled into one
        fake rhythm. Each destination is its own channel."""
        for index in range(12):
            detector.observe(connection(index * 60, destination_ip="10.0.0.1"))
            detector.observe(connection(index * 60 + 7, destination_ip="10.0.0.2"))
        # Both channels are individually periodic and will legitimately alert;
        # what matters is that they are counted separately.
        assert detector.tracked_channels == 2


class TestStateManagement:
    def test_cooldown_suppresses_repeat_alerts_within_the_window(
        self, detector: BeaconDetector
    ) -> None:
        """The beacon keeps beaconing, but within one 30-minute cooldown the
        analyst is told exactly once, not once per callback.

        Over a longer run the detector re-alerts each cooldown, which is the
        intended behaviour: a channel still beaconing an hour later is worth a
        fresh reminder. Here we stay inside a single cooldown to pin the
        suppression itself: 20 connections at 60s span 19 minutes, well under 30.
        """
        alerts = sum(
            detector.observe(connection(index * 60)) is not None for index in range(20)
        )
        assert alerts == 1, "within one cooldown a live beacon must alert once"

    def test_out_of_order_events_are_rejected(self, detector: BeaconDetector) -> None:
        """Clock skew across hosts produces negative intervals, which would
        poison the statistics silently."""
        feed(detector, [0, 60, 120])
        assert detector.observe(connection(30)) is None  # arrives late

    def test_prune_drops_idle_channels(self) -> None:
        detector = BeaconDetector(window=timedelta(minutes=30))
        feed(detector, [0, 60, 120])
        assert detector.tracked_channels == 1

        removed = detector.prune(now=BASE + timedelta(hours=2))
        assert removed == 1
        assert detector.tracked_channels == 0

    def test_channels_are_scoped_per_host(self, detector: BeaconDetector) -> None:
        """Two hosts beaconing to the same C2 are two findings, not one."""
        feed(detector, [i * 60 for i in range(8)], host="WS-01")
        feed(detector, [i * 60 for i in range(8)], host="WS-02")
        assert detector.tracked_channels == 2
