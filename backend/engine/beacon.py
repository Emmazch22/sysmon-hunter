"""Beaconing detection.

No single event is suspicious here. A process opening one connection to one
address is the most ordinary thing on a Windows host. The signal is the *rhythm*:
implants call home on a timer, and a timer looks nothing like a human.

This is why beaconing cannot be a YAML rule. A rule matches one event against a
pattern; a beacon only exists across dozens of events, and the thing being
matched is the shape of the intervals between them.

Why this is not just "are the intervals equal":

    Every C2 framework worth the name applies jitter. Cobalt Strike's default is
    a sleep time reduced by up to 37% at random, so a 60-second beacon arrives
    somewhere in 38-60 seconds. Demanding identical intervals finds nothing real.
    What survives jitter is *bounded* variation: the intervals still cluster
    tightly around a centre, they just are not identical.

    So we measure regularity, not equality, and we measure it with the median
    and the median absolute deviation rather than the mean and the standard
    deviation. MAD is robust to outliers, and beacons produce outliers all the
    time -- the operator interacts with the session, the host sleeps, a retry
    fires late. One 400-second gap in a 60-second beacon wrecks a
    standard-deviation score. The median barely notices.
"""

from __future__ import annotations

import logging
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Optional

from backend.engine.net_scope import is_internal
from backend.models.schemas import Detection, Event, Severity, utcnow

log = logging.getLogger(__name__)

# Sysmon EventID 3: a process made an outbound network connection.
NETWORK_CONNECT = 3

# Synthetic rule identity. Beacons are not rule-driven, but they flow through the
# same Detection pipeline, so they need an id an analyst can recognise and a
# technique they can pivot on.
BEACON_RULE_ID = "BCN-001"
BEACON_TECHNIQUES = ["T1071.001", "T1573"]


def _basename(path: Optional[str]) -> str:
    """Bare executable name from a Windows path."""
    if not path:
        return "unknown"
    return path.replace("/", "\\").split("\\")[-1].lower()


def regularity(intervals: list[float]) -> float:
    """Score how metronomic a sequence of intervals is, from 0.0 to 1.0.

    Defined as `1 - (MAD / median)`, clamped to [0, 1].

    Reading the scale:

        1.00  identical intervals. A cron job, a health check, or an implant
              with jitter switched off.
        0.85  a 60-second beacon with the Cobalt Strike default 37% jitter --
              still obviously a machine.
        0.40  a chatty application: bursts, idle periods, retries.
        0.00  a human. Browsing has no rhythm at all.

    A median of zero (many connections in the same second) returns 0: that is a
    burst, not a beacon, and treating a divide-by-zero as maximal regularity
    would make every noisy application look like C2.
    """
    if len(intervals) < 2:
        return 0.0

    median = statistics.median(intervals)
    if median <= 0:
        return 0.0

    deviations = [abs(value - median) for value in intervals]
    mad = statistics.median(deviations)

    return max(0.0, min(1.0, 1.0 - (mad / median)))


class _Channel:
    """One (process, destination) pair, and the timestamps of its connections."""

    def __init__(self, capacity: int) -> None:
        self.timestamps: Deque[datetime] = deque(maxlen=capacity)
        self.process_guid: Optional[str] = None
        self.image: Optional[str] = None
        self.last_alert: Optional[datetime] = None

    def intervals(self) -> list[float]:
        """Seconds between each pair of successive connections."""
        stamps = list(self.timestamps)
        return [
            (later - earlier).total_seconds()
            for earlier, later in zip(stamps, stamps[1:])
        ]


class BeaconDetector:
    """Watches network connections for machine-like periodicity.

    State is bounded on both axes: each channel keeps at most `capacity`
    timestamps, and channels idle beyond the window are dropped. A detector that
    grows without limit is a detector that gets killed by the OOM reaper at 3am,
    which is precisely when the beacon it was tracking would have fired.
    """

    def __init__(
        self,
        min_connections: int = 6,
        min_periods: int = 5,
        max_interval_ratio: float = 4.0,
        regularity_threshold: float = 0.75,
        min_interval_seconds: float = 5.0,
        max_interval_seconds: float = 3600.0,
        window: timedelta = timedelta(hours=2),
        cooldown: timedelta = timedelta(minutes=30),
        excluded_images: Optional[list[str]] = None,
        capacity: int = 64,
    ) -> None:
        self._min_connections = min_connections
        # A beacon must be observed across at least this many of its own periods
        # before we believe it. Bursts are dense but brief; beacons are sparse
        # but sustained. This is what tells them apart.
        self._min_periods = min_periods
        # Largest tolerated ratio of the biggest interval to the median. Cobalt
        # Strike's 37% jitter keeps this near 1.6; a burst-and-idle pattern blows
        # straight past 4. This is the single most effective false-positive
        # filter in the detector.
        self._max_interval_ratio = max_interval_ratio
        self._threshold = regularity_threshold
        self._min_interval = min_interval_seconds
        self._max_interval = max_interval_seconds
        self._window = window
        self._cooldown = cooldown
        self._capacity = capacity

        # Processes whose periodic traffic is expected. This list is a liability
        # and should stay short: every entry is a place an implant can hide by
        # naming itself correctly. Prefer raising the regularity threshold over
        # adding to it.
        self._excluded = {name.lower() for name in (excluded_images or [])}

        # (host, image, destination_ip, destination_port) -> channel
        self._channels: dict[tuple[str, str, str, str], _Channel] = defaultdict(
            lambda: _Channel(self._capacity)
        )

    def observe(self, event: Event) -> Optional[Detection]:
        """Feed one network event in. Returns a Detection if a beacon is confirmed.

        Called for every EventID 3, which on a busy host is a lot of events, so
        the early exits below are ordered cheapest-first.
        """
        if event.event_id != NETWORK_CONNECT:
            return None

        image = _basename(event.image)
        if image in self._excluded:
            return None

        destination_ip = event.get("DestinationIp")
        destination_port = event.get("DestinationPort")
        if not destination_ip:
            return None

        key = (event.host, image, str(destination_ip), str(destination_port))
        channel = self._channels[key]

        # A connection arriving out of order (clock skew across hosts, a delayed
        # shipper) would produce a negative interval and poison the statistics.
        if channel.timestamps and event.timestamp < channel.timestamps[-1]:
            return None

        channel.timestamps.append(event.timestamp)
        channel.process_guid = event.process_guid or channel.process_guid
        channel.image = event.image or channel.image

        return self._assess(key, channel, event)

    def _assess(
        self,
        key: tuple[str, str, str, str],
        channel: _Channel,
        event: Event,
    ) -> Optional[Detection]:
        """Decide whether this channel has become a beacon."""
        if len(channel.timestamps) < self._min_connections:
            return None

        # Do not re-alert on a channel we already reported. The beacon will keep
        # beaconing; the analyst does not need to be told once a minute.
        if channel.last_alert and event.timestamp - channel.last_alert < self._cooldown:
            return None

        intervals = channel.intervals()
        median_interval = statistics.median(intervals)

        # Sub-second chatter is a streaming connection, not a beacon. Anything
        # slower than the ceiling is a scheduled task we cannot distinguish from
        # a low-and-slow implant on timing alone -- and flagging every Windows
        # Update check would drown the console.
        if not (self._min_interval <= median_interval <= self._max_interval):
            return None

        # A cluster of connections fired off in a few seconds -- a web page
        # loading a dozen resources -- has a tiny, uniform interval and so scores
        # as perfectly regular over a span of seconds. That is not a beacon; a
        # beacon persists. Requiring the observations to span several median
        # intervals means a page-load burst is dismissed while a genuine low-rate
        # callback, which by definition takes minutes to accumulate, is not.
        observed_span = (channel.timestamps[-1] - channel.timestamps[0]).total_seconds()
        if observed_span < median_interval * self._min_periods:
            return None

        # A page-load burst produces a median dragged low by a handful of
        # near-simultaneous connections, while the real gaps between page visits
        # are hundreds of seconds. The median absolute deviation misses this --
        # most intervals are tiny and identical, so it reads as regular -- but
        # the spread between the smallest and largest interval gives it away. No
        # jittered beacon swings across two orders of magnitude; a mix of bursts
        # and idle time does nothing else. Reject when the largest interval
        # dwarfs the median beyond what jitter can explain.
        if max(intervals) > median_interval * self._max_interval_ratio:
            return None

        score = regularity(intervals)
        if score < self._threshold:
            return None

        channel.last_alert = event.timestamp
        return self._build_detection(
            key, channel, event, intervals, median_interval, score
        )

    def _build_detection(
        self,
        key: tuple[str, str, str, str],
        channel: _Channel,
        event: Event,
        intervals: list[float],
        median_interval: float,
        score: float,
    ) -> Detection:
        """Package a confirmed beacon as a Detection.

        Severity rises with how machine-like the rhythm is, then is capped
        one band lower when the destination is internal (private, loopback,
        or link-local): a heartbeat to infrastructure inside the network and
        a callback leaving it can score identically on regularity alone, but
        they are not the same finding, and CRITICAL should mean "this host is
        very likely talking to an outside operator" rather than "a scheduled
        job runs on time" -- both of which produce a perfect rhythm. Internal
        destinations still alert, they just cannot reach CRITICAL on rhythm
        alone, since lateral C2 to a compromised internal host is real and
        should not be silenced outright.
        """
        _, image, destination_ip, destination_port = key
        internal = is_internal(str(destination_ip))

        if internal:
            severity = Severity.HIGH if score >= 0.92 else Severity.MEDIUM
        else:
            severity = Severity.CRITICAL if score >= 0.92 else Severity.HIGH

        log.info(
            "Beacon confirmed: %s -> %s:%s every ~%.0fs (regularity %.2f, %d connections)",
            image,
            destination_ip,
            destination_port,
            median_interval,
            score,
            len(channel.timestamps),
        )

        return Detection(
            rule_id=BEACON_RULE_ID,
            title=(
                f"Periodic outbound connection: {image} to {destination_ip}"
                f":{destination_port} every ~{median_interval:.0f}s"
            ),
            severity=severity,
            attack=BEACON_TECHNIQUES,
            event=event,
            matched_at=event.timestamp,
            # The numbers the analyst needs to judge the call themselves. A
            # beacon detection that says only "beacon detected" is not
            # actionable -- it is an assertion, and assertions do not survive
            # contact with a false positive.
            evidence={
                "destination": f"{destination_ip}:{destination_port}",
                "destination_scope": "internal" if internal else "external",
                "connections": len(channel.timestamps),
                "median_interval_seconds": round(median_interval, 1),
                "jitter_seconds": round(
                    statistics.median([abs(i - median_interval) for i in intervals]), 1
                ),
                "regularity": round(score, 3),
                "observed_over_seconds": round(sum(intervals)),
            },
        )

    def prune(self, now: Optional[datetime] = None) -> int:
        """Drop channels idle beyond the window. Returns how many were removed."""
        now = now or utcnow()
        cutoff = now - self._window

        stale = [
            key
            for key, channel in self._channels.items()
            if not channel.timestamps or channel.timestamps[-1] < cutoff
        ]
        for key in stale:
            del self._channels[key]

        return len(stale)

    @property
    def tracked_channels(self) -> int:
        """Number of (process, destination) pairs currently under observation."""
        return len(self._channels)
