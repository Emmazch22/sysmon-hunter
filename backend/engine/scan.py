"""Network scan detection.

Beaconing (`engine/beacon.py`) looks at *rhythm*: one process, one destination,
many connections, evenly spaced. Discovery (`engine/discovery.py`) looks at
*command variety*: several different recon commands in one process tree. Neither
sees a scanner, because a scanner is neither periodic nor does it run
`whoami`-style commands -- it just opens a lot of connections, to a lot of
different places, fast.

That is the signal here: *breadth*, not rhythm. A normal process touches a
small, stable set of destinations -- a browser talks to a handful of CDNs, a
service talks to its database. A port scan or host sweep touches dozens of
distinct IP:port pairs from one process in a matter of seconds, and that
breadth is visible on Sysmon EventID 3 with no need to understand what the
process is or what command line launched it.

Two shapes are covered, because real scanning tools produce either or both:

    Port scan (vertical):  one host, many ports.    nmap -p1-1000 10.0.0.5
    Host sweep (horizontal): one port, many hosts.  nmap -p445 10.0.0.0/24

Demanding both at once would miss the common case of a single-host port scan,
so either threshold alone is sufficient to fire; ATT&CK tagging reflects
whichever shape (or both) was actually observed.

Why this cannot be a YAML rule: the same reason as beaconing and discovery. A
rule matches one event; a scan only exists across dozens of them, and the
thing being measured -- how many distinct destinations one process has
touched -- has no meaning for a single connection in isolation.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from backend.engine.net_scope import is_internal
from backend.models.schemas import Detection, Event, Severity, utcnow

log = logging.getLogger(__name__)

# Sysmon EventID 3: a process made an outbound network connection.
NETWORK_CONNECT = 3

SCAN_RULE_ID = "SCN-001"

# T1018 (Remote System Discovery) is added dynamically, only when the observed
# shape is a host sweep -- see _build_detection. T1046 applies to both shapes.
SCAN_BASE_TECHNIQUES = ["T1046"]


def _basename(path: Optional[str]) -> str:
    """Bare executable name from a Windows path."""
    if not path:
        return "unknown"
    return path.replace("/", "\\").split("\\")[-1].lower()


class _Scan:
    """One process's outbound connections, as a growing set of distinct
    destinations rather than a timing sequence -- breadth is the signal here,
    not rhythm, so what is tracked is *which* IP:port pairs were touched, each
    with its own last-seen timestamp so it can age out of the window on its
    own."""

    def __init__(self) -> None:
        self.destinations: dict[tuple[str, str], datetime] = {}
        self.process_guid: Optional[str] = None
        self.image: Optional[str] = None
        self.last_alert: Optional[datetime] = None

    def distinct_ips(self) -> int:
        return len({ip for ip, _port in self.destinations})

    def distinct_ports(self) -> int:
        return len({port for _ip, port in self.destinations})

    def span(self) -> float:
        """Seconds between the first and most recent connection touched."""
        if len(self.destinations) < 2:
            return 0.0
        stamps = list(self.destinations.values())
        return (max(stamps) - min(stamps)).total_seconds()

    def all_internal(self) -> bool:
        """Is every distinct destination IP touched so far private, loopback,
        or link-local? A single destination reaching outside the network is
        enough to call the whole scan external -- see _build_detection for
        why that asymmetry is deliberate."""
        return all(is_internal(ip) for ip, _port in self.destinations)


class ScanDetector:
    """Watches network connections for one process fanning out to many
    destinations in a short window.

    State is bounded the same way beacon.py's is: scans idle beyond the window
    are pruned, and destinations within a scan age out individually so a slow
    trickle of connections spread over hours never accumulates into a phantom
    scan.
    """

    def __init__(
        self,
        min_distinct_ips: int = 10,
        min_distinct_ports: int = 15,
        window: timedelta = timedelta(minutes=5),
        cooldown: timedelta = timedelta(minutes=15),
        excluded_images: Optional[list[str]] = None,
    ) -> None:
        # Distinct destination IPs from one process that constitute a host
        # sweep. Ten is well beyond what any normal client touches in five
        # minutes -- a browser's connection pool to a handful of CDN edges
        # does not come close.
        self._min_distinct_ips = min_distinct_ips
        # Distinct destination ports against (collectively) few hosts that
        # constitute a port scan. Higher than min_distinct_ips because a
        # single legitimate multi-service handshake (a deploy script hitting
        # a handful of ports on one box) is more common than a client
        # touching ten hosts, so the port axis needs a larger margin.
        self._min_distinct_ports = min_distinct_ports
        self._window = window
        self._cooldown = cooldown

        # Processes whose fan-out is expected, e.g. proxies and update
        # services that legitimately open many short-lived connections. Keep
        # this list short for the same reason beacon.py's is: every entry is
        # a place a real scanner can hide by naming itself correctly.
        self._excluded = {name.lower() for name in (excluded_images or [])}

        # (host, image, process_guid) -> scan. Grouped per scanning process,
        # not per tree root: a scanner is ordinarily one process making all
        # of its own connections, unlike discovery bursts which are commonly
        # spread across a shell's children.
        self._scans: dict[tuple[str, str, str], _Scan] = defaultdict(_Scan)

    def observe(self, event: Event) -> Optional[Detection]:
        """Feed one network event in. Returns a Detection if a scan is confirmed."""
        if event.event_id != NETWORK_CONNECT:
            return None

        image = _basename(event.image)
        if image in self._excluded:
            return None

        destination_ip = event.get("DestinationIp")
        destination_port = event.get("DestinationPort")
        if not destination_ip:
            return None

        guid = event.process_guid or f"orphan:{event.host}"
        key = (event.host, image, guid)
        scan = self._scans[key]
        scan.process_guid = event.process_guid or scan.process_guid
        scan.image = event.image or scan.image

        # Drop destinations that have aged out of the window before counting,
        # so connections trickling in over hours never accumulate into a
        # phantom scan.
        self._expire(scan, now=event.timestamp)
        scan.destinations[(str(destination_ip), str(destination_port))] = event.timestamp

        return self._assess(scan, event)

    def _expire(self, scan: _Scan, now: datetime) -> None:
        """Forget destinations last touched before the window opened."""
        cutoff = now - self._window
        scan.destinations = {
            dest: ts for dest, ts in scan.destinations.items() if ts >= cutoff
        }

    def _assess(self, scan: _Scan, event: Event) -> Optional[Detection]:
        """Decide whether the accumulated breadth is a scan worth reporting."""
        distinct_ips = scan.distinct_ips()
        distinct_ports = scan.distinct_ports()

        is_sweep = distinct_ips >= self._min_distinct_ips
        is_port_scan = distinct_ports >= self._min_distinct_ports
        if not (is_sweep or is_port_scan):
            return None

        # Do not re-alert on a process we already reported. It will keep
        # scanning; the analyst does not need to be told on every connection.
        if scan.last_alert and event.timestamp - scan.last_alert < self._cooldown:
            return None

        scan.last_alert = event.timestamp
        return self._build_detection(scan, event, is_sweep, is_port_scan)

    def _build_detection(
        self, scan: _Scan, event: Event, is_sweep: bool, is_port_scan: bool
    ) -> Detection:
        """Package a confirmed scan as a Detection.

        Severity rises when the breadth is far past the threshold -- a process
        that has already doubled the bar it needed to clear is not an edge
        case, it is a scanner running to completion -- then is capped one
        band lower when every destination touched is internal (private,
        loopback, or link-local): an internal-only vulnerability scanner or
        asset-inventory agent (Nessus, SCCM, and similar) produces the exact
        same breadth pattern as a real lateral-movement sweep, since both are
        "one process, many internal hosts, fast." This is a real trade-off,
        not a clean win the way it is for beacon.py's internal/external split
        -- an attacker's own internal host sweep is T1018/T1046 itself, the
        core technique this detector exists to catch, so capping it below
        CRITICAL does mean a genuine lateral-movement scan can land on HIGH
        instead. It still alerts, and the evidence still says exactly which
        destinations were touched; the trade is fewer CRITICAL pages from
        routine internal scanning tools against a small chance of under
        -stating a real one. A single destination reaching outside the
        network is enough to call the whole scan external and skip the cap,
        since no legitimate internal-only scanner mixes in random internet
        addresses.
        """
        distinct_ips = scan.distinct_ips()
        distinct_ports = scan.distinct_ports()
        image = _basename(scan.image)
        internal = scan.all_internal()

        techniques = list(SCAN_BASE_TECHNIQUES)
        if is_sweep:
            techniques.append("T1018")

        if is_sweep and is_port_scan:
            shape = "network scan"
        elif is_sweep:
            shape = "host sweep"
        else:
            shape = "port scan"

        past_double = (
            distinct_ips >= self._min_distinct_ips * 2
            or distinct_ports >= self._min_distinct_ports * 2
        )
        if internal:
            severity = Severity.HIGH if past_double else Severity.MEDIUM
        else:
            severity = Severity.CRITICAL if past_double else Severity.HIGH

        sample = sorted(f"{ip}:{port}" for ip, port in scan.destinations)[:10]

        log.info(
            "Scan confirmed: %s on %s touched %d host(s) / %d port(s) in %.0fs (%s)",
            image,
            event.host,
            distinct_ips,
            distinct_ports,
            scan.span(),
            shape,
        )

        return Detection(
            rule_id=SCAN_RULE_ID,
            title=(
                f"Network {shape}: {image} reached {distinct_ips} distinct "
                f"host(s) and {distinct_ports} distinct port(s) in "
                f"{scan.span():.0f}s"
            ),
            severity=severity,
            attack=techniques,
            # The finding is about the set of destinations, not any single
            # connection, so the triggering event's own destination fields
            # would mislead an analyst into thinking that one connection was
            # the whole story. The full sample lives in the evidence panel.
            event=event,
            matched_at=event.timestamp,
            evidence={
                "distinct_ips": distinct_ips,
                "distinct_ports": distinct_ports,
                "distinct_pairs": len(scan.destinations),
                "span_seconds": round(scan.span()),
                "sample_destinations": sample,
                "image": image,
                "destination_scope": "internal" if internal else "external",
            },
        )

    def prune(self, now: Optional[datetime] = None) -> int:
        """Drop scans whose destinations have entirely aged out. Returns count removed."""
        now = now or utcnow()
        cutoff = now - self._window

        stale = [
            key
            for key, scan in self._scans.items()
            if not scan.destinations or max(scan.destinations.values()) < cutoff
        ]
        for key in stale:
            del self._scans[key]
        return len(stale)

    @property
    def tracked_scans(self) -> int:
        """Number of (host, image, process) scanning processes under observation."""
        return len(self._scans)
