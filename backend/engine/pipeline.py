"""The detection pipeline.

One place that owns the full path an event takes:

    normalize -> observe in process tree -> match rules -> correlate -> persist -> push

Keeping this out of the HTTP layer means the pipeline can be driven by anything:
the `/ingest` endpoint today, a Kafka consumer or the EVTX replay script
tomorrow, and pytest with no server running at all.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from backend.config import settings
from backend.engine.beacon import BeaconDetector
from backend.engine.correlator import IncidentEngine, ProcessTree
from backend.engine.discovery import DiscoveryDetector
from backend.engine.matcher import evaluate
from backend.engine.normalizer import normalize
from backend.engine.rule_loader import rule_store
from backend.models import db
from backend.models.schemas import Detection, Event, Incident

log = logging.getLogger(__name__)


class Pipeline:
    """Stateful detection pipeline for a single collector."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        """(Re)build every piece of in-memory engine state from scratch.

        Used both at construction and after an analyst wipes the database from
        the console. The two must go together: if the database were cleared
        but the live ProcessTree, IncidentEngine and detectors were left as
        they were, the engine would keep correlating new events against
        processes and incidents whose records no longer exist -- new
        detections would land on stale, now-invisible incident ids.
        """
        self.tree = ProcessTree(ttl=timedelta(minutes=settings.process_ttl_minutes))
        self.incidents = IncidentEngine(
            tree=self.tree,
            window=timedelta(minutes=settings.correlation_window_minutes),
            score_threshold=settings.incident_score_threshold,
        )
        self.beacons = BeaconDetector(
            min_connections=settings.beacon_min_connections,
            regularity_threshold=settings.beacon_regularity_threshold,
            min_interval_seconds=settings.beacon_min_interval_seconds,
            max_interval_seconds=settings.beacon_max_interval_seconds,
            window=timedelta(minutes=settings.beacon_window_minutes),
            cooldown=timedelta(minutes=settings.beacon_cooldown_minutes),
            excluded_images=settings.beacon_excluded_images,
        )
        # Shares the process tree with the incident engine -- discovery bursts
        # are grouped by tree root, so the detector needs the same ancestry view
        # the correlator uses.
        self.discovery = DiscoveryDetector(
            tree=self.tree,
            min_distinct=settings.discovery_min_distinct,
            window=timedelta(minutes=settings.discovery_window_minutes),
            cooldown=timedelta(minutes=settings.discovery_cooldown_minutes),
        )
        self._events_seen = 0

    async def process(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Run one raw payload through the pipeline.

        Returns a summary for the ingest response. Detections and incidents are
        persisted and broadcast as a side effect -- the caller does not have to
        do anything with the return value beyond echoing it back to the collector.
        """
        event = normalize(payload)
        self._events_seen += 1

        # Every event feeds the tree, not just the ones that trigger a rule. The
        # ancestry of a malicious process is made of benign parents, and if we
        # only recorded suspicious processes the chain would be full of holes.
        self.tree.observe(event)

        rules = rule_store.for_event(event.event_id)
        detections = evaluate(event, rules)

        # Statistical detection runs alongside the rule engine, not instead of
        # it. A beacon is invisible to any single-event rule -- the signal lives
        # in the intervals between events -- but once confirmed it becomes an
        # ordinary Detection and travels the same path as everything else:
        # correlated into the process tree, scored, persisted, pushed. That is
        # the whole point of making it a Detection rather than a special case.
        if settings.beacon_enabled:
            beacon = self.beacons.observe(event)
            if beacon is not None:
                detections.append(beacon)

        # Discovery runs on process creation, after the tree has observed the
        # event, so the burst can be attributed to the correct tree root.
        if settings.discovery_enabled:
            burst = self.discovery.observe(event)
            if burst is not None:
                detections.append(burst)

        raised: list[Incident] = []
        for detection in detections:
            incident = self.incidents.correlate(detection)
            actionable = self.incidents.is_actionable(incident)

            # Capture the full branching tree the incident spans, from the live
            # ProcessTree, before it is pruned. Refreshed on every detection so
            # it grows as the incident does.
            incident.process_tree = self.tree.subtree(incident.host, incident.root_guid)

            # Order matters: the incident row must exist before the detection
            # row that references it, or the foreign key has nothing to point at.
            await db.upsert_incident(incident, actionable=actionable)
            await db.save_detection(detection)

            await self._publish(detection, incident, actionable)
            raised.append(incident)

        return {
            "event_id": event.event_id,
            "host": event.host,
            "rules_evaluated": len(rules),
            "detections": [
                {
                    "rule_id": d.rule_id,
                    "title": d.title,
                    "severity": d.severity.value,
                    "incident_id": d.incident_id,
                }
                for d in detections
            ],
            "incidents": [
                {
                    "id": i.id,
                    "score": i.score,
                    "severity": i.severity.value,
                    "detection_count": len(i.detections),
                }
                for i in raised
            ],
        }

    async def _publish(
        self, detection: Detection, incident: Incident, actionable: bool
    ) -> None:
        """Push a detection and its incident to every connected console.

        Imported lazily: the WebSocket manager belongs to the API layer, and a
        module-level import here would make the pipeline depend on FastAPI --
        which would break the "runs under pytest with no server" property.
        """
        from backend.api.serializers import serialize_detection, serialize_incident
        from backend.api.ws import manager

        await manager.broadcast(
            {"type": "detection", "data": serialize_detection(detection)}
        )
        await manager.broadcast(
            {"type": "incident", "data": serialize_incident(incident, actionable)}
        )

    def sweep(self) -> int:
        """Housekeeping: close idle incidents and prune the process tree.

        Called on a timer from the app's background loop. Returns how many
        process nodes were evicted.
        """
        closed = self.incidents.sweep()
        pruned = self.tree.prune()
        pruned += self.beacons.prune()
        pruned += self.discovery.prune()
        if closed:
            log.info("Swept %d idle incident(s)", len(closed))
        return pruned

    @property
    def stats(self) -> dict[str, int]:
        """Live engine counters, surfaced on /health."""
        return {
            "events_seen": self._events_seen,
            "rules_loaded": len(rule_store.all),
            "processes_tracked": self.tree.size,
            "incidents_open": self.incidents.open_count,
            "channels_watched": self.beacons.tracked_channels,
            "recon_trees_watched": self.discovery.tracked_bursts,
        }


# Module-level singleton. One collector, one pipeline.
pipeline = Pipeline()
