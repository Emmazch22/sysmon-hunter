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
from backend.engine.correlator import IncidentEngine, ProcessTree
from backend.engine.matcher import evaluate
from backend.engine.normalizer import normalize
from backend.engine.rule_loader import rule_store
from backend.models import db
from backend.models.schemas import Detection, Event, Incident

log = logging.getLogger(__name__)


class Pipeline:
    """Stateful detection pipeline for a single collector."""

    def __init__(self) -> None:
        self.tree = ProcessTree(ttl=timedelta(minutes=settings.process_ttl_minutes))
        self.incidents = IncidentEngine(
            tree=self.tree,
            window=timedelta(minutes=settings.correlation_window_minutes),
            score_threshold=settings.incident_score_threshold,
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

        raised: list[Incident] = []
        for detection in detections:
            incident = self.incidents.correlate(detection)
            actionable = self.incidents.is_actionable(incident)

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
        from backend.api.ws import manager
        from backend.api.serializers import serialize_detection, serialize_incident

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
        }


# Module-level singleton. One collector, one pipeline.
pipeline = Pipeline()