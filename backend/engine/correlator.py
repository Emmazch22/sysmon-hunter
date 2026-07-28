"""Process-tree correlation.

This module is what separates a rule matcher from a hunting tool. A matcher
answers "did anything suspicious happen?"; a correlator answers "is this the
same thing happening, and how bad has it gotten?"

Two pieces:

* `ProcessTree` reconstructs parent/child relationships from Sysmon's
  ProcessGuid and ParentProcessGuid fields, per host. It is populated by every
  process-creation event, not just the ones that trigger a rule, because the
  ancestry of a malicious process is usually made of perfectly benign parents.

* `IncidentEngine` groups detections that share a tree root inside a sliding
  time window, accumulating a score. A lone medium detection stays a lead; the
  same detection under a WINWORD.EXE root next to an outbound connection
  becomes an incident that an analyst should look at now.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from backend.models.schemas import (
    Detection,
    Event,
    Incident,
    ProcessNode,
    Severity,
    utcnow,
)

log = logging.getLogger(__name__)

# Guard against cycles or absurdly deep chains from malformed telemetry. Real
# ancestry on Windows rarely exceeds a handful of levels.
MAX_ANCESTRY_DEPTH = 24


class ProcessTree:
    """In-memory parent/child map of every process we have observed.

    Keyed by (host, process_guid). GUIDs are used rather than PIDs because
    Windows recycles PIDs aggressively; a PID-keyed tree will happily graft a
    malicious child onto whatever unrelated process inherited its parent's PID.
    """

    def __init__(self, ttl: timedelta) -> None:
        self._nodes: dict[tuple[str, str], ProcessNode] = {}
        # (host, parent_guid) -> child guids, maintained incrementally so that
        # subtree() never has to rescan every node this tree has ever seen --
        # see subtree()'s docstring for why that rescan used to be the cost.
        self._children: dict[tuple[str, str], list[str]] = {}
        self._ttl = ttl

    def observe(self, event: Event) -> ProcessNode | None:
        """Record (or refresh) the process this event came from.

        Returns the node, or None if the event carries no process identity --
        some Sysmon event types legitimately do not.
        """
        if not event.process_guid:
            return None

        key = (event.host, event.process_guid)
        node = self._nodes.get(key)

        if node is None:
            node = ProcessNode(
                guid=event.process_guid,
                parent_guid=event.parent_process_guid,
                host=event.host,
                image=event.image,
                command_line=event.command_line,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
            self._nodes[key] = node
            if node.parent_guid:
                self._children.setdefault(
                    (event.host, node.parent_guid), []
                ).append(node.guid)
        else:
            # Later events (network, image load) reference a process we already
            # know from its creation event. Refresh liveness, and backfill any
            # detail the earlier event happened to omit.
            node.last_seen = max(node.last_seen, event.timestamp)
            node.image = node.image or event.image
            node.command_line = node.command_line or event.command_line
            if not node.parent_guid and event.parent_process_guid:
                node.parent_guid = event.parent_process_guid
                self._children.setdefault(
                    (event.host, node.parent_guid), []
                ).append(node.guid)

        return node

    def ancestry(self, host: str, guid: str) -> list[ProcessNode]:
        """Walk from a process up to the highest ancestor we know about.

        Returned root-first, so the list reads the way an analyst reads an
        attack chain: WINWORD.EXE -> cmd.exe -> powershell.exe.

        The chain stops wherever our knowledge stops. If the parent was created
        before the collector started, the walk simply ends there -- an
        incomplete chain is still far more useful than none.
        """
        chain: list[ProcessNode] = []
        seen: set[str] = set()
        current: str | None = guid

        while current and current not in seen and len(chain) < MAX_ANCESTRY_DEPTH:
            seen.add(current)
            node = self._nodes.get((host, current))
            if node is None:
                break
            chain.append(node)
            current = node.parent_guid

        chain.reverse()
        return chain

    def root(self, host: str, guid: str) -> str:
        """GUID of the topmost known ancestor, used as the correlation key.

        If nothing is known about the process, it is its own root. That keeps
        correlation working (degraded but correct) on hosts where we only ever
        see leaf events.
        """
        chain = self.ancestry(host, guid)
        return chain[0].guid if chain else guid

    def subtree(self, host: str, root_guid: str) -> list[dict]:
        """Export every process descended from a root, as flat node records.

        This is the whole tree an incident spans, not just the ancestry chain of
        the one process that triggered a detection -- so a foothold that spawned
        three separate children shows all three branches, which is the real shape
        of what the malware did.

        Returned flat (each node carries its parent_guid) rather than nested, so
        the caller can build whatever structure it needs and the result serializes
        cleanly to JSON for storage. Benign intermediate processes are included:
        they are the branches, and a tree with holes where the quiet processes
        were is not a tree.
        """
        # The child-index (self._children) is maintained incrementally by
        # observe(), so walking down from the root costs work proportional to
        # the subtree itself, not to every process this host has ever run --
        # it used to rebuild that index from the full node table on every
        # call, which made a large, long-lived tree get slower to explore the
        # longer the process had been running.
        out: list[dict] = []
        seen: set[str] = set()
        stack = [root_guid]
        while stack:
            guid = stack.pop()
            if guid in seen:
                continue
            seen.add(guid)

            node = self._nodes.get((host, guid))
            if node is not None:
                out.append(
                    {
                        "guid": node.guid,
                        "parent_guid": node.parent_guid,
                        "image": node.image,
                        "name": node.name,
                        "command_line": node.command_line,
                        # Timestamps, so a node's popup has something to show
                        # even when it never fired a detection -- a benign
                        # context process is still worth knowing *when* it ran.
                        "first_seen": node.first_seen.isoformat(),
                        "last_seen": node.last_seen.isoformat(),
                    }
                )
            for child_guid in self._children.get((host, guid), []):
                stack.append(child_guid)

        return out

    def prune(self, now: datetime | None = None) -> int:
        """Drop nodes not seen within the TTL. Returns how many were removed.

        Without this the tree grows for the lifetime of the process. Called on a
        schedule from the app's background loop.
        """
        now = now or utcnow()
        cutoff = now - self._ttl
        stale = [key for key, node in self._nodes.items() if node.last_seen < cutoff]
        for key in stale:
            node = self._nodes.pop(key)
            host, guid = key
            # Drop this node's own children bucket, and remove it from its
            # parent's -- otherwise a pruned guid lingers forever inside
            # _children, a slow leak the node table itself doesn't have.
            self._children.pop((host, guid), None)
            if node.parent_guid:
                siblings = self._children.get((host, node.parent_guid))
                if siblings:
                    try:
                        siblings.remove(guid)
                    except ValueError:
                        pass
                    if not siblings:
                        del self._children[(host, node.parent_guid)]
        if stale:
            log.debug("Pruned %d stale process nodes", len(stale))
        return len(stale)

    @property
    def size(self) -> int:
        """Number of processes currently held in memory."""
        return len(self._nodes)


class IncidentEngine:
    """Groups detections into incidents by shared process-tree root.

    An incident is opened when a detection arrives whose root has no open
    incident, and stays open as long as new detections keep landing inside the
    correlation window. Once the window elapses with no activity, it is closed
    and a later detection on the same root opens a fresh one -- otherwise a host
    that is compromised twice in a day would report a single, meaningless
    incident spanning both.
    """

    def __init__(
        self,
        tree: ProcessTree,
        window: timedelta,
        score_threshold: int,
    ) -> None:
        self._tree = tree
        self._window = window
        self._threshold = score_threshold

        # Open incidents, keyed by (host, root_guid).
        self._open: dict[tuple[str, str], Incident] = {}
        # Everything ever raised, newest last. Swapped for the DB in the API layer;
        # kept here so the engine can be unit-tested with no database at all.
        self._history: list[Incident] = []

    def correlate(self, detection: Detection) -> Incident:
        """Attach a detection to an incident, opening one if necessary.

        Always returns an incident -- even a single detection belongs to one.
        Whether it is worth an analyst's attention is decided by `is_actionable`,
        not by whether an incident object exists.
        """
        event = detection.event
        guid = event.process_guid or f"orphan:{event.host}:{detection.rule_id}"
        root = self._tree.root(event.host, guid)
        key = (event.host, root)

        incident = self._open.get(key)

        # Reopen as a new incident if the previous one went quiet for longer
        # than the correlation window.
        if incident and detection.matched_at - incident.last_seen > self._window:
            self._close(key)
            incident = None

        if incident is None:
            chain = self._tree.ancestry(event.host, guid)
            incident = Incident(
                host=event.host,
                root_guid=root,
                root_image=chain[0].image if chain else event.parent_image,
                chain=[node.name for node in chain] or self._fallback_chain(event),
                first_seen=detection.matched_at,
                last_seen=detection.matched_at,
            )
            self._open[key] = incident
            self._history.append(incident)
        else:
            # An existing incident grows: refresh the chain, since this
            # detection may sit deeper in the tree than the one that opened it.
            chain = self._tree.ancestry(event.host, guid)
            if len(chain) > len(incident.chain):
                incident.chain = [node.name for node in chain]

        incident.add(detection)
        return incident

    def is_actionable(self, incident: Incident) -> bool:
        """Should this incident surface as an alert rather than a lead?

        Three independent triggers, any of which is enough:

        1. Cumulative score crossed the threshold -- several moderate findings
           in one tree are collectively worse than any of them alone.
        2. A critical detection landed -- LSASS access does not wait for a
           second opinion.
        3. Three or more detections in the same tree -- volume in a single
           process chain is itself a signal, whatever the individual severities.
        """
        if incident.score >= self._threshold:
            return True
        if any(d.severity is Severity.CRITICAL for d in incident.detections):
            return True
        return len(incident.detections) >= 3

    def sweep(self, now: datetime | None = None) -> list[Incident]:
        """Close incidents idle for longer than the window. Returns the closed ones."""
        now = now or utcnow()
        expired = [
            key
            for key, incident in self._open.items()
            if now - incident.last_seen > self._window
        ]
        return [self._close(key) for key in expired]

    def _close(self, key: tuple[str, str]) -> Incident:
        """Remove an incident from the open set. It stays in history."""
        incident = self._open.pop(key)
        log.info(
            "Incident %s closed on %s: %d detections, score %d",
            incident.id,
            incident.host,
            len(incident.detections),
            incident.score,
        )
        return incident

    @staticmethod
    def _fallback_chain(event: Event) -> list[str]:
        """Best-effort chain when the process tree knows nothing about the event.

        Rather than showing an empty chain, fall back to the parent/child image
        names carried on the event itself. Degraded, but still answers the first
        question an analyst asks.
        """

        def basename(path: str | None) -> str | None:
            if not path:
                return None
            return path.replace("/", "\\").split("\\")[-1]

        return [
            name
            for name in (basename(event.parent_image), basename(event.image))
            if name
        ]

    @property
    def open_count(self) -> int:
        """Number of incidents currently accepting new detections."""
        return len(self._open)

    @property
    def history(self) -> list[Incident]:
        """Every incident raised this session, oldest first."""
        return list(self._history)
