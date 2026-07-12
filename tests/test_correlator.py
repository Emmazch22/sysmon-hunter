"""Process-tree and incident correlation.

The heart of the engine, and the part most likely to break subtly. These tests
build attack chains by hand and assert on the shape of the incident that comes
out the other side.
"""

from __future__ import annotations

from datetime import timedelta

from backend.models.schemas import Detection, Severity
from tests.conftest import make_event, make_rule


def detect(event, rule_id="R", severity=Severity.HIGH, attack=None, when=None):
    """Wrap an event in a detection, the way the pipeline does after a match."""
    return Detection(
        rule_id=rule_id,
        title=f"Detection {rule_id}",
        severity=severity,
        attack=attack or [],
        event=event,
        matched_at=when or event.timestamp,
    )


class TestProcessTree:
    def test_ancestry_is_root_first(self, tree, at) -> None:
        """The chain must read the way an analyst reads an attack:
        WINWORD -> cmd -> powershell, not the reverse."""
        tree.observe(make_event(guid="w", image=r"C:\O\WINWORD.EXE", timestamp=at(0)))
        tree.observe(make_event(guid="c", parent_guid="w", image=r"C:\W\cmd.exe", timestamp=at(1)))
        tree.observe(make_event(guid="p", parent_guid="c", image=r"C:\W\powershell.exe", timestamp=at(2)))

        chain = [node.name for node in tree.ancestry("LAB-WIN11", "p")]
        assert chain == ["WINWORD.EXE", "cmd.exe", "powershell.exe"]

    def test_root_is_topmost_known_ancestor(self, tree, at) -> None:
        tree.observe(make_event(guid="w", image="WINWORD.EXE", timestamp=at(0)))
        tree.observe(make_event(guid="c", parent_guid="w", image="cmd.exe", timestamp=at(1)))
        assert tree.root("LAB-WIN11", "c") == "w"

    def test_unknown_process_is_its_own_root(self, tree) -> None:
        """Correlation must degrade gracefully on a host where we only ever see
        leaf events -- the process is simply its own root."""
        assert tree.root("HOST", "ghost") == "ghost"

    def test_ancestry_stops_at_the_edge_of_knowledge(self, tree, at) -> None:
        """If the parent was created before the collector started, the walk ends
        there. An incomplete chain still beats no chain."""
        tree.observe(make_event(guid="c", parent_guid="missing", image="cmd.exe", timestamp=at(0)))
        chain = [node.name for node in tree.ancestry("LAB-WIN11", "c")]
        assert chain == ["cmd.exe"]

    def test_tree_is_scoped_per_host(self, tree, at) -> None:
        """Two hosts must never share a tree, even if a GUID happens to collide.
        Grafting host B's process under host A's root would invent an intrusion."""
        tree.observe(make_event(host="A", guid="x", image="a.exe", timestamp=at(0)))
        tree.observe(make_event(host="B", guid="x", image="b.exe", timestamp=at(0)))
        assert tree.ancestry("A", "x")[0].name == "a.exe"
        assert tree.ancestry("B", "x")[0].name == "b.exe"

    def test_later_events_backfill_missing_detail(self, tree, at) -> None:
        """A network event (EventID 3) references a process we already know from
        its creation event but carries no image itself. The known image must
        survive the update rather than being nulled out."""
        tree.observe(make_event(guid="p", image=r"C:\W\powershell.exe", timestamp=at(0)))
        tree.observe(make_event(event_id=3, guid="p", image=None, timestamp=at(5)))
        assert tree.ancestry("LAB-WIN11", "p")[0].name == "powershell.exe"

    def test_prune_evicts_stale_nodes(self, at) -> None:
        from backend.engine.correlator import ProcessTree

        tree = ProcessTree(ttl=timedelta(minutes=30))
        tree.observe(make_event(guid="old", image="old.exe", timestamp=at(0)))
        tree.observe(make_event(guid="new", image="new.exe", timestamp=at(3600)))
        removed = tree.prune(now=at(3600))
        assert removed == 1
        assert tree.size == 1


class TestIncidentCorrelation:
    def test_detections_on_one_tree_form_one_incident(self, incidents, tree, at) -> None:
        tree.observe(make_event(guid="w", image="WINWORD.EXE", timestamp=at(0)))
        tree.observe(make_event(guid="c", parent_guid="w", image="cmd.exe", timestamp=at(1)))
        tree.observe(make_event(guid="p", parent_guid="c", image="powershell.exe", timestamp=at(2)))

        i1 = incidents.correlate(detect(make_event(guid="c", parent_guid="w"), "SYS-001", when=at(1)))
        i2 = incidents.correlate(detect(make_event(guid="p", parent_guid="c"), "SYS-002", when=at(2)))

        assert i1.id == i2.id
        assert len(i2.detections) == 2

    def test_incident_chain_reflects_the_deepest_detection(self, incidents, tree, at) -> None:
        """When a later detection sits deeper in the tree than the one that
        opened the incident, the chain must grow to include it."""
        tree.observe(make_event(guid="w", image="WINWORD.EXE", timestamp=at(0)))
        tree.observe(make_event(guid="c", parent_guid="w", image="cmd.exe", timestamp=at(1)))
        tree.observe(make_event(guid="p", parent_guid="c", image="powershell.exe", timestamp=at(2)))

        incidents.correlate(detect(make_event(guid="c", parent_guid="w"), "SYS-001", when=at(1)))
        incident = incidents.correlate(detect(make_event(guid="p", parent_guid="c"), "SYS-002", when=at(2)))
        assert incident.chain == ["WINWORD.EXE", "cmd.exe", "powershell.exe"]

    def test_separate_trees_form_separate_incidents(self, incidents, tree, at) -> None:
        tree.observe(make_event(guid="a", image="a.exe", timestamp=at(0)))
        tree.observe(make_event(guid="b", image="b.exe", timestamp=at(0)))
        i1 = incidents.correlate(detect(make_event(guid="a"), when=at(0)))
        i2 = incidents.correlate(detect(make_event(guid="b"), when=at(0)))
        assert i1.id != i2.id

    def test_quiet_period_opens_a_fresh_incident(self, incidents, tree, at) -> None:
        """A host compromised twice in a day must report two incidents, not one
        meaningless incident spanning both. The correlation window is what
        separates them."""
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        first = incidents.correlate(detect(make_event(guid="p"), "SYS-001", when=at(0)))
        # 11 minutes later, past the 10-minute window.
        second = incidents.correlate(detect(make_event(guid="p"), "SYS-001", when=at(660)))
        assert first.id != second.id


class TestActionability:
    def test_critical_detection_is_immediately_actionable(self, incidents, tree, at) -> None:
        """LSASS access does not wait for a second opinion."""
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        incident = incidents.correlate(
            detect(make_event(guid="p"), "SYS-010", severity=Severity.CRITICAL, when=at(0))
        )
        assert incidents.is_actionable(incident)

    def test_a_single_medium_detection_is_not_actionable(self, incidents, tree, at) -> None:
        """One moderate finding is a lead, not an alert. This is the noise the
        threshold exists to hold back."""
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        incident = incidents.correlate(
            detect(make_event(guid="p"), "SYS-050", severity=Severity.MEDIUM, when=at(0))
        )
        assert not incidents.is_actionable(incident)

    def test_accumulated_score_crosses_threshold(self, incidents, tree, at) -> None:
        """Three mediums (15) outweigh the threshold (12) together, though none
        would alone."""
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        incident = None
        for index in range(3):
            incident = incidents.correlate(
                detect(make_event(guid="p"), f"SYS-{index}", severity=Severity.MEDIUM, when=at(index))
            )
        assert incident.score == 15
        assert incidents.is_actionable(incident)

    def test_three_detections_are_actionable_by_volume(self, incidents, tree, at) -> None:
        """Volume in one process chain is itself a signal, whatever the
        individual severities."""
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        incident = None
        for index in range(3):
            incident = incidents.correlate(
                detect(make_event(guid="p"), f"SYS-{index}", severity=Severity.LOW, when=at(index))
            )
        assert len(incident.detections) == 3
        assert incidents.is_actionable(incident)


class TestIncidentScoring:
    def test_severity_derives_from_cumulative_score(self, incidents, tree, at) -> None:
        """An incident's severity is a property of the whole, not of any one rule
        -- two highs should read as more urgent than either high alone."""
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        incidents.correlate(detect(make_event(guid="p"), "A", severity=Severity.HIGH, when=at(0)))
        incident = incidents.correlate(detect(make_event(guid="p"), "B", severity=Severity.HIGH, when=at(1)))
        assert incident.score == 16
        assert incident.severity is Severity.CRITICAL

    def test_techniques_are_deduplicated_and_sorted(self, incidents, tree, at) -> None:
        tree.observe(make_event(guid="p", image="powershell.exe", timestamp=at(0)))
        incidents.correlate(detect(make_event(guid="p"), "A", attack=["T1059", "T1027"], when=at(0)))
        incident = incidents.correlate(detect(make_event(guid="p"), "B", attack=["T1059", "T1003"], when=at(1)))
        assert incident.techniques == ["T1003", "T1027", "T1059"]