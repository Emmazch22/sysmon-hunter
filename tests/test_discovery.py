"""Discovery-burst detection.

The design commitment under test: variety, not volume. A script hammering one
recon command is not a burst; an attacker running several different ones is. The
tests that pin this down are the ones where volume is high but variety is low —
those must stay quiet.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.engine.correlator import ProcessTree
from backend.engine.discovery import DiscoveryDetector, classify
from backend.models.schemas import Event, Severity

BASE = datetime(2026, 7, 12, 10, 0, 0, tzinfo=timezone.utc)


def proc(
    command_line: str,
    offset_seconds: float = 0,
    guid: str = "{shell}",
    parent_guid: str = "{foothold}",
    host: str = "LAB-WIN11",
    image: str = r"C:\Windows\System32\cmd.exe",
) -> Event:
    """One process-creation event running a command."""
    return Event(
        event_id=1,
        host=host,
        image=image,
        command_line=command_line,
        process_guid=guid,
        parent_process_guid=parent_guid,
        timestamp=BASE + timedelta(seconds=offset_seconds),
    )


@pytest.fixture
def tree() -> ProcessTree:
    """A tree with a root foothold, so bursts have an ancestry to group under."""
    tree = ProcessTree(ttl=timedelta(hours=1))
    tree.observe(
        Event(
            event_id=1,
            host="LAB-WIN11",
            image=r"C:\Temp\payload.exe",
            process_guid="{foothold}",
            timestamp=BASE,
        )
    )
    tree.observe(
        Event(
            event_id=1,
            host="LAB-WIN11",
            image=r"C:\Windows\System32\cmd.exe",
            process_guid="{shell}",
            parent_process_guid="{foothold}",
            timestamp=BASE,
        )
    )
    return tree


@pytest.fixture
def detector(tree: ProcessTree) -> DiscoveryDetector:
    return DiscoveryDetector(tree=tree, min_distinct=4, window=timedelta(minutes=5))


def feed(detector: DiscoveryDetector, commands: list[tuple[str, float]], **kwargs):
    """Push (command, offset) pairs; return the last detection if any."""
    result = None
    for command, offset in commands:
        found = detector.observe(proc(command, offset, **kwargs))
        if found is not None:
            result = found
    return result


class TestClassification:
    def test_recognizes_the_staple_recon_commands(self) -> None:
        assert classify("whoami /all")[0] == "T1033"
        assert classify('net group "domain admins" /domain')[0] == "T1069"
        assert classify("systeminfo")[0] == "T1082"
        assert classify("nltest /domain_trusts")[0] == "T1069"
        assert classify("ipconfig /all")[0] == "T1016"

    def test_recognizes_lolbin_equivalents(self) -> None:
        """Attackers reach for PowerShell and wmic precisely because they look
        less alarming than the native tools. The classifier must see through
        that or it only catches the careless."""
        assert classify("Get-ADUser -Filter *")[0] == "T1087"
        assert classify("wmic os get caption")[0] == "T1082"
        assert classify("Get-NetIPConfiguration")[0] == "T1016"

    def test_ignores_benign_commands(self) -> None:
        assert classify(r"notepad.exe C:\notes.txt") is None
        assert classify("git status") is None
        assert classify(None) is None


class TestBurstDetection:
    def test_four_distinct_techniques_is_a_burst(
        self, detector: DiscoveryDetector
    ) -> None:
        """The core case: a foothold fingerprinting a host."""
        detection = feed(
            detector,
            [
                ("whoami", 0),
                ("net user", 10),
                ("systeminfo", 20),
                ("nltest /domain_trusts", 30),
            ],
        )
        assert detection is not None
        assert detection.rule_id == "DSC-001"
        assert detection.evidence["distinct_techniques"] == 4

    def test_severity_scales_with_breadth(self, tree: ProcessTree) -> None:
        """Five or more distinct techniques is methodical enumeration and reads
        as high, not medium.

        The threshold is raised to 5 here so the alert fires on the fifth
        command rather than the fourth -- with the default threshold of 4 the
        cooldown would suppress the fifth and we would never see the high band.
        """
        detector = DiscoveryDetector(
            tree=tree, min_distinct=5, window=timedelta(minutes=5)
        )
        detection = feed(
            detector,
            [
                ("whoami", 0),
                ("net user", 5),
                ("systeminfo", 10),
                ("ipconfig /all", 15),
                ("net view", 20),
            ],
        )
        assert detection is not None
        assert detection.evidence["distinct_techniques"] == 5
        assert detection.severity is Severity.HIGH

    def test_burst_is_grouped_across_child_processes(self, tree: ProcessTree) -> None:
        """The recon runs in different children of the foothold, not one process.
        Grouping by tree root is what lets the detector see one burst instead of
        four unrelated single commands."""
        tree.observe(proc("", guid="{c1}", parent_guid="{shell}"))
        tree.observe(proc("", guid="{c2}", parent_guid="{shell}"))
        detector = DiscoveryDetector(tree=tree, min_distinct=4)

        detector.observe(proc("whoami", 0, guid="{c1}", parent_guid="{shell}"))
        detector.observe(proc("net user", 5, guid="{c2}", parent_guid="{shell}"))
        detector.observe(proc("systeminfo", 10, guid="{c1}", parent_guid="{shell}"))
        result = detector.observe(
            proc("nltest /domain_trusts", 15, guid="{c2}", parent_guid="{shell}")
        )

        assert result is not None
        assert result.evidence["distinct_techniques"] == 4

    def test_evidence_carries_sample_commands(
        self, detector: DiscoveryDetector
    ) -> None:
        detection = feed(
            detector,
            [
                ("whoami /all", 0),
                ("net user", 10),
                ("systeminfo", 20),
                ("nltest /domain_trusts", 30),
            ],
        )
        assert detection is not None
        assert "whoami /all" in detection.evidence["commands"]
        assert detection.evidence["span_seconds"] == 30


class TestDistinctnessRequirement:
    """Variety, not volume — the decision this detector is built around."""

    def test_repeating_one_command_is_never_a_burst(
        self, detector: DiscoveryDetector
    ) -> None:
        """A monitoring script running systeminfo on a loop produces volume and
        no variety. It must stay silent no matter how many times it runs."""
        result = feed(detector, [("systeminfo", i * 10) for i in range(20)])
        assert result is None

    def test_two_techniques_repeated_is_not_enough(
        self, detector: DiscoveryDetector
    ) -> None:
        """Even two distinct commands, hammered, fall short of the threshold.
        The bar is breadth of recon, not activity."""
        commands = []
        for i in range(10):
            commands.append(("whoami", i * 20))
            commands.append(("ipconfig", i * 20 + 5))
        assert feed(detector, commands) is None

    def test_same_technique_via_different_syntax_counts_once(
        self, detector: DiscoveryDetector
    ) -> None:
        """`net user` and `net group` are both account discovery (T1087). Hitting
        both is one kind of recon, not two -- otherwise the distinctness
        guarantee leaks."""
        result = feed(
            detector,
            [
                ("net user", 0),
                ("net group", 5),
                ("net localgroup", 10),
                ("net accounts", 15),
            ],
        )
        assert result is None  # four commands, one technique


class TestWindowing:
    def test_recon_outside_the_window_does_not_accumulate(
        self, detector: DiscoveryDetector
    ) -> None:
        """A slow trickle -- one command every few minutes -- must never add up
        into a phantom burst. Each new command ages out the ones before it."""
        result = feed(
            detector,
            [
                ("whoami", 0),
                ("net user", 200),  # 3m20s
                ("systeminfo", 400),  # 6m40s -- first has aged out
                ("nltest /domain_trusts", 600),  # 10m -- second has aged out
            ],
        )
        assert result is None

    def test_cooldown_suppresses_repeat_alerts(
        self, detector: DiscoveryDetector
    ) -> None:
        """A burst in progress alerts once, not on every further recon command."""
        alerts = 0
        for i in range(8):
            commands = [
                ("whoami", i * 60),
                ("net user", i * 60 + 5),
                ("systeminfo", i * 60 + 10),
                ("nltest /dclist:x", i * 60 + 15),
            ]
            for cmd, off in commands:
                if detector.observe(proc(cmd, off)) is not None:
                    alerts += 1
        assert alerts == 1

    def test_bursts_are_scoped_per_host(self, tree: ProcessTree) -> None:
        """Two hosts each doing light recon are not one burst spanning both."""
        detector = DiscoveryDetector(tree=tree, min_distinct=4)
        detector.observe(proc("whoami", 0, host="WS-01", guid="{a}", parent_guid=None))
        detector.observe(
            proc("net user", 5, host="WS-02", guid="{b}", parent_guid=None)
        )
        assert detector.tracked_bursts == 2
