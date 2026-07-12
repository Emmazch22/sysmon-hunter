"""Matcher semantics.

These tests pin down the contract that every YAML rule depends on. A change here
that goes unnoticed silently changes the meaning of the entire rule corpus.
"""

from __future__ import annotations

import pytest

from backend.engine.matcher import RuleSyntaxError, evaluate, matches
from backend.models.schemas import Severity
from tests.conftest import make_event, make_rule


class TestOperators:
    def test_equals_is_the_default_operator(self) -> None:
        event = make_event(image="cmd.exe")
        assert matches(event, make_rule(image="cmd.exe"))
        assert not matches(event, make_rule(image="powershell.exe"))

    def test_matching_is_case_insensitive(self) -> None:
        """Windows paths are case-insensitive, so rules must be too. A rule that
        misses because Sysmon wrote WINWORD.EXE and the author typed winword.exe
        is a blind spot with no error message."""
        event = make_event(image=r"C:\Windows\System32\CMD.EXE")
        assert matches(event, make_rule(**{"image|endswith": r"\cmd.exe"}))

    def test_endswith_matches_any_value_in_a_list(self) -> None:
        """Multiple expected values are OR'd -- one rule, several executables."""
        rule = make_rule(**{"image|endswith": [r"\cmd.exe", r"\powershell.exe"]})
        assert matches(make_event(image=r"C:\W\powershell.exe"), rule)
        assert not matches(make_event(image=r"C:\W\notepad.exe"), rule)

    def test_contains_and_startswith(self) -> None:
        event = make_event(command_line="powershell -enc SQBFAFgA")
        assert matches(event, make_rule(**{"command_line|contains": "-enc"}))
        assert matches(event, make_rule(**{"command_line|startswith": "powershell"}))
        assert not matches(event, make_rule(**{"command_line|startswith": "cmd"}))

    def test_regex_operator(self) -> None:
        rule = make_rule(**{"command_line|re": r"-e(nc)?\s+[a-z0-9+/=]{20,}"})
        assert matches(make_event(command_line="powershell -enc " + "A" * 30), rule)
        # Below the length threshold: a short -e argument is not obfuscation.
        assert not matches(make_event(command_line="powershell -enc AAAA"), rule)

    def test_not_modifier_negates(self) -> None:
        rule = make_rule(**{"image|endswith|not": r"\notepad.exe"})
        assert matches(make_event(image=r"C:\W\cmd.exe"), rule)
        assert not matches(make_event(image=r"C:\W\notepad.exe"), rule)

    def test_unknown_operator_raises(self) -> None:
        """A typo in a rule must fail loudly, not match nothing forever."""
        with pytest.raises(RuleSyntaxError):
            matches(make_event(image="cmd.exe"), make_rule(**{"image|fuzzy": "cmd"}))


class TestConditions:
    def test_condition_all_requires_every_field(self) -> None:
        rule = make_rule(
            condition="all",
            **{"parent_image|endswith": r"\winword.exe", "image|endswith": r"\cmd.exe"},
        )
        assert matches(
            make_event(parent_image=r"C:\O\WINWORD.EXE", image=r"C:\W\cmd.exe"), rule
        )
        # Right child, wrong parent: no match. This is the whole point of the rule.
        assert not matches(
            make_event(parent_image=r"C:\W\explorer.exe", image=r"C:\W\cmd.exe"), rule
        )

    def test_condition_any_requires_one_field(self) -> None:
        rule = make_rule(
            condition="any",
            **{"image|endswith": r"\mshta.exe", "command_line|contains": "http"},
        )
        assert matches(make_event(image=r"C:\W\mshta.exe"), rule)
        assert matches(make_event(image=r"C:\W\cmd.exe", command_line="curl http://x"), rule)
        assert not matches(make_event(image=r"C:\W\cmd.exe", command_line="dir"), rule)

    def test_empty_detection_never_matches(self) -> None:
        """An empty detection block must not mean 'match everything'. That
        default would turn one malformed rule into a total alert flood."""
        assert not matches(make_event(image="cmd.exe"), make_rule())


class TestFieldResolution:
    def test_missing_field_never_matches(self) -> None:
        """An event with no command line must not satisfy a command-line rule."""
        event = make_event(image=r"C:\W\cmd.exe", command_line=None)
        assert not matches(event, make_rule(**{"command_line|contains": "-enc"}))

    def test_raw_sysmon_fields_are_addressable(self) -> None:
        """Rules can reach fields the normalizer never promoted, which is how
        EventID 10 rules address TargetImage and GrantedAccess."""
        event = make_event(
            event_id=10,
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1410",
        )
        rule = make_rule(
            event_id=10,
            **{"TargetImage|endswith": r"\lsass.exe", "GrantedAccess": ["0x1010", "0x1410"]},
        )
        assert matches(event, rule)


class TestEvaluate:
    def test_one_event_can_fire_several_rules(self) -> None:
        """An Office-spawned PowerShell with an encoded command is genuinely two
        findings. Suppressing the 'lesser' one throws away context."""
        event = make_event(
            parent_image=r"C:\O\WINWORD.EXE",
            image=r"C:\W\powershell.exe",
            command_line="powershell -enc " + "A" * 30,
        )
        rules = [
            make_rule("SYS-001", severity=Severity.HIGH, **{"parent_image|endswith": r"\winword.exe"}),
            make_rule("SYS-002", severity=Severity.HIGH, **{"command_line|re": r"-enc\s+[a-z0-9]{20,}"}),
            make_rule("SYS-999", **{"image|endswith": r"\notepad.exe"}),
        ]
        detections = evaluate(event, rules)
        assert [d.rule_id for d in detections] == ["SYS-001", "SYS-002"]

    def test_detection_carries_rule_metadata(self) -> None:
        rule = make_rule("SYS-010", severity=Severity.CRITICAL, attack=["T1003.001"], image="lsass.exe")
        detection = evaluate(make_event(image="lsass.exe"), [rule])[0]
        assert detection.severity is Severity.CRITICAL
        assert detection.attack == ["T1003.001"]
        assert detection.score == 14