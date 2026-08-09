"""backend/engine/redos_guard.py -- the gate on Sigma-imported `|re` regexes.

Four ways a pattern can be rejected (length, syntax, the static nested-
quantifier heuristic, the empirical timing probe) and one way it can be
accepted -- each pinned down individually so a future change to one check
cannot silently widen what the others catch.
"""

from __future__ import annotations

from backend.engine.redos_guard import MAX_PATTERN_LENGTH, is_safe_regex


class TestIsSafeRegex:
    def test_accepts_an_ordinary_detection_pattern(self) -> None:
        safe, reason = is_safe_regex(r".*\\powershell\.exe$")
        assert safe is True
        assert reason == ""

    def test_rejects_a_pattern_over_the_length_limit(self) -> None:
        safe, reason = is_safe_regex("a" * (MAX_PATTERN_LENGTH + 1))
        assert safe is False
        assert "character limit" in reason

    def test_rejects_invalid_regex_syntax(self) -> None:
        safe, reason = is_safe_regex("(unclosed")
        assert safe is False
        assert "invalid regex" in reason

    def test_rejects_a_nested_quantifier_statically(self) -> None:
        """(a+)+ is the textbook catastrophic-backtracking shape -- caught by
        the static heuristic before the timing probe ever has to run."""
        safe, reason = is_safe_regex(r"(a+)+$")
        assert safe is False
        assert "nested quantifier" in reason

    def test_rejects_an_alternation_blowup_via_the_timing_probe(self) -> None:
        """(a|aa)+$ has no nested quantifier (the '+' sits outside the group,
        the group itself only has alternation) so the static heuristic cannot
        catch it -- this is exactly what the timing probe exists for."""
        safe, reason = is_safe_regex(r"(a|aa)+$")
        assert safe is False
        assert "timing probe" in reason
