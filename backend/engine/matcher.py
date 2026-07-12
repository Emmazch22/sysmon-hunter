"""Rule evaluation.

A deliberately small matcher with Sigma-compatible semantics for the subset of
modifiers that Sysmon rules actually need. Writing it by hand rather than
depending on pySigma keeps the hot path transparent: when a rule does not fire
against real telemetry, the reason is somewhere in this file and nowhere else.

Field specs look like `field`, `field|operator`, or `field|operator|not`.
Matching is case-insensitive throughout, because Windows paths are.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Callable

from backend.models.schemas import Detection, Event, Rule


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str]:
    """Compile and cache a regex.

    Rules are evaluated on every matching event, so recompiling the same pattern
    thousands of times per minute is pure waste. The cache is keyed on the
    pattern string, which is stable for the lifetime of a rule.
    """
    return re.compile(pattern, re.IGNORECASE)


def _as_list(value: Any) -> list[Any]:
    """Treat a scalar and a list identically.

    YAML authors write a single value when there is one and a list when there
    are several; the matcher should not care which.
    """
    return value if isinstance(value, list) else [value]


# Each operator answers: does the event's value satisfy any of the expected ones?
# Multiple expected values are always OR'd -- an `image|endswith` with five
# executables means "any of these five".
OPERATORS: dict[str, Callable[[str, list[str]], bool]] = {
    "equals": lambda actual, expected: actual in expected,
    "contains": lambda actual, expected: any(e in actual for e in expected),
    "startswith": lambda actual, expected: any(actual.startswith(e) for e in expected),
    "endswith": lambda actual, expected: any(actual.endswith(e) for e in expected),
    "re": lambda actual, expected: any(_compiled(e).search(actual) for e in expected),
}


class RuleSyntaxError(ValueError):
    """A rule used an operator the matcher does not implement."""


def _compare(operator: str, actual: Any, expected: Any) -> bool:
    """Apply one operator to one field.

    A missing field never matches. This matters: a rule looking for
    `command_line|contains: -enc` must not fire on an event that carries no
    command line at all, which is exactly what a naive `None in x` check would
    do by raising instead of returning False.
    """
    if actual is None:
        return False

    handler = OPERATORS.get(operator)
    if handler is None:
        raise RuleSyntaxError(f"Unknown operator: {operator!r}")

    # `re` patterns are lowercased by the IGNORECASE flag, not by us -- folding
    # the pattern itself would break character classes like [A-Z].
    needle = str(actual) if operator == "re" else str(actual).lower()
    haystack = [str(v) if operator == "re" else str(v).lower() for v in _as_list(expected)]

    return handler(needle, haystack)


def _evaluate_field(event: Event, spec: str, expected: Any) -> bool:
    """Evaluate a single `field|operator|not` spec against an event."""
    parts = spec.split("|")
    field = parts[0]
    modifiers = parts[1:]

    negate = "not" in modifiers
    operators = [m for m in modifiers if m != "not"]
    operator = operators[0] if operators else "equals"

    result = _compare(operator, event.get(field), expected)
    return not result if negate else result


def matches(event: Event, rule: Rule) -> bool:
    """Does this event satisfy this rule?

    `condition: all` requires every field spec to hold (AND); `condition: any`
    requires at least one (OR). A rule with an empty `detection` block never
    fires -- treating it as "match everything" would be a catastrophic default.
    """
    if not rule.detection:
        return False

    results = (
        _evaluate_field(event, spec, expected)
        for spec, expected in rule.detection.items()
    )

    # all()/any() short-circuit, so an AND rule stops at the first field that
    # fails -- typically the cheap `image|endswith` before the expensive regex.
    return all(results) if rule.condition == "all" else any(results)


def evaluate(event: Event, rules: list[Rule]) -> list[Detection]:
    """Run an event against a set of rules and return every detection raised.

    An event can trigger several rules at once -- an Office-spawned PowerShell
    with an encoded command legitimately fires both -- and all of them are
    reported. Suppressing the "lesser" one would throw away context the analyst
    needs.
    """
    return [
        Detection(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            attack=rule.attack,
            event=event,
        )
        for rule in rules
        if matches(event, rule)
    ]