from typing import Any

from backend.models.schemas import Detection, Event, Rule


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _cmp(operator: str, actual: Any, expected: Any) -> bool:
    """Compara un valor del evento contra uno esperado. Case-insensitive."""
    if actual is None:
        return False

    a = str(actual).lower()
    candidates = [str(v).lower() for v in _as_list(expected)]

    if operator == "equals":
        return a in candidates
    if operator == "contains":
        return any(c in a for c in candidates)
    if operator == "startswith":
        return any(a.startswith(c) for c in candidates)
    if operator == "endswith":
        return any(a.endswith(c) for c in candidates)
    if operator == "re":
        import re

        return any(re.search(c, a) is not None for c in candidates)
    raise ValueError(f"Operador desconocido: {operator}")


def _eval_field(event: Event, spec: str, expected: Any) -> bool:
    """spec es 'campo' o 'campo|operador', opcionalmente con sufijo '|not'."""
    parts = spec.split("|")
    field = parts[0]
    modifiers = parts[1:]

    negate = "not" in modifiers
    ops = [m for m in modifiers if m != "not"]
    operator = ops[0] if ops else "equals"

    result = _cmp(operator, event.get(field), expected)
    return not result if negate else result


def match(event: Event, rule: Rule) -> bool:
    results = [_eval_field(event, spec, expected) for spec, expected in rule.detection.items()]
    if not results:
        return False
    return all(results) if rule.condition == "all" else any(results)


def evaluate(event: Event, rules: list[Rule]) -> list[Detection]:
    return [
        Detection(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            attack=rule.attack,
            event=event,
        )
        for rule in rules
        if match(event, rule)
    ]