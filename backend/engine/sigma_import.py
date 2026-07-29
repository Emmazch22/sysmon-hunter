"""Sigma rule import.

Converts a subset of the Sigma detection format (https://sigmahq.io) into
this engine's own rule schema (`backend.models.schemas.Rule`), so a rule
authored against the public Sigma corpus can be dropped in instead of hand-
translated one field at a time.

Sigma is a much richer language than `backend/engine/matcher.py` implements:
nested boolean groups, aggregations (`count()`, `near`), field modifiers we
do not support (`|cidr`, `|base64`, `|all`, numeric comparisons), and log
sources far outside Sysmon are all real Sigma features. Rather than
approximate any of that -- which would mean a rule that looks like it
imported cleanly but does not fire the way its author intended -- every rule
that needs one of those features is rejected with a specific reason. This is
the same policy `rule_loader.RuleStore.load` already applies to a malformed
YAML file on disk: one bad rule is logged and skipped, never fatal, and
never silently wrong.

What IS supported, because it maps cleanly onto `Rule.detection`'s flat
`field-spec -> expected-value` dict and single `condition: all|any`:

  - `logsource.product: windows`, `.category` one of `SYSMON_EVENT_ID` below,
    `.service` unset or `sysmon`.
  - A single named detection block, or several combined with a plain
    `and` / `or` / `1 of x*` / `all of x*` condition. AND-combination merges
    every field from every block into one dict (rejected on a field-spec
    collision). OR-combination requires every combined block be exactly one
    field -- `(A and B) or C` cannot be flattened into one level and is
    rejected rather than guessed.
  - One trailing `and not <filter>` exclusion, where `<filter>` is a single
    field. Negating a multi-field block would need De Morgan's law to turn
    it into an OR of negations, which again is not representable here.
  - Modifiers `contains`, `startswith`, `endswith`, `re` (1:1 with the
    matcher's own operators) and `cased` (accepted and ignored -- the
    matcher is always case-insensitive, so asking for case sensitivity only
    ever makes real-world matching *more* permissive than the rule intended,
    never less).
  - Bare (unmodified) field values that use Sigma's glob wildcards (`*` and
    `?`) -- Sigma's default field match is a glob, not a literal equals.
    Single-shape globs (`*foo`, `foo*`, `*foo*`) become `endswith` /
    `startswith` / `contains`; anything with a `?`, more than one `*`, or a
    field whose values glob in more than one shape falls back to an anchored
    regex, which is always correct even when it is less readable.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml

from backend.models.schemas import Rule, Severity

# Sigma logsource category -> Sysmon EventID. Only categories with one clear,
# unambiguous EventID are listed. Sigma itself only loosely defines a few of
# these (e.g. "registry_event" spans three different Sysmon IDs depending on
# the backend that consumes it); those are pinned to the single most common
# ID rather than guessed at import time, matching this module's overall
# stance of rejecting ambiguity instead of resolving it silently.
SYSMON_EVENT_ID: dict[str, int] = {
    "process_creation": 1,
    "file_change": 2,
    "network_connection": 3,
    "driver_load": 6,
    "image_load": 7,
    "create_remote_thread": 8,
    "raw_access_thread": 9,
    "process_access": 10,
    "file_event": 11,
    "file_create": 11,
    "registry_add": 12,
    "registry_event": 13,
    "registry_set": 13,
    "registry_rename": 14,
    "create_stream_hash": 15,
    "pipe_created": 17,
    "wmi_event": 19,
    "dns_query": 22,
    "file_delete": 23,
    "clipboard_capture": 24,
    "process_tampering": 25,
    "file_delete_detected": 26,
}

_SIGMA_SEVERITY: dict[str, Severity] = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Sigma modifiers that translate 1:1 onto a matcher operator.
_MODIFIER_TO_OPERATOR: dict[str, str] = {
    "contains": "contains",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "re",
}

# Modifiers that are safe to see and ignore: they narrow what a rule matches,
# never widen it, so ignoring them can only make the imported rule fire on
# marginally more events than the original -- never fewer, never wrongly.
_IGNORED_MODIFIERS = {"cased"}

# Modifiers whose semantics this matcher cannot reproduce at all (list-AND,
# encoding transforms, numeric/CIDR comparison, existence checks...). A rule
# using one of these is rejected outright rather than silently mis-imported.
_UNSUPPORTED_MODIFIERS = {
    "all", "base64", "base64offset", "wide", "utf16", "utf16le", "utf16be",
    "windash", "cidr", "gt", "gte", "lt", "lte", "exists", "fieldref", "expand",
}

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_GLOB_CHARS = re.compile(r"[*?]")
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class SigmaImportError(ValueError):
    """A Sigma rule could not be safely converted. The message says why."""


@dataclass
class SigmaImportResult:
    """The outcome of importing every document found in one uploaded file."""

    accepted: list[Rule] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)  # {"title", "reason"}


# ---------------------------------------------------------------------------
# Logsource -> EventID
# ---------------------------------------------------------------------------


def _event_id_for_logsource(logsource: dict[str, Any]) -> int:
    product = str(logsource.get("product") or "").lower()
    service = str(logsource.get("service") or "").lower()
    category = str(logsource.get("category") or "").lower()

    if product != "windows":
        raise SigmaImportError(
            f"unsupported logsource product: {product or '(none)'!r} -- this "
            "engine only ingests Windows Sysmon telemetry"
        )
    if service and service != "sysmon":
        raise SigmaImportError(
            f"unsupported logsource service: {service!r} -- only Sysmon-sourced "
            "rules (service: sysmon, or no service at all) are supported"
        )
    if not category:
        raise SigmaImportError("logsource has no category to map to a Sysmon EventID")

    event_id = SYSMON_EVENT_ID.get(category)
    if event_id is None:
        raise SigmaImportError(f"unsupported logsource category: {category!r}")
    return event_id


# ---------------------------------------------------------------------------
# Condition parsing
# ---------------------------------------------------------------------------


def _require_block(blocks: dict[str, Any], name: str) -> Any:
    if name not in blocks:
        raise SigmaImportError(f"condition references undefined selection: {name!r}")
    return blocks[name]


def _match_block_names(pattern: str, blocks: dict[str, Any]) -> list[str]:
    """Resolve a `1 of <pattern>` / `all of <pattern>` target to block names."""
    if pattern.lower() == "them":
        return list(blocks.keys())
    if "*" not in pattern:
        return [pattern] if pattern in blocks else []
    regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
    return [name for name in blocks if regex.match(name)]


def _merge_expected(existing: Any, new: Any) -> Any:
    """Union two expected-value sets for the same field spec.

    Every operator this matcher implements already ORs across a list of
    expected values for one field (`field|contains: [a, b]` means "a or b"),
    so two OR'd selections that happen to check the *same* field spec with
    *different* values collapse cleanly into one spec with both values --
    `DestinationPort: 4444` and `DestinationPort: 8443` combined with `or`
    becomes `DestinationPort: [4444, 8443]`, which is exactly what the Sigma
    rule meant.
    """
    existing_list = existing if isinstance(existing, list) else [existing]
    new_list = new if isinstance(new, list) else [new]
    merged = list(existing_list)
    for item in new_list:
        if item not in merged:
            merged.append(item)
    return merged


def _merge_or_list(name: str, items: list[Any]) -> dict[str, Any]:
    """Flatten a block written as a list of single-field maps (an inline OR)."""
    merged: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            raise SigmaImportError(
                f"selection {name!r} is a list of alternatives, but each "
                "alternative must be exactly one field to be representable"
            )
        (spec, expected), = item.items()
        merged[spec] = _merge_expected(merged[spec], expected) if spec in merged else expected
    return merged


def _combine(names: list[str], blocks: dict[str, Any], join: str) -> tuple[dict[str, Any], str]:
    """Merge the named blocks with AND (`join='all'`) or OR (`join='any'`).

    A lone block's own shape decides the outcome: a mapping is a conjunction
    of its fields, a list of single-field mappings is Sigma's shorthand for
    an OR of simple checks. Combining *several* blocks only works flattened
    into one level: AND merges every field into one dict, OR requires every
    block be exactly one field, since `(A and B) or C` has no one-level
    representation here. Either way, two blocks landing on the *same* field
    spec are folded together via `_merge_expected` rather than rejected --
    under OR that is exactly what the rule means (`X or Y` -> `[X, Y]`);
    under AND it is only kept when the two values are identical (redundant,
    harmless) and rejected otherwise (a genuine, unresolvable conflict).
    """
    if len(names) == 1 and join == "all":
        block = _require_block(blocks, names[0])
        if isinstance(block, dict):
            return dict(block), "all"
        if isinstance(block, list):
            return _merge_or_list(names[0], block), "any"
        raise SigmaImportError(f"selection {names[0]!r} is neither a mapping nor a list")

    merged: dict[str, Any] = {}
    for name in names:
        block = _require_block(blocks, name)
        if isinstance(block, list):
            raise SigmaImportError(
                f"selection {name!r} is a list of alternatives and cannot be "
                f"combined with other selections via {join!r}"
            )
        if not isinstance(block, dict):
            raise SigmaImportError(f"selection {name!r} is neither a mapping nor a list")
        if join == "any" and len(block) != 1:
            raise SigmaImportError(
                f"selection {name!r} has {len(block)} fields -- an OR between "
                "selections only works when each selection is a single field "
                "(the matcher cannot flatten '(A and B) or C')"
            )
        for spec, expected in block.items():
            if spec not in merged:
                merged[spec] = expected
            elif join == "any":
                merged[spec] = _merge_expected(merged[spec], expected)
            elif merged[spec] != expected:
                raise SigmaImportError(f"field spec collision on {spec!r} across combined selections")
            # else: identical spec and identical value in an AND -- redundant, harmless.
    return merged, join


def _append_not(spec: str) -> str:
    parts = spec.split("|")
    if "not" in parts[1:]:
        return spec  # already negated; leave a double negative alone
    return spec + "|not"


def _parse_condition(condition: str, blocks: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Parse a Sigma `detection.condition` string into one merged field dict
    plus the `all`/`any` this engine's matcher understands.

    Only the patterns documented at the top of this module are recognized;
    anything else (nested parentheses, `count()`/`near` aggregations, more
    than one `and not`, mixing `and` and `or` in the same expression) raises
    `SigmaImportError` naming the exact expression that could not be parsed.
    """
    condition = " ".join(condition.split())

    match = re.match(rf"^(?P<pos>.+)\s+and\s+not\s+(?P<filt>{_NAME})$", condition, re.IGNORECASE)
    if match:
        pos_fields, pos_cond = _parse_condition(match.group("pos"), blocks)
        if pos_cond != "all":
            raise SigmaImportError(
                "cannot combine an OR'd selection with 'and not <filter>' -- "
                "the matcher has no way to express (A or B) and not C"
            )
        filt_name = match.group("filt")
        filt_block = _require_block(blocks, filt_name)
        if not isinstance(filt_block, dict) or len(filt_block) != 1:
            raise SigmaImportError(
                f"filter {filt_name!r} must be exactly one field to be negated -- "
                "negating a multi-field block is not representable"
            )
        (fspec, fexpected), = filt_block.items()
        negated_spec = _append_not(fspec)
        if negated_spec in pos_fields:
            raise SigmaImportError(f"field spec collision on negated filter: {negated_spec!r}")
        pos_fields[negated_spec] = fexpected
        return pos_fields, "all"

    match = re.match(r"^(1|all)\s+of\s+([A-Za-z0-9_*]+)$", condition, re.IGNORECASE)
    if match:
        quantifier, pattern = match.group(1).lower(), match.group(2)
        names = _match_block_names(pattern, blocks)
        if not names:
            raise SigmaImportError(f"{quantifier} of {pattern!r} matched no selection blocks")
        return _combine(names, blocks, "any" if quantifier == "1" else "all")

    if re.match(rf"^{_NAME}(\s+and\s+{_NAME})+$", condition, re.IGNORECASE):
        return _combine(re.split(r"\s+and\s+", condition, flags=re.IGNORECASE), blocks, "all")

    if re.match(rf"^{_NAME}(\s+or\s+{_NAME})+$", condition, re.IGNORECASE):
        return _combine(re.split(r"\s+or\s+", condition, flags=re.IGNORECASE), blocks, "any")

    if re.match(rf"^{_NAME}$", condition):
        return _combine([condition], blocks, "all")

    raise SigmaImportError(
        f"unsupported condition expression: {condition!r} -- only a single "
        "selection, selections joined by a single 'and'/'or', '1 of x*' / "
        "'all of x*', and one trailing 'and not <filter>' are supported"
    )


# ---------------------------------------------------------------------------
# Field/value conversion
# ---------------------------------------------------------------------------


def _classify_glob(item: str) -> tuple[str | None, str]:
    """Classify one glob value into a matcher operator, or `None` if it needs
    a regex (a `?`, or more than one `*` in a shape other than `*x*`)."""
    if "?" in item:
        return None, item
    stars = item.count("*")
    if stars == 0:
        return "equals", item
    if stars == 1 and item.startswith("*") and not item.endswith("*"):
        return "endswith", item[1:]
    if stars == 1 and item.endswith("*") and not item.startswith("*"):
        return "startswith", item[:-1]
    if stars == 2 and item.startswith("*") and item.endswith("*"):
        return "contains", item[1:-1]
    return None, item


def _glob_to_regex(item: str) -> str:
    """Translate a Sigma glob into an anchored regex, preserving Sigma's
    full-string-match semantics (a bare Sigma value matches the *whole*
    field, not a substring, unless bounded by `*`)."""
    out: list[str] = []
    for ch in item:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


def _convert_bare_value(expected: Any) -> tuple[str, Any]:
    """Convert a Sigma value with no operator modifier: literal if there are
    no wildcards, otherwise translated per `_classify_glob`/`_glob_to_regex`."""
    is_list = isinstance(expected, list)
    items = expected if is_list else [expected]
    if not items:
        raise SigmaImportError("empty value list")

    str_items = [str(item) for item in items]
    if not any(_GLOB_CHARS.search(item) for item in str_items):
        return "equals", expected

    shapes = [_classify_glob(item) for item in str_items]
    operators_used = {op for op, _ in shapes}
    if None not in operators_used and len(operators_used) == 1:
        operator = next(iter(operators_used))
        cores = [core for _, core in shapes]
        return operator, cores if is_list else cores[0]

    # Mixed shapes, or something too complex for a friendly operator: always
    # correct, if less readable, to fall back to one anchored regex per value
    # and let the matcher's own list-OR handle "any of these".
    return "re", [_glob_to_regex(item) for item in str_items]


def _convert_field(spec: str, expected: Any) -> tuple[str, Any]:
    """Convert one `field[|modifier...]: expected` pair to this engine's
    `field[|operator][|not]` spec."""
    parts = spec.split("|")
    field_name = parts[0]
    modifiers = parts[1:]

    negate = "not" in modifiers
    modifiers = [m for m in modifiers if m != "not"]

    unsupported = [m for m in modifiers if m in _UNSUPPORTED_MODIFIERS]
    if unsupported:
        raise SigmaImportError(f"field {field_name!r}: unsupported modifier(s): {', '.join(unsupported)}")

    operator_mods = [m for m in modifiers if m in _MODIFIER_TO_OPERATOR]
    if len(operator_mods) > 1:
        raise SigmaImportError(f"field {field_name!r}: more than one operator modifier ({', '.join(operator_mods)})")

    unknown = [m for m in modifiers if m not in _MODIFIER_TO_OPERATOR and m not in _IGNORED_MODIFIERS]
    if unknown:
        raise SigmaImportError(f"field {field_name!r}: unknown modifier(s): {', '.join(unknown)}")

    if expected is None:
        raise SigmaImportError(f"field {field_name!r}: a null value is not supported")

    if operator_mods:
        operator, converted_expected = _MODIFIER_TO_OPERATOR[operator_mods[0]], expected
    else:
        operator, converted_expected = _convert_bare_value(expected)

    out_spec = field_name
    if operator != "equals":
        out_spec += f"|{operator}"
    if negate:
        out_spec += "|not"
    return out_spec, converted_expected


# ---------------------------------------------------------------------------
# Rule-level conversion
# ---------------------------------------------------------------------------


def _extract_attack_ids(tags: Any) -> list[str]:
    if not isinstance(tags, list):
        return []
    ids: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _TECHNIQUE_TAG.match(tag.strip().lower())
        if match:
            ids.add(match.group(1).upper())
    return sorted(ids)


def convert_sigma_rule(document: dict[str, Any], *, id_prefix: str = "SIGMA") -> Rule:
    """Convert one parsed Sigma YAML document into a `Rule`.

    Raises `SigmaImportError` naming exactly which part of the rule could not
    be safely represented -- never guesses, never approximates.
    """
    if not isinstance(document, dict):
        raise SigmaImportError("not a Sigma rule document (expected a YAML mapping)")

    title = document.get("title")
    if not title:
        raise SigmaImportError("missing required field: title")

    logsource = document.get("logsource")
    if not isinstance(logsource, dict):
        raise SigmaImportError("missing required field: logsource")
    event_id = _event_id_for_logsource(logsource)

    detection = document.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaImportError("missing required field: detection.condition")

    condition = detection["condition"]
    if not isinstance(condition, str):
        raise SigmaImportError("only a single string detection.condition is supported, not a list")

    blocks = {k: v for k, v in detection.items() if k != "condition"}
    if not blocks:
        raise SigmaImportError("detection has no selection blocks")

    merged_fields, internal_condition = _parse_condition(condition, blocks)

    rule_detection: dict[str, Any] = {}
    for spec, expected in merged_fields.items():
        conv_spec, conv_expected = _convert_field(spec, expected)
        if conv_spec in rule_detection:
            raise SigmaImportError(f"field spec collision after conversion: {conv_spec!r}")
        rule_detection[conv_spec] = conv_expected

    sigma_id = str(document.get("id") or "").replace("-", "")
    rule_id = f"{id_prefix}-{sigma_id[:8]}" if sigma_id else f"{id_prefix}-{uuid.uuid4().hex[:8]}"

    level = str(document.get("level") or "medium").lower()
    severity = _SIGMA_SEVERITY.get(level, Severity.MEDIUM)

    return Rule(
        id=rule_id,
        title=str(title),
        event_id=event_id,
        severity=severity,
        attack=_extract_attack_ids(document.get("tags")),
        description=str(document.get("description") or "").strip(),
        detection=rule_detection,
        condition=internal_condition,
        enabled=True,
    )


def import_sigma_text(text: str, *, source_name: str = "upload") -> SigmaImportResult:
    """Convert every Sigma document in one YAML file (Sigma allows several,
    `---`-separated) into `Rule`s, collecting successes and failures
    independently so one bad rule in a batch never blocks the rest."""
    result = SigmaImportResult()

    try:
        documents = [doc for doc in yaml.safe_load_all(text) if doc]
    except yaml.YAMLError as exc:
        result.rejected.append({"title": source_name, "reason": f"invalid YAML: {exc}"})
        return result

    if not documents:
        result.rejected.append({"title": source_name, "reason": "empty file"})
        return result

    for index, document in enumerate(documents):
        label = (
            str(document.get("title"))
            if isinstance(document, dict) and document.get("title")
            else f"{source_name}#{index}"
        )
        try:
            rule = convert_sigma_rule(document)
        except SigmaImportError as exc:
            result.rejected.append({"title": label, "reason": str(exc)})
            continue
        except Exception as exc:  # noqa: BLE001 -- one bad rule must never crash the batch
            result.rejected.append({"title": label, "reason": f"unexpected error: {exc}"})
            continue
        result.accepted.append(rule)

    return result
