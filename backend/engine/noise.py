"""False-positive similarity heuristic.

Every incident an analyst marks as a false positive is a labeled example of
noise -- this module is what makes that marking pay off for the *next*
incident, without needing a trained model or a mountain of data to get
there. A newly-opened incident is compared against the incident's own recent
history of confirmed false positives on four explainable signals -- which
detection rules fired, which ATT&CK techniques were involved, whether the
same process was the root of the tree, and how much of the process chain
overlaps -- and the result is a score plus the *specific reasons* it
matched, never a bare number an analyst has to trust blind.

This is deliberately not a classifier. A classifier needs enough labeled
examples to generalize and produces a probability nobody can fully explain;
this produces "72% similar to incident abc123, because: same detection
rules, same root process" from the very first false positive an analyst
ever marks, and the explanation is exactly the arithmetic that produced the
score -- nothing hidden, nothing to retrain, nothing that can silently drift
as the rule corpus changes underneath it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# Similarity is a weighted average across these four signals. Rule IDs carry
# the most weight because they are the most precise statement of "this is
# the same detection pattern" available -- two incidents that fired the
# exact same rules are far more likely to be the same recurring noise than
# two that merely share a technique. Root process and technique overlap are
# next: a different specific rule can still describe the same underlying
# benign behavior. Chain overlap carries the least weight deliberately,
# since two unrelated incidents on a similar host image can share several
# common ancestor processes (explorer.exe, svchost.exe) by sheer platform
# convention, not because they are the same story.
_WEIGHT_RULE_IDS = 0.5
_WEIGHT_TECHNIQUES = 0.2
_WEIGHT_ROOT_PROCESS = 0.2
_WEIGHT_CHAIN = 0.1

# Below this, two incidents sharing "some" signal is coincidence, not a
# pattern worth surfacing -- flagging too eagerly trains analysts to ignore
# the badge, which defeats the point of having it.
DEFAULT_THRESHOLD = 0.6

# How many past false positives to cite as evidence. One or two is usually
# more persuasive than a wall of IDs, and the score already carries the
# strength of the match.
MAX_MATCHES = 3

# A signal only earns a place in the human-readable "matched_on" list once
# it is a real match, not a token overlap -- otherwise a 0.15 Jaccard on the
# process chain would show up looking exactly as confident as a 1.0 exact
# rule-ID match.
_REASON_THRESHOLD = 0.5


def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()


@dataclass(frozen=True)
class Fingerprint:
    """The signals one incident contributes to the similarity comparison.

    `rule_ids` is `None` when the caller could not afford to load the
    incident's detections (e.g. scoring an entire list-view page) rather
    than when the incident genuinely fired no rules -- `_compare` treats
    the two very differently, see below.
    """

    incident_id: str
    root_image: str
    chain: tuple[str, ...]
    techniques: frozenset[str]
    rule_ids: Optional[frozenset[str]] = None


def fingerprint_from_incident(
    incident: dict[str, Any], rule_ids: Optional[Iterable[str]] = None
) -> Fingerprint:
    """Build a `Fingerprint` from a serialized incident (the same shape
    `api/serializers.py` produces) plus, optionally, its detections' rule
    IDs fetched separately -- incidents do not carry rule IDs of their own,
    only their member detections do.

    The root process is read from `chain[0]` rather than a dedicated field:
    `Incident.chain` is documented as running "from the root down to the
    process itself", so the first element already *is* the root image, and
    every incident already carries it with no extra query.
    """
    chain = tuple(incident.get("chain") or [])
    return Fingerprint(
        incident_id=incident["id"],
        root_image=_basename(chain[0]) if chain else "",
        chain=tuple(_basename(c) for c in chain),
        techniques=frozenset(incident.get("techniques") or []),
        rule_ids=frozenset(rule_ids) if rule_ids is not None else None,
    )


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    """Intersection over union. Two empty sets are "no signal", not
    "identical" -- returning 1.0 there would flag every incident with no
    techniques as maximally similar to every false positive with none
    either, which is the opposite of informative."""
    if not a and not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _compare(candidate: Fingerprint, reference: Fingerprint) -> tuple[float, list[str]]:
    """Score one candidate against one historical false positive.

    Returns `(score, reasons)`. `score` is a weighted average over whichever
    signals are actually available -- when the candidate has no rule IDs
    (see `Fingerprint.rule_ids`'s docstring), that component is dropped
    entirely and the remaining weights are renormalized, rather than
    treating "signal unavailable" the same as "signal absent" (which would
    silently deflate every list-view score relative to the detail view).
    """
    components: list[tuple[float, float, str]] = []

    if candidate.rule_ids is not None and reference.rule_ids:
        components.append(
            (_WEIGHT_RULE_IDS, _jaccard(candidate.rule_ids, reference.rule_ids), "same detection rules")
        )

    components.append(
        (_WEIGHT_TECHNIQUES, _jaccard(candidate.techniques, reference.techniques), "same ATT&CK techniques")
    )

    root_match = 1.0 if candidate.root_image and candidate.root_image == reference.root_image else 0.0
    components.append((_WEIGHT_ROOT_PROCESS, root_match, "same root process"))

    components.append(
        (_WEIGHT_CHAIN, _jaccard(frozenset(candidate.chain), frozenset(reference.chain)), "overlapping process chain")
    )

    total_weight = sum(weight for weight, _, _ in components)
    if total_weight == 0:
        return 0.0, []

    score = sum(weight * value for weight, value, _ in components) / total_weight
    reasons = [reason for _, value, reason in components if value >= _REASON_THRESHOLD]
    return score, reasons


@dataclass
class NoiseMatch:
    """One past false positive the candidate resembles, and why."""

    incident_id: str
    score: float
    matched_on: list[str] = field(default_factory=list)


@dataclass
class NoiseAssessment:
    """The result of comparing one incident against the false-positive
    history: the strongest match's score (0.0 if nothing cleared the
    threshold) and the ranked evidence behind it."""

    score: float
    matches: list[NoiseMatch] = field(default_factory=list)


def assess(
    candidate: Fingerprint,
    history: Iterable[Fingerprint],
    *,
    threshold: float = DEFAULT_THRESHOLD,
    limit: int = MAX_MATCHES,
) -> NoiseAssessment:
    """Compare one incident's fingerprint against every fingerprint in the
    false-positive history and return the matches that cleared `threshold`,
    strongest first.

    An empty or all-below-threshold history returns `NoiseAssessment(0.0,
    [])`, which the API layer treats as "nothing to show" -- this function
    never claims a match it cannot back with a reason.
    """
    matches = []
    for reference in history:
        score, reasons = _compare(candidate, reference)
        if score >= threshold:
            matches.append(NoiseMatch(incident_id=reference.incident_id, score=round(score, 2), matched_on=reasons))

    matches.sort(key=lambda m: m.score, reverse=True)
    top = matches[:limit]
    return NoiseAssessment(score=top[0].score if top else 0.0, matches=top)
