"""ReDoS-safe validation for user-supplied regex patterns.

Every regex this engine ever evaluates against live event data comes from one
of two places: a hand-authored YAML file under `rules/` that the maintainer
wrote and reviewed, or a Sigma document uploaded through
`/admin/rules/import-sigma`. The second is the one place an attacker-
controlled regex can reach `backend/engine/matcher.py`'s hot path -- and
`re.compile`'s backtracking engine has no built-in defense against
catastrophic backtracking. A single crafted pattern accepted there would run
against every event ingested from then on, for as long as the rule stays
enabled.

This module is the gate `backend/engine/sigma_import.py` calls before
accepting a Sigma rule's `|re` field. Three layers, cheapest first:

  1. A length cap. Not a security control on its own (a short pattern can
     still be catastrophic), but it rejects the "whole regex corpus pasted
     into one field" mistake for free.
  2. A static heuristic for the classic nested-quantifier shape (`(a+)+`,
     `(a*)*`, ...) -- fast, but neither complete (misses `(a|aa)+`-style
     alternation blowups) nor sound (can flag a pattern that is actually
     fine), which is exactly why it is a first pass, not the only pass.
  3. An empirical timing probe: the pattern is matched against a couple of
     adversarial strings in a throwaway subprocess with a hard wall-clock
     budget. A thread cannot be forcibly stopped once it is inside a CPU-
     bound backtracking match -- the GIL keeps it running regardless of any
     caller-side timeout -- so a subprocess, which actually can be killed, is
     the only reliable way to bound the cost of testing a pattern this code
     does not yet trust.
"""

from __future__ import annotations

import multiprocessing
import re

# A legitimate detection regex over a Windows path or command line has no
# business being longer than this. Generous headroom over the longest
# hand-written pattern in rules/ today, not a tight fit.
MAX_PATTERN_LENGTH = 200

# Nested-quantifier shapes are the classic catastrophic-backtracking
# fingerprint: a group that can itself match the same input in more than one
# way, immediately followed by another quantifier -- (a+)+, (a*)*, (a+)*,
# (a{2,4})+, and so on. Deliberately restricted to non-nested groups (no
# inner parens): parsing genuinely nested groups correctly needs a real regex
# parser, and this only has to catch the common case cheaply, not every case
# -- the timing probe below is the backstop for what this misses.
_NESTED_QUANTIFIER = re.compile(r"\([^()]*(?:[+*]|\{\d+,?\d*\})[^()]*\)[+*]")

# Strings chosen to trip catastrophic backtracking: a long run of one
# character (maximizes the number of ways a vulnerable pattern can partition
# it) followed by a character the pattern cannot consume, which is what
# forces a vulnerable engine to exhaust every partition before it can fail.
# Two lengths so a pattern that is merely slow (not exponential) still passes.
_PROBE_STRINGS = ("a" * 32 + "!", "a" * 48 + "!")

# Wall-clock budget per probe. Any pattern this engine legitimately needs
# matches in comfortably under a millisecond; half a second is generous
# headroom for a loaded CI box, and a catastrophic pattern blows past it by
# orders of magnitude regardless.
_PROBE_TIMEOUT_SECONDS = 0.5


def _match_worker(pattern: str, probe: str) -> None:
    """Run in a subprocess: attempt one match and exit. Never sends a result
    back -- the parent only cares whether this returns before the timeout,
    not what it found."""
    try:
        re.compile(pattern, re.IGNORECASE).search(probe)
    except re.error:
        pass  # an invalid pattern is reported by the caller, not here


def _probe_is_fast(pattern: str, probe: str) -> bool:
    proc = multiprocessing.Process(target=_match_worker, args=(pattern, probe))
    proc.start()
    proc.join(_PROBE_TIMEOUT_SECONDS)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return False
    return True


def is_safe_regex(pattern: str) -> tuple[bool, str]:
    """Check one regex pattern before it is allowed into the live rule set.

    Returns `(True, "")` if the pattern is accepted, or `(False, reason)`
    naming exactly why it was rejected -- the same "never guess, always say
    why" policy the rest of the Sigma importer follows for every other kind
    of unsupported rule.
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        return False, (
            f"regex is {len(pattern)} characters, over the "
            f"{MAX_PATTERN_LENGTH}-character limit"
        )

    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return False, f"invalid regex: {exc}"

    if _NESTED_QUANTIFIER.search(pattern):
        return False, (
            "regex contains a nested quantifier (e.g. '(a+)+'), a classic "
            "catastrophic-backtracking shape"
        )

    for probe in _PROBE_STRINGS:
        if not _probe_is_fast(pattern, probe):
            return False, (
                "regex did not complete a timing probe in time -- likely "
                "catastrophic backtracking"
            )

    return True, ""
