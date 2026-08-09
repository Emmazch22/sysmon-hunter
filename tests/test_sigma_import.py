"""Sigma import: the conversion contract and the API that exposes it.

Every accepted-case test also cross-checks the produced `Rule` against the
real matcher (via `tests.conftest.make_event`/a normalized `Event`) so a test
suite that only inspected `rule.detection` dicts could not paper over a
conversion that "looks right" but never actually fires. Every rejected-case
test pins down the *reason* a rule is unsupported, not just that it failed --
that reason is what an analyst reads when their own Sigma rule bounces.
"""

from __future__ import annotations

import textwrap

import pytest
from httpx import ASGITransport, AsyncClient

from backend.engine.matcher import matches
from backend.engine.normalizer import normalize
from backend.engine.sigma_import import (
    SigmaImportError,
    convert_sigma_rule,
    import_sigma_text,
)
from backend.models.schemas import Severity


def sigma(body: str) -> str:
    """Dedent a Sigma YAML fixture written as a triple-quoted raw string."""
    return textwrap.dedent(body)


def event_from(**sysmon_fields: object) -> object:
    """Build a normalized Event the way a real Sysmon/Winlogbeat event would
    arrive -- through `normalize`, not `conftest.make_event` -- because a
    Sigma-imported rule's field names (PascalCase, e.g. `Image`) only resolve
    through `Event.raw`, which only `normalize` populates."""
    return normalize(sysmon_fields)


# ---------------------------------------------------------------------------
# Accepted: single selection, straightforward modifiers
# ---------------------------------------------------------------------------


class TestSingleSelection:
    def test_contains_modifier_round_trips_through_the_matcher(self) -> None:
        doc = sigma(r"""
            title: Suspicious PowerShell Encoded Command
            level: high
            logsource: {category: process_creation, product: windows}
            tags: [attack.execution, attack.t1059.001]
            detection:
              selection:
                Image|endswith: '\powershell.exe'
                CommandLine|contains: ['-enc', '-EncodedCommand']
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))

        assert rule.event_id == 1
        assert rule.severity == Severity.HIGH
        assert rule.attack == ["T1059.001"]
        assert rule.condition == "all"
        assert rule.detection == {
            "Image|endswith": r"\powershell.exe",
            "CommandLine|contains": ["-enc", "-EncodedCommand"],
        }

        fires = event_from(EventID=1, Image=r"C:\Windows\System32\powershell.exe",
                            CommandLine="powershell.exe -enc SGVsbG8=")
        quiet = event_from(EventID=1, Image=r"C:\Windows\System32\powershell.exe",
                            CommandLine="powershell.exe -Command Get-Process")
        assert matches(fires, rule)
        assert not matches(quiet, rule)

    def test_id_and_level_and_description_are_carried_over(self) -> None:
        doc = sigma(r"""
            id: 51e646ea-2898-4a26-9b6d-e6006e5b6a6d
            title: A rule
            level: critical
            description: Something bad.
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image|endswith: '\evil.exe'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.id == "SIGMA-51e646ea"
        assert rule.severity == Severity.CRITICAL
        assert rule.description == "Something bad."

    def test_missing_id_still_gets_a_stable_looking_generated_one(self) -> None:
        doc = sigma(r"""
            title: No id here
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image|endswith: '\evil.exe'
              condition: selection
        """)
        rule_a = convert_sigma_rule(_only_doc(doc))
        rule_b = convert_sigma_rule(_only_doc(doc))
        assert rule_a.id.startswith("SIGMA-")
        assert rule_b.id.startswith("SIGMA-")
        assert rule_a.id != rule_b.id  # two independent imports, two ids

    def test_unknown_level_defaults_to_medium(self) -> None:
        doc = sigma(r"""
            title: Weird level
            level: super-duper-bad
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image|endswith: '\evil.exe'
              condition: selection
        """)
        assert convert_sigma_rule(_only_doc(doc)).severity == Severity.MEDIUM

    def test_non_technique_tags_are_ignored(self) -> None:
        doc = sigma(r"""
            title: Tag filtering
            logsource: {category: process_creation, product: windows}
            tags: [attack.execution, car.2016-04-001, attack.t1059.001]
            detection:
              selection:
                Image|endswith: '\evil.exe'
              condition: selection
        """)
        assert convert_sigma_rule(_only_doc(doc)).attack == ["T1059.001"]


# ---------------------------------------------------------------------------
# Accepted: glob translation
# ---------------------------------------------------------------------------


class TestGlobTranslation:
    def test_leading_star_becomes_endswith(self) -> None:
        doc = sigma(r"""
            title: Rundll32 anywhere
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image: '*\rundll32.exe'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {"Image|endswith": r"\rundll32.exe"}
        assert matches(event_from(EventID=1, Image=r"C:\Windows\System32\rundll32.exe"), rule)
        assert not matches(event_from(EventID=1, Image=r"C:\Windows\System32\notepad.exe"), rule)

    def test_trailing_star_becomes_startswith(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image: 'C:\Temp\*'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {"Image|startswith": "C:\\Temp\\"}

    def test_bounded_star_becomes_contains(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine: '*mimikatz*'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {"CommandLine|contains": "mimikatz"}

    def test_question_mark_falls_back_to_anchored_regex(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image: 'C:\Users\???\evil.exe'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        spec, pattern = next(iter(rule.detection.items()))
        assert spec == "Image|re"
        assert pattern == [r"^C:\\Users\\...\\evil\.exe$"]
        assert matches(event_from(EventID=1, Image=r"C:\Users\bob\evil.exe"), rule)
        assert not matches(event_from(EventID=1, Image=r"C:\Users\bobby\evil.exe"), rule)

    def test_mixed_shapes_in_one_list_fall_back_to_regex(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine: ['*foo*bar*', 'exact-match']
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        spec, patterns = next(iter(rule.detection.items()))
        assert spec == "CommandLine|re"
        assert patterns == [r"^.*foo.*bar.*$", r"^exact\-match$"]

    def test_no_wildcards_stays_a_literal_equals(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                DestinationPort: ['4444', '1337']
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {"DestinationPort": ["4444", "1337"]}


# ---------------------------------------------------------------------------
# Accepted: condition combinators
# ---------------------------------------------------------------------------


class TestConditionCombinators:
    def test_and_merges_fields_from_both_selections(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel1:
                Image|endswith: '\cmd.exe'
              sel2:
                ParentImage|endswith: '\winword.exe'
              condition: sel1 and sel2
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.condition == "all"
        assert rule.detection == {
            "Image|endswith": r"\cmd.exe",
            "ParentImage|endswith": r"\winword.exe",
        }

    def test_or_between_single_field_selections_merges_into_one_list(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: network_connection, product: windows}
            detection:
              a:
                DestinationPort: 4444
              b:
                DestinationPort: 8443
              condition: a or b
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.condition == "any"
        assert rule.detection == {"DestinationPort": [4444, 8443]}

    def test_and_with_identical_duplicate_field_is_harmless(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel1:
                Image|endswith: '\cmd.exe'
              sel2:
                Image|endswith: '\cmd.exe'
                ParentImage|endswith: '\explorer.exe'
              condition: sel1 and sel2
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {
            "Image|endswith": r"\cmd.exe",
            "ParentImage|endswith": r"\explorer.exe",
        }

    def test_and_not_filter_negates_a_single_field_filter(self) -> None:
        doc = sigma(r"""
            title: t
            level: high
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image|endswith: '\powershell.exe'
              filter:
                ParentImage|endswith: '\explorer.exe'
              condition: selection and not filter
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.condition == "all"
        assert rule.detection == {
            "Image|endswith": r"\powershell.exe",
            "ParentImage|endswith|not": r"\explorer.exe",
        }
        fires = event_from(EventID=1, Image=r"C:\W\powershell.exe", ParentImage=r"C:\W\cmd.exe")
        quiet = event_from(EventID=1, Image=r"C:\W\powershell.exe", ParentImage=r"C:\W\explorer.exe")
        assert matches(fires, rule)
        assert not matches(quiet, rule)

    def test_1_of_them(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel_a:
                Image|endswith: '\a.exe'
              sel_b:
                Image|endswith: '\b.exe'
              condition: 1 of them
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.condition == "any"
        assert rule.detection == {"Image|endswith": [r"\a.exe", r"\b.exe"]}

    def test_all_of_wildcard_prefix(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel_a:
                Image|endswith: '\cmd.exe'
              sel_b:
                ParentImage|endswith: '\winword.exe'
              other:
                DestinationPort: 4444
              condition: all of sel*
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.condition == "all"
        assert rule.detection == {
            "Image|endswith": r"\cmd.exe",
            "ParentImage|endswith": r"\winword.exe",
        }

    def test_list_of_single_field_maps_is_an_inline_or(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                - Image|endswith: '\a.exe'
                - Image|endswith: '\b.exe'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.condition == "any"
        assert rule.detection == {"Image|endswith": [r"\a.exe", r"\b.exe"]}


# ---------------------------------------------------------------------------
# Rejected: logsource
# ---------------------------------------------------------------------------


class TestLogsourceRejections:
    def test_non_windows_product_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: linux}
            detection:
              selection: {Image|endswith: '/bin/bash'}
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="unsupported logsource product"):
            convert_sigma_rule(_only_doc(doc))

    def test_non_sysmon_service_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows, service: security}
            detection:
              selection: {Image|endswith: '\cmd.exe'}
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="unsupported logsource service"):
            convert_sigma_rule(_only_doc(doc))

    def test_unsupported_category_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: some_made_up_category, product: windows}
            detection:
              selection: {Image|endswith: '\cmd.exe'}
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="unsupported logsource category"):
            convert_sigma_rule(_only_doc(doc))

    def test_missing_logsource_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            detection:
              selection: {Image|endswith: '\cmd.exe'}
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="missing required field: logsource"):
            convert_sigma_rule(_only_doc(doc))


# ---------------------------------------------------------------------------
# Rejected: structural / condition-language limits
# ---------------------------------------------------------------------------


class TestStructuralRejections:
    def test_missing_title(self) -> None:
        doc = sigma(r"""
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\cmd.exe'}
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="missing required field: title"):
            convert_sigma_rule(_only_doc(doc))

    def test_missing_condition(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\cmd.exe'}
        """)
        with pytest.raises(SigmaImportError, match="detection.condition"):
            convert_sigma_rule(_only_doc(doc))

    def test_list_condition_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\cmd.exe'}
              condition: [selection]
        """)
        with pytest.raises(SigmaImportError, match="single string"):
            convert_sigma_rule(_only_doc(doc))

    def test_undefined_selection_reference(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\cmd.exe'}
              condition: ghost
        """)
        with pytest.raises(SigmaImportError, match="undefined selection"):
            convert_sigma_rule(_only_doc(doc))

    def test_nested_boolean_expression_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel1: {Image|endswith: '\a.exe'}
              sel2: {Image|endswith: '\b.exe'}
              sel3: {Image|endswith: '\c.exe'}
              condition: (sel1 or sel2) and sel3
        """)
        with pytest.raises(SigmaImportError, match="unsupported condition expression"):
            convert_sigma_rule(_only_doc(doc))

    def test_or_between_multi_field_selections_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel1:
                Image|endswith: '\a.exe'
                CommandLine|contains: 'x'
              sel2:
                Image|endswith: '\b.exe'
              condition: sel1 or sel2
        """)
        with pytest.raises(SigmaImportError, match="cannot flatten"):
            convert_sigma_rule(_only_doc(doc))

    def test_and_with_genuinely_conflicting_values_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              sel1: {Image|endswith: '\cmd.exe'}
              sel2: {Image|endswith: '\powershell.exe'}
              condition: sel1 and sel2
        """)
        with pytest.raises(SigmaImportError, match="collision"):
            convert_sigma_rule(_only_doc(doc))

    def test_and_not_filter_with_multi_field_filter_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\powershell.exe'}
              filter:
                ParentImage|endswith: '\explorer.exe'
                CommandLine|contains: 'x'
              condition: selection and not filter
        """)
        with pytest.raises(SigmaImportError, match="must be exactly one field"):
            convert_sigma_rule(_only_doc(doc))

    def test_and_not_filter_after_an_or_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              a: {Image|endswith: '\a.exe'}
              b: {Image|endswith: '\b.exe'}
              filter: {ParentImage|endswith: '\explorer.exe'}
              condition: a or b and not filter
        """)
        with pytest.raises(SigmaImportError, match="cannot combine an OR"):
            convert_sigma_rule(_only_doc(doc))


# ---------------------------------------------------------------------------
# Rejected: field modifiers and values
# ---------------------------------------------------------------------------


class TestFieldRejections:
    @pytest.mark.parametrize("modifier", ["all", "base64", "cidr", "gt", "exists"])
    def test_unsupported_modifiers_are_rejected(self, modifier: str) -> None:
        doc = sigma(f"""
            title: t
            logsource: {{category: process_creation, product: windows}}
            detection:
              selection:
                CommandLine|{modifier}: 'x'
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="unsupported modifier"):
            convert_sigma_rule(_only_doc(doc))

    def test_unknown_modifier_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine|frobnicate: 'x'
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="unknown modifier"):
            convert_sigma_rule(_only_doc(doc))

    def test_cased_modifier_is_accepted_and_ignored(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                Image|endswith|cased: '\CMD.exe'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {"Image|endswith": r"\CMD.exe"}
        # The matcher is always case-insensitive, so lowercase still fires.
        assert matches(event_from(EventID=1, Image=r"C:\W\cmd.exe"), rule)

    def test_two_operator_modifiers_on_one_field_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine|contains|startswith: 'x'
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="more than one operator modifier"):
            convert_sigma_rule(_only_doc(doc))

    def test_null_value_is_rejected(self) -> None:
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine:
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="null value"):
            convert_sigma_rule(_only_doc(doc))

    def test_re_modifier_accepts_a_safe_pattern_and_round_trips(self) -> None:
        """An explicit |re modifier hands the matcher a regex the Sigma
        author wrote verbatim (unlike a bare-value glob, which this module
        generates itself and is safe by construction), so it goes through
        backend/engine/redos_guard.py -- an ordinary pattern must still come
        out the other side and actually fire, not just be accepted."""
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine|re: '.*-enc(odedcommand)?\s'
              condition: selection
        """)
        rule = convert_sigma_rule(_only_doc(doc))
        assert rule.detection == {"CommandLine|re": r".*-enc(odedcommand)?\s"}
        assert matches(event_from(EventID=1, CommandLine="powershell.exe -enc AB=="), rule)

    def test_re_modifier_rejects_a_catastrophic_backtracking_pattern(self) -> None:
        """A regex an attacker crafts to hang the matcher's hot path must be
        rejected at import time, before it ever reaches a live rule -- see
        tests/test_redos_guard.py for the check itself."""
        doc = sigma(r"""
            title: t
            logsource: {category: process_creation, product: windows}
            detection:
              selection:
                CommandLine|re: '(a+)+$'
              condition: selection
        """)
        with pytest.raises(SigmaImportError, match="unsafe regex"):
            convert_sigma_rule(_only_doc(doc))


# ---------------------------------------------------------------------------
# Batch import: file-level parsing, multi-document, partial success
# ---------------------------------------------------------------------------


class TestImportSigmaText:
    def test_invalid_yaml_is_reported_not_raised(self) -> None:
        result = import_sigma_text("not: valid: yaml: [", source_name="broken.yml")
        assert result.accepted == []
        assert len(result.rejected) == 1
        assert "invalid YAML" in result.rejected[0]["reason"]

    def test_empty_file_is_reported(self) -> None:
        result = import_sigma_text("", source_name="empty.yml")
        assert result.accepted == []
        assert result.rejected == [{"title": "empty.yml", "reason": "empty file"}]

    def test_multi_document_file_converts_each_independently(self) -> None:
        text = sigma(r"""
            title: First rule
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\a.exe'}
              condition: selection
            ---
            title: Second rule
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\b.exe'}
              condition: selection
        """)
        result = import_sigma_text(text)
        assert len(result.accepted) == 2
        assert {r.title for r in result.accepted} == {"First rule", "Second rule"}

    def test_one_bad_document_does_not_block_the_rest_of_the_batch(self) -> None:
        text = sigma(r"""
            title: Good rule
            logsource: {category: process_creation, product: windows}
            detection:
              selection: {Image|endswith: '\a.exe'}
              condition: selection
            ---
            title: Bad rule
            logsource: {category: made_up, product: windows}
            detection:
              selection: {Image|endswith: '\b.exe'}
              condition: selection
        """)
        result = import_sigma_text(text)
        assert len(result.accepted) == 1
        assert result.accepted[0].title == "Good rule"
        assert len(result.rejected) == 1
        assert result.rejected[0]["title"] == "Bad rule"
        assert "unsupported logsource category" in result.rejected[0]["reason"]


def _only_doc(text: str) -> dict:
    import yaml

    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# The /admin/rules/import-sigma endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_rules(tmp_path, monkeypatch):
    """Point the whole rule pipeline at an empty temp directory instead of
    the real `rules/` tree.

    The endpoint writes accepted rules under `admin.SIGMA_IMPORT_DIR` and
    then calls `rule_store.load(settings.rules_dir)` to go live -- without
    this fixture, an API-level test would (a) write real files into the
    actual project's `rules/imported_sigma/` and (b) reload the real 100+
    rule corpus, making "how many rules are loaded now" an unusable
    assertion. `SIGMA_IMPORT_DIR` is computed once at import time, so it is
    repointed directly rather than relying on the `settings.rules_dir`
    patch to reach it.
    """
    from backend.api import admin
    from backend.config import settings

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    monkeypatch.setattr(settings, "rules_dir", rules_dir)
    monkeypatch.setattr(admin, "SIGMA_IMPORT_DIR", rules_dir / "imported_sigma")
    return rules_dir


VALID_SIGMA = sigma(r"""
    title: Suspicious PowerShell Encoded Command
    level: high
    logsource: {category: process_creation, product: windows}
    detection:
      selection:
        Image|endswith: '\powershell.exe'
      condition: selection
""")

INVALID_SIGMA = sigma(r"""
    title: Bad logsource
    logsource: {category: made_up, product: windows}
    detection:
      selection: {Image|endswith: '\x.exe'}
      condition: selection
""")


class TestImportSigmaEndpoint:
    async def test_valid_file_is_accepted_written_and_loaded(self, tmp_db, isolated_rules) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post(
                    "/admin/rules/import-sigma",
                    files={"files": ("good.yml", VALID_SIGMA, "application/yaml")},
                )
                assert r.status_code == 200
                body = r.json()
                assert len(body["accepted"]) == 1
                assert body["accepted"][0]["title"] == "Suspicious PowerShell Encoded Command"
                assert body["rejected"] == []
                assert body["rules_loaded"] == 1

        written = list(isolated_rules.glob("imported_sigma/*.yml"))
        assert len(written) == 1
        assert written[0].name.startswith("SIGMA-")

    async def test_invalid_file_is_reported_not_written(self, tmp_db, isolated_rules) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post(
                    "/admin/rules/import-sigma",
                    files={"files": ("bad.yml", INVALID_SIGMA, "application/yaml")},
                )
                assert r.status_code == 200
                body = r.json()
                assert body["accepted"] == []
                assert len(body["rejected"]) == 1
                assert body["rejected"][0]["source"] == "bad.yml"
                assert "unsupported logsource category" in body["rejected"][0]["reason"]
                assert body["rules_loaded"] == 0

        assert not list(isolated_rules.glob("imported_sigma/*.yml"))

    async def test_one_good_one_bad_file_in_the_same_request(self, tmp_db, isolated_rules) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post(
                    "/admin/rules/import-sigma",
                    files=[
                        ("files", ("good.yml", VALID_SIGMA, "application/yaml")),
                        ("files", ("bad.yml", INVALID_SIGMA, "application/yaml")),
                    ],
                )
                body = r.json()
                assert len(body["accepted"]) == 1
                assert len(body["rejected"]) == 1
                assert body["rules_loaded"] == 1

    async def test_duplicate_import_gets_a_suffixed_id_not_overwritten(self, tmp_db, isolated_rules) -> None:
        from backend.main import app

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                first = await c.post(
                    "/admin/rules/import-sigma",
                    files={"files": ("good.yml", VALID_SIGMA, "application/yaml")},
                )
                second = await c.post(
                    "/admin/rules/import-sigma",
                    files={"files": ("good.yml", VALID_SIGMA, "application/yaml")},
                )
                first_id = first.json()["accepted"][0]["id"]
                second_id = second.json()["accepted"][0]["id"]
                assert first_id != second_id
                assert second.json()["rules_loaded"] == 2

    async def test_oversized_file_is_rejected_without_parsing(self, tmp_db, isolated_rules) -> None:
        from backend.api.admin import MAX_UPLOAD_BYTES
        from backend.main import app

        huge = "x" * (MAX_UPLOAD_BYTES + 1)
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post(
                    "/admin/rules/import-sigma",
                    files={"files": ("huge.yml", huge, "application/yaml")},
                )
                body = r.json()
                assert body["accepted"] == []
                assert "import limit" in body["rejected"][0]["reason"]
