"""False-positive similarity heuristic.

Two layers, tested separately: `backend/engine/noise.py` is pure arithmetic --
given a candidate and a history of past false positives, does it score above
threshold, and why -- with no I/O of its own, so it is tested directly against
its public functions (`fingerprint_from_incident`, `assess`), never its
underscore-prefixed helpers. `backend/api/incidents.py` is the wiring: it
fetches the false-positive history from the database, batches rule IDs, and
attaches the result to `GET /incidents` and `GET /incidents/{id}` as a `noise`
field -- that part is tested at the HTTP layer, the same way the rest of
`incidents.py` is in `test_incidents_api.py`.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from backend.engine.noise import Fingerprint, assess, fingerprint_from_incident
from backend.models import db
from backend.models.schemas import Detection, Event, Incident, Severity

# ---------------------------------------------------------------------------
# engine/noise.py -- pure similarity scoring
# ---------------------------------------------------------------------------


class TestFingerprintFromIncident:
    def test_root_image_and_chain_are_lowercased_basenames(self) -> None:
        """The root is `chain[0]`, not a separate field -- `Incident.chain` is
        documented as running root-to-leaf, so the first element already is
        the root image."""
        incident = {
            "id": "abc",
            "chain": [
                r"C:\Windows\explorer.exe",
                r"C:\Windows\System32\RUNDLL32.EXE",
            ],
            "techniques": ["T1218"],
        }
        fp = fingerprint_from_incident(incident)
        assert fp.root_image == "explorer.exe"
        assert fp.chain == ("explorer.exe", "rundll32.exe")

    def test_empty_chain_yields_empty_root_and_chain(self) -> None:
        fp = fingerprint_from_incident({"id": "x", "chain": [], "techniques": []})
        assert fp.root_image == ""
        assert fp.chain == ()

    def test_rule_ids_default_to_none_when_not_supplied(self) -> None:
        """`None` means "not fetched", distinct from an empty set meaning
        "fetched, but this incident fired no rules" -- `assess` treats the two
        very differently (see the renormalization test below)."""
        fp = fingerprint_from_incident({"id": "x", "chain": [], "techniques": []})
        assert fp.rule_ids is None

    def test_rule_ids_are_captured_when_supplied(self) -> None:
        fp = fingerprint_from_incident(
            {"id": "x", "chain": [], "techniques": []}, rule_ids=["SYS-001", "SYS-002"]
        )
        assert fp.rule_ids == frozenset({"SYS-001", "SYS-002"})


class TestAssess:
    def test_identical_incidents_score_at_the_top_and_cite_every_reason(self) -> None:
        candidate = Fingerprint(
            incident_id="new",
            root_image="rundll32.exe",
            chain=("explorer.exe", "rundll32.exe"),
            techniques=frozenset({"T1218"}),
            rule_ids=frozenset({"SYS-008"}),
        )
        reference = Fingerprint(
            incident_id="old-fp",
            root_image="rundll32.exe",
            chain=("explorer.exe", "rundll32.exe"),
            techniques=frozenset({"T1218"}),
            rule_ids=frozenset({"SYS-008"}),
        )
        result = assess(candidate, [reference])
        assert result.score == 1.0
        assert len(result.matches) == 1
        assert result.matches[0].incident_id == "old-fp"
        assert set(result.matches[0].matched_on) == {
            "same detection rules",
            "same ATT&CK techniques",
            "same root process",
            "overlapping process chain",
        }

    def test_completely_unrelated_incidents_score_zero_with_no_matches(self) -> None:
        candidate = Fingerprint(
            incident_id="new",
            root_image="powershell.exe",
            chain=("explorer.exe", "powershell.exe"),
            techniques=frozenset({"T1059.001"}),
            rule_ids=frozenset({"SYS-002"}),
        )
        reference = Fingerprint(
            incident_id="old-fp",
            root_image="sqlservr.exe",
            chain=("services.exe", "sqlservr.exe"),
            techniques=frozenset({"T1505.003"}),
            rule_ids=frozenset({"SYS-089"}),
        )
        result = assess(candidate, [reference])
        assert result.score == 0.0
        assert result.matches == []

    def test_shared_rule_ids_and_root_process_clear_the_default_threshold(self) -> None:
        """Rule IDs (weight 0.5) plus root process (weight 0.2) sum to 0.7,
        clearing the 0.6 default even with different techniques and chains --
        this is the "same tool, same launch point, still flagged" case a
        recurring benign admin script produces."""
        candidate = Fingerprint(
            incident_id="new",
            root_image="anydesk.exe",
            chain=("services.exe", "anydesk.exe"),
            techniques=frozenset({"T1219"}),
            rule_ids=frozenset({"SYS-155"}),
        )
        reference = Fingerprint(
            incident_id="old-fp",
            root_image="anydesk.exe",
            chain=("explorer.exe", "anydesk.exe"),
            techniques=frozenset({"T1219", "T1105"}),
            rule_ids=frozenset({"SYS-155"}),
        )
        result = assess(candidate, [reference])
        assert result.score >= 0.6
        assert "same detection rules" in result.matches[0].matched_on
        assert "same root process" in result.matches[0].matched_on
        # Techniques overlap partially (jaccard 0.5) and chains do not overlap
        # at all -- present in the weighted score but below the 0.5 reason
        # threshold to be cited as a matched-on reason for chain overlap.
        assert "overlapping process chain" not in result.matches[0].matched_on

    def test_missing_candidate_rule_ids_drops_and_renormalizes_that_component(self) -> None:
        """A list-view candidate with `rule_ids=None` (not fetched, to avoid an
        N+1 query) must not be silently scored as if it shared zero rules with
        every reference -- the weight is dropped and the rest renormalized, so
        a strong match on the remaining three signals can still clear
        threshold."""
        candidate = Fingerprint(
            incident_id="new",
            root_image="rundll32.exe",
            chain=("explorer.exe", "rundll32.exe"),
            techniques=frozenset({"T1218"}),
            rule_ids=None,
        )
        reference = Fingerprint(
            incident_id="old-fp",
            root_image="rundll32.exe",
            chain=("explorer.exe", "rundll32.exe"),
            techniques=frozenset({"T1218"}),
            rule_ids=frozenset({"SYS-008"}),
        )
        result = assess(candidate, [reference])
        # (0.2 techniques + 0.2 root + 0.1 chain) / 0.5 total weight == 1.0
        assert result.score == 1.0

    def test_two_incidents_with_no_techniques_are_not_treated_as_identical(self) -> None:
        """Two empty technique sets are "no signal", not "perfect match" --
        otherwise every incident with no ATT&CK coverage would look maximally
        similar to every false positive with none either. Everything else
        about these two fingerprints matches exactly, so this isolates the
        technique component: if empty sets scored as identical, "same ATT&CK
        techniques" would appear in matched_on alongside the other three."""
        candidate = Fingerprint(
            incident_id="new", root_image="cmd.exe", chain=("cmd.exe",),
            techniques=frozenset(), rule_ids=frozenset({"SYS-999"}),
        )
        reference = Fingerprint(
            incident_id="old-fp", root_image="cmd.exe", chain=("cmd.exe",),
            techniques=frozenset(), rule_ids=frozenset({"SYS-999"}),
        )
        result = assess(candidate, [reference])
        assert result.matches, "rule IDs, root, and chain all match -- this must clear threshold"
        assert "same detection rules" in result.matches[0].matched_on
        assert "same ATT&CK techniques" not in result.matches[0].matched_on

    def test_matches_are_capped_and_sorted_strongest_first(self) -> None:
        candidate = Fingerprint(
            incident_id="new", root_image="rundll32.exe",
            chain=("explorer.exe", "rundll32.exe"),
            techniques=frozenset({"T1218"}), rule_ids=frozenset({"SYS-008"}),
        )
        history = [
            Fingerprint(
                incident_id=f"fp-{i}", root_image="rundll32.exe",
                chain=("explorer.exe", "rundll32.exe"),
                techniques=frozenset({"T1218"}), rule_ids=frozenset({"SYS-008"}),
            )
            for i in range(5)
        ]
        # Make one of them a slightly weaker match so ordering is meaningful.
        history[2] = Fingerprint(
            incident_id="fp-2", root_image="rundll32.exe",
            chain=("explorer.exe",), techniques=frozenset(), rule_ids=frozenset({"SYS-008"}),
        )
        result = assess(candidate, history, limit=3)
        assert len(result.matches) == 3
        assert result.score == result.matches[0].score
        assert all(
            result.matches[i].score >= result.matches[i + 1].score
            for i in range(len(result.matches) - 1)
        )

    def test_empty_history_scores_zero(self) -> None:
        candidate = Fingerprint(
            incident_id="new", root_image="x", chain=(), techniques=frozenset(), rule_ids=None
        )
        result = assess(candidate, [])
        assert result.score == 0.0
        assert result.matches == []

    def test_threshold_is_configurable(self) -> None:
        """A weak match (root process only, weight 0.2) clears a low threshold
        but not the library default -- the API layer's `settings.
        noise_similarity_threshold` depends on this being a real parameter,
        not a module-level constant baked into `assess`."""
        candidate = Fingerprint(
            incident_id="new", root_image="cmd.exe", chain=("cmd.exe",),
            techniques=frozenset({"T1059"}), rule_ids=frozenset({"SYS-001"}),
        )
        reference = Fingerprint(
            incident_id="old-fp", root_image="cmd.exe", chain=("svchost.exe",),
            techniques=frozenset({"T1219"}), rule_ids=frozenset({"SYS-155"}),
        )
        assert assess(candidate, [reference]).score == 0.0
        low_threshold_result = assess(candidate, [reference], threshold=0.15)
        assert low_threshold_result.score > 0.0


# ---------------------------------------------------------------------------
# api/incidents.py -- wiring the score into GET /incidents and /incidents/{id}
# ---------------------------------------------------------------------------


async def _make_incident(
    incident_id: str,
    *,
    host: str = "WS-01",
    rule_id: str = "SYS-001",
    techniques: list[str] | None = None,
    chain: list[str] | None = None,
    status: str = "open",
) -> None:
    inc = Incident(id=incident_id, host=host, root_guid=f"g-{incident_id}")
    inc.chain = chain if chain is not None else [r"C:\Windows\explorer.exe"]
    inc.add(
        Detection(
            rule_id=rule_id,
            title="x",
            severity=Severity.HIGH,
            attack=techniques if techniques is not None else ["T1566.001"],
            event=Event(event_id=1),
        )
    )
    await db.upsert_incident(inc, actionable=True)
    await db.save_detection(inc.detections[0])
    if status != "open":
        await db.update_incident_status(incident_id, status)


class TestNoiseWiringOnListIncidents:
    async def test_open_incident_similar_to_a_false_positive_is_flagged(self, tmp_db) -> None:
        from backend.main import app

        await _make_incident(
            "fp1",
            rule_id="SYS-008",
            techniques=["T1218"],
            chain=[r"C:\Windows\explorer.exe", r"C:\Windows\System32\rundll32.exe"],
            status="false_positive",
        )
        await _make_incident(
            "new1",
            rule_id="SYS-008",
            techniques=["T1218"],
            chain=[r"C:\Windows\explorer.exe", r"C:\Windows\System32\rundll32.exe"],
        )

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents")
                assert r.status_code == 200
                items = {i["id"]: i for i in r.json()["items"]}

                assert items["new1"]["noise"] is not None
                assert items["new1"]["noise"]["score"] >= 0.6
                assert items["new1"]["noise"]["matches"][0]["incident_id"] == "fp1"

                # The false positive itself is never scored -- it is the
                # history, not a candidate.
                assert items["fp1"]["noise"] is None

    async def test_dissimilar_open_incident_is_not_flagged(self, tmp_db) -> None:
        from backend.main import app

        await _make_incident(
            "fp2", rule_id="SYS-008", techniques=["T1218"], status="false_positive"
        )
        await _make_incident(
            "new2",
            rule_id="SYS-060",
            techniques=["T1071.001"],
            chain=[r"C:\Windows\System32\svchost.exe"],
        )

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents")
                items = {i["id"]: i for i in r.json()["items"]}
                assert items["new2"]["noise"] is None

    async def test_no_false_positive_history_means_no_scoring(self, tmp_db) -> None:
        """Nothing has ever been dismissed yet -- every incident's `noise` key
        is present (the console never has to special-case a missing field)
        but always `None`."""
        from backend.main import app

        await _make_incident("solo")

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents")
                item = r.json()["items"][0]
                assert "noise" in item
                assert item["noise"] is None

    async def test_closed_incident_is_never_scored_even_with_matching_history(
        self, tmp_db
    ) -> None:
        from backend.main import app

        await _make_incident(
            "fp3", rule_id="SYS-008", techniques=["T1218"], status="false_positive"
        )
        await _make_incident(
            "closed1", rule_id="SYS-008", techniques=["T1218"], status="closed"
        )

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents")
                items = {i["id"]: i for i in r.json()["items"]}
                assert items["closed1"]["noise"] is None


class TestNoiseWiringOnGetIncident:
    async def test_detail_view_carries_the_same_assessment_as_the_list_view(
        self, tmp_db
    ) -> None:
        from backend.main import app

        await _make_incident(
            "fp4",
            rule_id="SYS-155",
            techniques=["T1219"],
            chain=[r"C:\Windows\System32\services.exe", r"C:\Users\Public\AnyDesk.exe"],
            status="false_positive",
        )
        await _make_incident(
            "new4",
            rule_id="SYS-155",
            techniques=["T1219"],
            chain=[r"C:\Windows\System32\services.exe", r"C:\Users\Public\AnyDesk.exe"],
        )

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents/new4")
                assert r.status_code == 200
                body = r.json()
                assert body["noise"] is not None
                assert body["noise"]["score"] >= 0.6
                assert body["noise"]["matches"][0]["incident_id"] == "fp4"

    async def test_threshold_from_settings_is_honored(self, tmp_db, monkeypatch) -> None:
        """A match that clears the default 0.6 threshold must stop being
        flagged once `settings.noise_similarity_threshold` is raised past its
        score -- proves the API layer reads the live setting rather than a
        hardcoded default."""
        from backend.api import incidents as incidents_api
        from backend.main import app

        await _make_incident(
            "fp5", rule_id="SYS-008", techniques=["T1218"], status="false_positive"
        )
        await _make_incident("new5", rule_id="SYS-008", techniques=["T1218"])

        # Both incidents share every signal (rule ID, techniques, default
        # chain), so their similarity score is a perfect 1.0 -- push the
        # threshold above that rather than guessing a value just under it.
        monkeypatch.setattr(incidents_api.settings, "noise_similarity_threshold", 1.01)

        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/incidents/new5")
                assert r.json()["noise"] is None
