"""IOC enrichment.

The commitments under test: private IPs are never sent to a third party, the
worst verdict wins, and the whole thing degrades gracefully with no API keys --
because "works the moment you clone it" is the point.
"""

from __future__ import annotations

import pytest

from backend.engine.enrichment import (
    Enrichment,
    EnrichmentService,
    ProviderResult,
    classify_indicator,
)


class TestClassification:
    def test_public_ip_is_enrichable(self) -> None:
        assert classify_indicator("185.234.72.19") == "ip"

    def test_domain_is_enrichable(self) -> None:
        assert classify_indicator("evil-c2.example.com") == "domain"

    @pytest.mark.parametrize(
        "private", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"]
    )
    def test_private_and_reserved_ips_are_never_enriched(self, private: str) -> None:
        """Private IPs must return None -- enriching them is pointless and leaks
        internal addressing to a third-party service."""
        assert classify_indicator(private) is None

    def test_garbage_is_rejected(self) -> None:
        assert classify_indicator("not an indicator") is None
        assert classify_indicator("") is None


class TestWorstVerdict:
    def test_worst_verdict_wins(self) -> None:
        """One credible malicious verdict outweighs several clean ones -- an
        analyst cares about the worst thing known, not the average."""
        enrichment = Enrichment(
            indicator="1.2.3.4",
            indicator_type="ip",
            results=[
                ProviderResult("A", available=True, verdict="clean", summary=""),
                ProviderResult("B", available=True, verdict="malicious", summary=""),
                ProviderResult("C", available=True, verdict="clean", summary=""),
            ],
        )
        assert enrichment.worst_verdict == "malicious"

    def test_unavailable_providers_are_ignored_in_verdict(self) -> None:
        """A provider that could not be queried must not count as a clean vote."""
        enrichment = Enrichment(
            indicator="1.2.3.4",
            indicator_type="ip",
            results=[
                ProviderResult("A", available=False, verdict="unknown", summary=""),
                ProviderResult("B", available=True, verdict="suspicious", summary=""),
            ],
        )
        assert enrichment.worst_verdict == "suspicious"


class TestGracefulDegradation:
    async def test_no_keys_returns_unavailable_not_error(self, monkeypatch) -> None:
        """With no keys configured, enrichment must still return a result -- every
        provider simply reports itself unavailable. Keys are cleared explicitly so
        this holds whether or not the machine has a populated .env."""
        from backend.config import settings

        monkeypatch.setattr(settings, "abuseipdb_api_key", "")
        monkeypatch.setattr(settings, "virustotal_api_key", "")

        service = EnrichmentService()
        result = await service.enrich("185.234.72.19")
        assert result is not None
        assert all(not r.available for r in result.results)
        assert result.worst_verdict == "unknown"

    async def test_private_ip_returns_none(self) -> None:
        service = EnrichmentService()
        assert await service.enrich("10.0.0.1") is None

    async def test_cache_prevents_duplicate_lookups(self, monkeypatch) -> None:
        """A second lookup returns the cached object, so no request is made."""
        from backend.config import settings

        monkeypatch.setattr(settings, "abuseipdb_api_key", "")
        monkeypatch.setattr(settings, "virustotal_api_key", "")

        service = EnrichmentService(ttl_seconds=3600)
        first = await service.enrich("185.234.72.19")
        second = await service.enrich("185.234.72.19")
        assert first is second


class TestHashEnrichment:
    """Hash enrichment reuses the enrichment pipeline for the highest-value
    lookup the tool offers: a flagged hash is a confirmed-malicious binary."""

    def test_hashes_are_classified_by_length(self) -> None:
        from backend.engine.enrichment import classify_indicator

        assert classify_indicator("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # md5
        assert (
            classify_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"
        )  # sha1
        assert (
            classify_indicator(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            == "hash"
        )  # sha256

    def test_non_hex_of_hash_length_is_not_a_hash(self) -> None:
        """A 32-character string that is not hex is not an MD5 -- length alone is
        not enough."""
        from backend.engine.enrichment import classify_indicator

        assert classify_indicator("z" * 32) is None

    def test_parse_sysmon_hashes(self) -> None:
        from backend.engine.enrichment import parse_sysmon_hashes

        parsed = parse_sysmon_hashes("MD5=ABC,SHA256=DEF,IMPHASH=00FF")
        assert parsed == {"md5": "ABC", "sha256": "DEF", "imphash": "00FF"}

    def test_best_hash_prefers_sha256(self) -> None:
        """SHA256 is the most collision-resistant, so it is the lookup key when
        present -- MD5 is a last resort because collisions are cheap."""
        from backend.engine.enrichment import best_hash

        assert best_hash({"md5": "A", "sha1": "B", "sha256": "C"}) == "C"
        assert best_hash({"md5": "A", "sha1": "B"}) == "B"
        assert best_hash({"md5": "A"}) == "A"
        assert best_hash({}) is None

    async def test_hash_enrichment_dispatches_to_virustotal_only(
        self, monkeypatch
    ) -> None:
        """A hash goes to VirusTotal's file endpoint, not AbuseIPDB (which only
        knows IPs)."""
        from backend.config import settings
        from backend.engine.enrichment import EnrichmentService

        monkeypatch.setattr(settings, "virustotal_api_key", "")
        service = EnrichmentService()
        result = await service.enrich("d41d8cd98f00b204e9800998ecf8427e")
        assert result is not None
        assert result.indicator_type == "hash"
        assert [r.provider for r in result.results] == ["VirusTotal"]
