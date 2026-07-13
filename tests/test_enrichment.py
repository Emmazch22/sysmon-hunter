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
        provider simply reports itself unavailable.

        The keys are cleared explicitly so this holds whether or not the machine
        running the tests happens to have a populated .env."""
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
        """A second lookup of the same indicator returns the cached object, so no
        request is made -- the safeguard that keeps a tight free tier usable."""
        from backend.config import settings

        monkeypatch.setattr(settings, "abuseipdb_api_key", "")
        monkeypatch.setattr(settings, "virustotal_api_key", "")

        service = EnrichmentService(ttl_seconds=3600)
        first = await service.enrich("185.234.72.19")
        second = await service.enrich("185.234.72.19")
        assert first is second
