"""IOC enrichment.

Turns an indicator the engine extracted -- a beacon's destination IP, a
suspicious domain -- into context an analyst can act on: reputation scores,
geolocation, how many times it has been reported. The difference between
"periodic connection to 185.234.72.19" and "185.234.72.19, reported 47 times,
hosting in Russia, 12 vendors flag it malicious".

Three design commitments:

1. **Works with no API keys.** Every provider degrades gracefully: with no key
   configured it reports itself unavailable and is skipped, rather than erroring.
   The project is useful the moment it is cloned, and better once keys are added.

2. **On-demand, never in the hot path.** Enrichment runs when an analyst asks
   for it on a specific incident, not on every event. The free tiers here are
   measured in requests per minute; enriching every network connection would
   exhaust the quota in seconds and add a third-party latency tax to ingestion.

3. **Cached hard.** An IP's reputation does not change between two clicks a
   minute apart. With free tiers this tight, caching is not an optimization, it
   is what makes the feature usable at all.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from backend.config import settings

log = logging.getLogger(__name__)


@dataclass
class ProviderResult:
    """One provider's answer about one indicator."""

    provider: str
    available: bool  # was the provider actually queryable (key present, no error)?
    summary: str  # one-line human verdict for the UI
    verdict: str = "unknown"  # "malicious" | "suspicious" | "clean" | "unknown"
    details: dict[str, Any] = field(default_factory=dict)
    link: Optional[str] = None  # URL to the full report on the provider


@dataclass
class Enrichment:
    """The combined enrichment for one indicator across all providers."""

    indicator: str
    indicator_type: str  # "ip" | "domain"
    results: list[ProviderResult] = field(default_factory=list)
    cached_at: float = field(default_factory=time.time)

    @property
    def worst_verdict(self) -> str:
        """The most severe verdict any provider returned.

        An analyst triaging cares about the worst thing known about an
        indicator, not the average -- one credible "malicious" outweighs three
        "clean"s, so verdicts are reduced to their maximum severity, not blended.
        """
        order = ["malicious", "suspicious", "unknown", "clean"]
        for verdict in order:
            if any(r.verdict == verdict for r in self.results if r.available):
                return verdict
        return "unknown"


def classify_indicator(value: str) -> Optional[str]:
    """Return "ip", "domain", or None for something we do not enrich.

    Private and reserved IPs return None: enriching 10.0.0.1 against a global
    reputation service is pointless and leaks internal addressing to a third
    party, which is its own small security problem.
    """
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return None
        return "ip"
    except ValueError:
        pass

    # Very loose domain check: something with a dot and no spaces or slashes.
    if "." in value and " " not in value and "/" not in value and len(value) < 254:
        return "domain"

    return None


# ---------------------------------------------------------------------------
# Providers. Each is an async callable: (client, indicator) -> ProviderResult.
# A provider that lacks its key returns available=False and is skipped.
# ---------------------------------------------------------------------------


async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> ProviderResult:
    """AbuseIPDB IP reputation. Free tier: 1,000 checks/day with a free key."""
    name = "AbuseIPDB"
    report_link = f"https://www.abuseipdb.com/check/{ip}"

    if not settings.abuseipdb_api_key:
        return ProviderResult(
            name, available=False, summary="No API key configured", link=report_link
        )

    try:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8.0,
        )
        response.raise_for_status()
        data = response.json()["data"]
    except httpx.HTTPError as exc:
        log.warning("AbuseIPDB query failed for %s: %s", ip, exc)
        return ProviderResult(
            name, available=False, summary=f"Query failed: {exc}", link=report_link
        )

    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)
    country = data.get("countryCode") or "??"
    isp = data.get("isp", "unknown")

    # AbuseIPDB's confidence score is 0-100. The bands here are conventional:
    # 90+ is acted on, 25+ is worth a look, below is noise.
    if score >= 90:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return ProviderResult(
        provider=name,
        available=True,
        verdict=verdict,
        summary=f"{score}% confidence, {reports} reports, {country} ({isp})",
        details={
            "abuse_confidence": score,
            "total_reports": reports,
            "country": country,
            "isp": isp,
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
        },
        link=report_link,
    )


async def query_virustotal(
    client: httpx.AsyncClient, indicator: str, kind: str
) -> ProviderResult:
    """VirusTotal reputation for an IP or domain. Free tier: 4 requests/min."""
    name = "VirusTotal"
    endpoint = "ip_addresses" if kind == "ip" else "domains"
    report_link = f"https://www.virustotal.com/gui/{'ip-address' if kind == 'ip' else 'domain'}/{indicator}"

    if not settings.virustotal_api_key:
        return ProviderResult(
            name, available=False, summary="No API key configured", link=report_link
        )

    try:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=8.0,
        )
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except httpx.HTTPError as exc:
        log.warning("VirusTotal query failed for %s: %s", indicator, exc)
        return ProviderResult(
            name, available=False, summary=f"Query failed: {exc}", link=report_link
        )

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    if malicious >= 3:
        verdict = "malicious"
    elif malicious + suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return ProviderResult(
        provider=name,
        available=True,
        verdict=verdict,
        summary=f"{malicious}/{total} vendors flag malicious, {suspicious} suspicious",
        details={
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
        },
        link=report_link,
    )


class EnrichmentService:
    """Runs indicators through the configured providers, with caching."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._cache: dict[str, Enrichment] = {}
        self._ttl = ttl_seconds

    async def enrich(self, indicator: str) -> Optional[Enrichment]:
        """Enrich one indicator, or None if it is not a type we handle.

        A cache hit costs nothing and makes no request -- which is what keeps a
        curious analyst clicking the same incident from burning the daily quota.
        """
        kind = classify_indicator(indicator)
        if kind is None:
            return None

        cached = self._cache.get(indicator)
        if cached and (time.time() - cached.cached_at) < self._ttl:
            return cached

        results: list[ProviderResult] = []
        async with httpx.AsyncClient() as client:
            if kind == "ip":
                results.append(await query_abuseipdb(client, indicator))
            results.append(await query_virustotal(client, indicator, kind))

        enrichment = Enrichment(
            indicator=indicator, indicator_type=kind, results=results
        )
        self._cache[indicator] = enrichment
        return enrichment

    @property
    def providers_configured(self) -> dict[str, bool]:
        """Which providers have a key. Surfaced on /health so it is obvious when
        enrichment is running key-less and therefore mostly empty."""
        return {
            "abuseipdb": bool(settings.abuseipdb_api_key),
            "virustotal": bool(settings.virustotal_api_key),
        }


enrichment_service = EnrichmentService()
