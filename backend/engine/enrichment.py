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
import re
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


# Hash lengths in hex characters, by algorithm. A file hash is enrichable against
# VirusTotal; the length alone identifies which algorithm it is.
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}

_HEX = re.compile(r"^[0-9a-fA-F]+$")


def classify_indicator(value: str) -> Optional[str]:
    """Return "ip", "domain", "hash", or None for something we do not enrich.

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

    # A file hash: hex of a length that matches a known algorithm.
    if len(value) in _HASH_LENGTHS and _HEX.match(value):
        return "hash"

    # Very loose domain check: something with a dot and no spaces or slashes.
    if "." in value and " " not in value and "/" not in value and len(value) < 254:
        return "domain"

    return None


def parse_sysmon_hashes(raw: str) -> dict[str, str]:
    """Parse Sysmon's Hashes field, e.g. 'SHA256=ABC,MD5=DEF', into a dict.

    Sysmon emits several algorithms in one field. The strongest one present is
    what should be sent to VirusTotal, so callers can pick from this by key.
    """
    out: dict[str, str] = {}
    for part in raw.split(","):
        if "=" in part:
            algorithm, digest = part.split("=", 1)
            out[algorithm.strip().lower()] = digest.strip()
    return out


def best_hash(hashes: dict[str, str]) -> Optional[str]:
    """Pick the strongest hash available: SHA256 > SHA1 > MD5.

    A stronger hash is a more reliable lookup key -- MD5 collisions are cheap
    enough that malware authors produce them deliberately, so it is the last
    resort, not the first."""
    for algorithm in ("sha256", "sha1", "md5"):
        if algorithm in hashes:
            return hashes[algorithm]
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


async def query_virustotal_file(
    client: httpx.AsyncClient, file_hash: str
) -> ProviderResult:
    """VirusTotal reputation for a file hash. Free tier: 4 requests/min.

    This is the highest-value enrichment the tool offers: a hash that several
    engines flag turns "a process ran" into "a known-malicious binary executed",
    which is the difference between a lead and a confirmed compromise.
    """
    name = "VirusTotal"
    report_link = f"https://www.virustotal.com/gui/file/{file_hash}"

    if not settings.virustotal_api_key:
        return ProviderResult(
            name, available=False, summary="No API key configured", link=report_link
        )

    try:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=8.0,
        )
        # A 404 is meaningful here, not an error: VT has never seen this file.
        # For a bespoke payload that is itself suspicious -- unknown binaries are
        # rarer than known-good ones on a normal host.
        if response.status_code == 404:
            return ProviderResult(
                name,
                available=True,
                verdict="unknown",
                summary="Not seen by VirusTotal (unknown file)",
                details={"known": False},
                link=report_link,
            )
        response.raise_for_status()
        attrs = response.json()["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
    except httpx.HTTPError as exc:
        log.warning("VirusTotal file query failed for %s: %s", file_hash, exc)
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

    # The name VT knows the file by is useful context -- often a malware family.
    label = attrs.get("meaningful_name") or attrs.get("type_description", "")

    return ProviderResult(
        provider=name,
        available=True,
        verdict=verdict,
        summary=f"{malicious}/{total} engines flag malicious"
        + (f" · {label}" if label else ""),
        details={
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "label": label,
            "known": True,
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
            if kind == "hash":
                results.append(await query_virustotal_file(client, indicator))
            elif kind == "ip":
                results.append(await query_abuseipdb(client, indicator))
                results.append(await query_virustotal(client, indicator, kind))
            else:  # domain
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
