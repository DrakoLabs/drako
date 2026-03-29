#!/usr/bin/env python3
"""abuse.ch feed sync — URLhaus and ThreatFox.

Fetches recent malicious URLs from URLhaus, filters for those targeting
AI infrastructure endpoints, and maps matches to DRAKO-ABSS format.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("threat-intel-sync.abusech")

# Default AI infrastructure domains
_DEFAULT_AI_DOMAINS: frozenset[str] = frozenset({
    "openai.com", "api.openai.com",
    "anthropic.com", "api.anthropic.com",
    "huggingface.co", "hf.co",
    "replicate.com", "api.replicate.com",
    "together.ai", "api.together.xyz",
    "cohere.ai", "api.cohere.ai",
    "stability.ai",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract the network location from a URL."""
    try:
        return urlparse(url).netloc
    except Exception:
        return "unknown"


def _domain_to_framework(url: str) -> str:
    """Map a URL to the most likely targeted AI framework."""
    url_lower = url.lower()
    if "openai" in url_lower:
        return "openai"
    if "anthropic" in url_lower:
        return "anthropic"
    if "huggingface" in url_lower or "hf.co" in url_lower:
        return "huggingface"
    if "replicate" in url_lower:
        return "replicate"
    if "together" in url_lower:
        return "together"
    if "cohere" in url_lower:
        return "cohere"
    if "stability" in url_lower:
        return "stability"
    return "generic"


def _is_ai_targeted(url: str, ai_domains: frozenset[str]) -> bool:
    """Return True if the URL targets a known AI infrastructure domain."""
    return any(domain in url for domain in ai_domains)


# ---------------------------------------------------------------------------
# URL entry → ABSS advisory
# ---------------------------------------------------------------------------

def map_urlhaus_to_abss(
    url_entry: dict[str, Any],
) -> dict[str, Any]:
    """Map a URLhaus entry to DRAKO-ABSS advisory format."""
    url = url_entry.get("url", "")
    entry_id = str(url_entry.get("id", "unknown"))[:8]

    return {
        "id": f"DRAKO-ABSS-EXT-AH-{entry_id}",
        "title": f"Malicious URL targeting {_extract_domain(url)}",
        "category": "threat-intel",
        "severity": 8,
        "confidence": 0.7,
        "source": "abusech_urlhaus",
        "source_url": url_entry.get("urlhaus_reference", ""),
        "affected": {
            "frameworks": [_domain_to_framework(url)],
        },
        "ioc": {
            "type": "INFRASTRUCTURE_ATTACK",
            "indicators": [
                {"type": "url", "value": url},
            ],
        },
        "taint_path": {},
        "references": [],
        "mitigation": {
            "drako_rules": [],
            "description": f"Block access to malicious URL targeting AI infrastructure: {_extract_domain(url)}",
            "remediation_effort": "low",
        },
        "metadata": {
            "published": url_entry.get("date_added", ""),
            "threat_type": url_entry.get("threat", "unknown"),
            "external": True,
        },
    }


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

async def fetch_ai_targeted_urls(
    *,
    urlhaus_api: str = "https://urlhaus-api.abuse.ch/v1",
    ai_domains: frozenset[str] | None = None,
    limit: int = 100,
    timeout: float = 15.0,
) -> list[dict[str, Any]]:
    """Fetch recent URLhaus entries that target AI API endpoints.

    Returns a list of DRAKO-ABSS-formatted advisories (already mapped).
    """
    if ai_domains is None:
        ai_domains = _DEFAULT_AI_DOMAINS

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.post(
                f"{urlhaus_api}/urls/recent/",
                data={"limit": str(limit)},
            )
            response.raise_for_status()
            urls = response.json().get("urls", [])
        except httpx.HTTPStatusError as exc:
            logger.error(
                "URLhaus API HTTP %d: %s",
                exc.response.status_code, exc,
            )
            return []
        except httpx.TimeoutException:
            logger.warning("URLhaus API timeout after %.1fs", timeout)
            return []
        except httpx.HTTPError as exc:
            logger.error("URLhaus network error: %s", exc)
            return []

    relevant: list[dict[str, Any]] = []
    for url_entry in urls:
        url = url_entry.get("url", "")
        if _is_ai_targeted(url, ai_domains):
            advisory = map_urlhaus_to_abss(url_entry)
            relevant.append(advisory)

    logger.info(
        "URLhaus: %d total URLs, %d targeting AI infrastructure",
        len(urls), len(relevant),
    )
    return relevant
