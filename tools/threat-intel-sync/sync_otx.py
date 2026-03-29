#!/usr/bin/env python3
"""AlienVault OTX feed sync for AI/LLM-related threat intelligence.

Fetches pulses from OTX, applies a quality gate (subscriber count,
indicator count, AI-relevant tags), and maps accepted pulses to
DRAKO-ABSS advisory format.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger("threat-intel-sync.otx")

OTX_API_KEY_ENV = "OTX_API_KEY"


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------

def is_quality_pulse(
    pulse: dict[str, Any],
    *,
    min_subscribers: int = 10,
    min_indicators: int = 1,
    ai_tags: set[str] | None = None,
) -> bool:
    """Return True only if the pulse passes every quality check.

    Rejects low-quality pulses to prevent corpus pollution from
    untrusted OTX contributors.  Every rejection is logged at DEBUG
    level so failures are never silent.
    """
    if ai_tags is None:
        ai_tags = {
            "prompt injection", "llm", "ai agent", "langchain", "openai",
            "anthropic", "machine learning attack", "model poisoning",
            "ai supply chain", "agent hijacking", "tool abuse",
        }

    pulse_id = pulse.get("id", "unknown")

    # --- Subscriber count ---
    author = pulse.get("author", {})
    subscribers = author.get("subscriber_count", 0) if isinstance(author, dict) else 0
    if subscribers < min_subscribers:
        logger.debug(
            "Rejected pulse %s: subscriber_count=%d < %d",
            pulse_id, subscribers, min_subscribers,
        )
        return False

    # --- Indicator count ---
    indicator_count = pulse.get("indicator_count", 0)
    if indicator_count < min_indicators:
        logger.debug(
            "Rejected pulse %s: indicator_count=%d < %d",
            pulse_id, indicator_count, min_indicators,
        )
        return False

    # --- AI-relevant tags ---
    pulse_tags = {t.lower() for t in pulse.get("tags", [])}
    if not pulse_tags & ai_tags:
        logger.debug(
            "Rejected pulse %s: no AI-relevant tags in %s",
            pulse_id, pulse_tags,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# ABSS mapping helpers
# ---------------------------------------------------------------------------

def _classify_ioc_type(pulse: dict[str, Any]) -> str:
    """Classify the IOC type based on pulse tags."""
    tags = {t.lower() for t in pulse.get("tags", [])}
    if tags & {"prompt injection", "injection"}:
        return "PROMPT_INJECTION"
    if tags & {"supply chain", "poisoning", "backdoor"}:
        return "SUPPLY_CHAIN"
    if tags & {"exfiltration", "data leak", "credential"}:
        return "DATA_EXFILTRATION"
    return "GENERIC_THREAT"


def _map_tlp_to_severity(tlp: str) -> int:
    """Map TLP colour to a 1-10 severity score."""
    return {"red": 9, "amber": 7, "green": 5, "white": 3}.get(tlp.lower(), 5)


def _estimate_confidence(pulse: dict[str, Any]) -> float:
    """Derive a 0.0-1.0 confidence score from author reputation and IOC depth."""
    subs = (pulse.get("author") or {}).get("subscriber_count", 0)
    indicators = pulse.get("indicator_count", 0)
    base = min(subs / 100, 0.5) + min(indicators / 10, 0.4)
    return round(min(base + 0.1, 1.0), 2)


def _extract_indicators(pulse: dict[str, Any], *, cap: int = 20) -> list[dict[str, str]]:
    """Extract concrete indicators, capped to avoid oversized advisories."""
    indicators = pulse.get("indicators", [])
    return [
        {"type": i.get("type", "unknown"), "value": i.get("indicator", "")}
        for i in indicators[:cap]
        if i.get("indicator")
    ]


def _infer_frameworks(pulse: dict[str, Any]) -> list[str]:
    """Infer affected AI frameworks from pulse text."""
    text = (pulse.get("name", "") + " " + pulse.get("description", "")).lower()
    frameworks: list[str] = []
    for fw, keywords in {
        "langchain": ["langchain"],
        "crewai": ["crewai", "crew ai"],
        "autogen": ["autogen"],
        "openai": ["openai", "gpt"],
        "anthropic": ["anthropic", "claude"],
    }.items():
        if any(kw in text for kw in keywords):
            frameworks.append(fw)
    return frameworks or ["generic"]


def _extract_references(pulse: dict[str, Any], *, cap: int = 5) -> list[dict[str, str]]:
    """Extract URL references from the pulse."""
    refs: list[dict[str, str]] = []
    for ref in pulse.get("references", [])[:cap]:
        if isinstance(ref, str) and ref.startswith("http"):
            refs.append({"type": "url", "url": ref})
    return refs


# ---------------------------------------------------------------------------
# Pulse → ABSS advisory
# ---------------------------------------------------------------------------

def map_otx_to_abss(
    pulse: dict[str, Any],
    *,
    min_subscribers: int = 10,
    min_indicators: int = 1,
    ai_tags: set[str] | None = None,
) -> dict[str, Any] | None:
    """Map a quality-verified OTX pulse to DRAKO-ABSS format.

    Returns None if the pulse fails the quality gate or has no
    extractable indicators.
    """
    if not is_quality_pulse(
        pulse,
        min_subscribers=min_subscribers,
        min_indicators=min_indicators,
        ai_tags=ai_tags,
    ):
        return None

    indicators = _extract_indicators(pulse)
    if not indicators:
        logger.debug("Rejected pulse %s: no extractable indicators", pulse.get("id"))
        return None

    pulse_id = pulse["id"][:8]

    return {
        "id": f"DRAKO-ABSS-EXT-{pulse_id}",
        "title": pulse.get("name", "Untitled")[:120],
        "category": "threat-intel",
        "severity": _map_tlp_to_severity(pulse.get("TLP", "white")),
        "confidence": _estimate_confidence(pulse),
        "source": "alienvault_otx",
        "source_id": pulse["id"],
        "source_url": f"https://otx.alienvault.com/pulse/{pulse['id']}",
        "affected": {
            "frameworks": _infer_frameworks(pulse),
        },
        "ioc": {
            "type": _classify_ioc_type(pulse),
            "indicators": indicators,
        },
        "taint_path": {},
        "references": _extract_references(pulse),
        "mitigation": {
            "drako_rules": [],
            "description": pulse.get("description", "")[:500],
            "remediation_effort": "unknown",
        },
        "metadata": {
            "published": pulse.get("created", ""),
            "updated": pulse.get("modified", ""),
            "author": pulse.get("author_name", "OTX Community"),
            "author_subscribers": (pulse.get("author") or {}).get("subscriber_count", 0),
            "indicator_count": pulse.get("indicator_count", 0),
            "external": True,
        },
    }


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

async def fetch_ai_pulses(
    *,
    base_url: str = "https://otx.alienvault.com/api/v1",
    keywords: list[str] | None = None,
    max_per_keyword: int = 20,
    limit: int = 50,
    timeout: float = 15.0,
) -> list[dict[str, Any]]:
    """Fetch OTX pulses related to AI/LLM threats.

    Returns deduplicated pulses sorted by modification date (newest first).
    """
    api_key = os.environ.get(OTX_API_KEY_ENV, "")
    if not api_key:
        logger.warning(
            "Environment variable %s is not set — OTX requests may be rate-limited",
            OTX_API_KEY_ENV,
        )

    if keywords is None:
        keywords = [
            "LLM prompt injection",
            "AI agent attack",
            "machine learning security",
            "model supply chain",
        ]

    headers: dict[str, str] = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=timeout) as client:
        for keyword in keywords:
            try:
                response = await client.get(
                    f"{base_url}/search/pulses",
                    params={"q": keyword, "sort": "modified", "limit": max_per_keyword},
                    headers=headers,
                )
                response.raise_for_status()
                results.extend(response.json().get("results", []))
            except httpx.HTTPStatusError as exc:
                logger.error(
                    "OTX API HTTP %d for keyword '%s': %s",
                    exc.response.status_code, keyword, exc,
                )
            except httpx.TimeoutException:
                logger.warning("OTX timeout fetching keyword '%s'", keyword)
            except httpx.HTTPError as exc:
                logger.error("OTX network error for keyword '%s': %s", keyword, exc)

    # Deduplicate by pulse ID
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for pulse in results:
        pid = pulse.get("id")
        if pid and pid not in seen:
            seen.add(pid)
            unique.append(pulse)

    logger.info("OTX: fetched %d pulses, %d unique", len(results), len(unique))
    return unique[:limit]
