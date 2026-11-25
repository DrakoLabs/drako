"""DRAKO-ABSS advisory loader and matcher.

Loads structured security advisories from the data/advisories/ directory
and matches them to scan findings for enriched output.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pyyaml is optional at import time
    yaml = None

if TYPE_CHECKING:
    from drako.cli.policies.base import Finding


# ---------------------------------------------------------------------------
# Advisory dataclass
# ---------------------------------------------------------------------------

@dataclass
class Advisory:
    """A single DRAKO-ABSS advisory."""

    id: str
    title: str
    category: str  # owasp-llm | mitre-atlas | framework-cve | prompt-injection
    severity: int  # 1-10
    confidence: float

    affected_frameworks: list[str] = field(default_factory=list)
    affected_conditions: list[str] = field(default_factory=list)

    ioc_type: str = ""
    ioc_patterns: list[str] = field(default_factory=list)
    ioc_pattern_hashes: list[str] = field(default_factory=list)

    taint_source: str = ""
    taint_sink: str = ""
    taint_via: list[str] = field(default_factory=list)

    references: list[dict[str, str]] = field(default_factory=list)

    drako_rules: list[str] = field(default_factory=list)
    mitigation_description: str = ""
    remediation_effort: str = "moderate"

    published: str = ""
    updated: str = ""
    author: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _advisories_dir() -> Path:
    """Return the path to the bundled advisories directory."""
    return Path(__file__).parent / "data" / "advisories"


def _parse_advisory(raw: dict[str, Any]) -> Advisory:
    """Parse a raw YAML dict into an Advisory dataclass."""
    affected = raw.get("affected", {})
    ioc = raw.get("ioc", {})
    taint = raw.get("taint_path", {})
    mitigation = raw.get("mitigation", {})
    metadata = raw.get("metadata", {})

    return Advisory(
        id=raw.get("id", ""),
        title=raw.get("title", ""),
        category=raw.get("category", ""),
        severity=raw.get("severity", 5),
        confidence=raw.get("confidence", 0.5),
        affected_frameworks=affected.get("frameworks", []),
        affected_conditions=affected.get("conditions", []),
        ioc_type=ioc.get("type", ""),
        ioc_patterns=ioc.get("patterns", []),
        ioc_pattern_hashes=ioc.get("pattern_hashes", []),
        taint_source=taint.get("source", ""),
        taint_sink=taint.get("sink", ""),
        taint_via=taint.get("via", []),
        references=raw.get("references", []),
        drako_rules=mitigation.get("drako_rules", []),
        mitigation_description=mitigation.get("description", ""),
        remediation_effort=mitigation.get("remediation_effort", "moderate"),
        published=metadata.get("published", ""),
        updated=metadata.get("updated", ""),
        author=metadata.get("author", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_advisories() -> tuple[Advisory, ...]:
    """Load all DRAKO-ABSS advisories from the bundled data directory.

    Returns a tuple (hashable for lru_cache).  Advisories are sorted by ID.
    """
    if yaml is None:
        return ()

    adv_dir = _advisories_dir()
    if not adv_dir.is_dir():
        return ()

    advisories: list[Advisory] = []
    for path in sorted(adv_dir.glob("DRAKO-ABSS-*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if raw and isinstance(raw, dict):
                advisories.append(_parse_advisory(raw))
        except Exception:
            continue  # skip malformed files silently

    return tuple(advisories)


def match_advisory(finding: Finding) -> list[Advisory]:
    """Match a scan finding to related advisories.

    Matches when the finding's policy_id appears in the advisory's drako_rules list.
    """
    matched: list[Advisory] = []
    for adv in load_advisories():
        if finding.policy_id in adv.drako_rules:
            matched.append(adv)
    return matched


def match_advisories_bulk(findings: list[Finding]) -> dict[str, list[Advisory]]:
    """Match all findings to advisories in one pass.

    Returns a dict mapping policy_id → list of matched advisories.
    Deduplicates: each advisory appears at most once per policy_id.
    """
    all_advisories = load_advisories()

    # Build reverse index: rule_id → [advisory, ...]
    rule_to_advisories: dict[str, list[Advisory]] = {}
    for adv in all_advisories:
        for rule_id in adv.drako_rules:
            rule_to_advisories.setdefault(rule_id, []).append(adv)

    result: dict[str, list[Advisory]] = {}
    seen_policy_ids: set[str] = set()
    for finding in findings:
        if finding.policy_id in seen_policy_ids:
            continue
        seen_policy_ids.add(finding.policy_id)
        matched = rule_to_advisories.get(finding.policy_id, [])
        if matched:
            result[finding.policy_id] = matched

    return result


def get_ioc_hashes() -> set[str]:
    """Get all IOC pattern hashes across all advisories.

    These can be used for runtime IOC matching without loading full advisories.
    """
    hashes: set[str] = set()
    for adv in load_advisories():
        hashes.update(adv.ioc_pattern_hashes)
    return hashes


def compute_pattern_hash(pattern: str) -> str:
    """Compute SHA-256 hash for an IOC pattern (normalized: lowercase, stripped)."""
    normalized = pattern.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
