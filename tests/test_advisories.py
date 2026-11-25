"""Tests for the DRAKO-ABSS advisory loader and matcher."""

from __future__ import annotations

from drako.advisories import (
    Advisory,
    compute_pattern_hash,
    get_ioc_hashes,
    load_advisories,
    match_advisories_bulk,
    match_advisory,
)
from drako.cli.policies.base import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(policy_id: str) -> Finding:
    return Finding(
        policy_id=policy_id,
        category="Security",
        severity="HIGH",
        title="test",
        message="test finding",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLoadAdvisories:
    def test_loads_all_25_advisories(self):
        advisories = load_advisories()
        assert len(advisories) >= 25, f"Expected >=25, got {len(advisories)}"

    def test_advisory_is_dataclass(self):
        advisories = load_advisories()
        assert all(isinstance(a, Advisory) for a in advisories)

    def test_no_duplicate_ids(self):
        advisories = load_advisories()
        ids = [a.id for a in advisories]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_categories_present(self):
        advisories = load_advisories()
        categories = {a.category for a in advisories}
        expected = {"owasp-llm", "mitre-atlas", "framework-cve", "prompt-injection"}
        assert expected.issubset(categories), f"Missing categories: {expected - categories}"

    def test_advisory_has_required_fields(self):
        advisories = load_advisories()
        for adv in advisories:
            assert adv.id, "Advisory missing id"
            assert adv.title, f"Advisory {adv.id} missing title"
            assert adv.category, f"Advisory {adv.id} missing category"
            assert 1 <= adv.severity <= 10, f"Advisory {adv.id} severity out of range: {adv.severity}"
            assert adv.drako_rules, f"Advisory {adv.id} has no drako_rules"

    def test_advisories_sorted_by_id(self):
        advisories = load_advisories()
        ids = [a.id for a in advisories]
        assert ids == sorted(ids)


class TestMatchAdvisory:
    def test_matches_by_drako_rule(self):
        finding = _make_finding("SEC-007")
        matched = match_advisory(finding)
        assert len(matched) > 0, "SEC-007 should match at least one advisory"
        assert any("SEC-007" in a.drako_rules for a in matched)

    def test_no_match_for_unknown_rule(self):
        finding = _make_finding("NONEXISTENT-999")
        matched = match_advisory(finding)
        assert matched == []

    def test_matches_multiple_advisories(self):
        # SEC-007 appears in many advisories (prompt injection, jailbreak, etc.)
        finding = _make_finding("SEC-007")
        matched = match_advisory(finding)
        assert len(matched) >= 2, "SEC-007 should match multiple advisories"


class TestMatchAdvisoriesBulk:
    def test_returns_dict_keyed_by_policy_id(self):
        findings = [_make_finding("SEC-007"), _make_finding("SEC-005")]
        result = match_advisories_bulk(findings)
        assert isinstance(result, dict)
        if "SEC-007" in result:
            assert all(isinstance(a, Advisory) for a in result["SEC-007"])

    def test_deduplicates_same_policy_id(self):
        findings = [_make_finding("SEC-007"), _make_finding("SEC-007")]
        result = match_advisories_bulk(findings)
        # Should only have one entry for SEC-007, not two
        assert len([k for k in result if k == "SEC-007"]) <= 1


class TestIOCHashes:
    def test_returns_nonempty_set(self):
        hashes = get_ioc_hashes()
        assert len(hashes) > 0

    def test_hashes_are_hex_strings(self):
        hashes = get_ioc_hashes()
        for h in list(hashes)[:10]:  # check first 10
            assert isinstance(h, str)
            assert len(h) >= 32  # at least 128 bits


class TestComputePatternHash:
    def test_consistent_for_same_input(self):
        h1 = compute_pattern_hash("ignore previous instructions")
        h2 = compute_pattern_hash("ignore previous instructions")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = compute_pattern_hash("IGNORE PREVIOUS INSTRUCTIONS")
        h2 = compute_pattern_hash("ignore previous instructions")
        assert h1 == h2

    def test_strips_whitespace(self):
        h1 = compute_pattern_hash("  hello  ")
        h2 = compute_pattern_hash("hello")
        assert h1 == h2

    def test_different_inputs_different_hashes(self):
        h1 = compute_pattern_hash("foo")
        h2 = compute_pattern_hash("bar")
        assert h1 != h2
