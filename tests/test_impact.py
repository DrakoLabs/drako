"""Tests for structured impact explanations on all policy rules."""
import json
import re
import pytest
from pathlib import Path

from drako.cli.policies import ALL_POLICIES
from drako.cli.scanner import run_scan
from drako.cli.formats.json_fmt import format_json
from drako.cli.formats.sarif import format_sarif

FIXTURES = Path(__file__).parent / "fixtures"


class TestAllRulesHaveImpact:
    """Verify every policy has non-empty impact metadata."""

    def test_every_policy_has_impact(self):
        for policy in ALL_POLICIES:
            assert policy.impact, f"{policy.policy_id} missing impact"
            assert len(policy.impact) <= 200, (
                f"{policy.policy_id} impact too long ({len(policy.impact)} chars, max 200)"
            )

    def test_every_policy_has_attack_scenario(self):
        for policy in ALL_POLICIES:
            assert policy.attack_scenario, f"{policy.policy_id} missing attack_scenario"
            assert len(policy.attack_scenario) <= 300, (
                f"{policy.policy_id} attack_scenario too long ({len(policy.attack_scenario)} chars, max 300)"
            )

    def test_every_policy_has_references(self):
        for policy in ALL_POLICIES:
            assert policy.references, f"{policy.policy_id} missing references"
            for ref in policy.references:
                assert ref.startswith("https://"), (
                    f"{policy.policy_id} reference must be HTTPS URL: {ref}"
                )

    def test_every_policy_has_valid_remediation_effort(self):
        for policy in ALL_POLICIES:
            assert policy.remediation_effort in ("trivial", "moderate", "significant"), (
                f"{policy.policy_id} invalid remediation_effort: {policy.remediation_effort}"
            )

    def test_policy_count(self):
        """Sanity check: we have 99 policies (82 Python + 17 TypeScript)."""
        assert len(ALL_POLICIES) == 99, f"Expected 99 policies, got {len(ALL_POLICIES)}"


class TestImpactInJSON:
    def test_json_includes_impact_fields(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        data = json.loads(format_json(result))

        for finding in data["findings"]:
            assert "impact" in finding
            assert "attack_scenario" in finding
            assert "references" in finding
            assert "remediation_effort" in finding

    def test_json_impact_not_null_for_findings(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        data = json.loads(format_json(result))

        # At least some findings should have impact data
        impacts = [f["impact"] for f in data["findings"] if f["impact"]]
        assert len(impacts) > 0, "No findings have impact text"


class TestImpactInSARIF:
    def test_sarif_includes_references(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        for rule in rules:
            assert "properties" in rule
            # Rules with references should have helpUri
            if "references" in rule.get("properties", {}):
                assert "helpUri" in rule

    def test_sarif_includes_attack_scenario(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        # At least some rules should have attack_scenario
        scenarios = [
            r["properties"]["attack_scenario"]
            for r in rules
            if "attack_scenario" in r.get("properties", {})
        ]
        assert len(scenarios) > 0


class TestImpactInFinding:
    """Test that Finding dataclass correctly carries impact fields."""

    def test_finding_has_impact_fields(self):
        from drako.cli.policies.base import Finding

        f = Finding(
            policy_id="TEST-001",
            category="Test",
            severity="HIGH",
            title="Test",
            message="Test message",
            impact="Test impact",
            attack_scenario="Test scenario",
            references=["https://example.com"],
            remediation_effort="trivial",
        )
        assert f.impact == "Test impact"
        assert f.attack_scenario == "Test scenario"
        assert f.references == ["https://example.com"]
        assert f.remediation_effort == "trivial"

    def test_finding_defaults_to_none(self):
        from drako.cli.policies.base import Finding

        f = Finding(
            policy_id="TEST-001",
            category="Test",
            severity="HIGH",
            title="Test",
            message="Test message",
        )
        assert f.impact is None
        assert f.attack_scenario is None
        assert f.references == []
        assert f.remediation_effort is None
