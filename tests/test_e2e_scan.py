"""End-to-end integration tests for the full scan pipeline."""
import json
import pytest
from pathlib import Path

from drako.cli.scanner import run_scan
from drako.cli.formats.json_fmt import format_json
from drako.cli.formats.sarif import format_sarif

FIXTURES = Path(__file__).parent / "fixtures"


class TestE2ECrewAIBasic:
    """Full pipeline test on crewai_basic fixture."""

    def test_scan_produces_valid_results(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))

        assert 0 <= result.score <= 100
        assert result.grade in ("A", "B", "C", "D", "F")
        assert len(result.findings) > 0
        assert result.scan_duration_ms >= 0

    def test_expected_findings(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        policy_ids = {f.policy_id for f in result.findings}

        # Must detect hardcoded API key
        assert "SEC-001" in policy_ids
        # Must detect exec()
        assert "SEC-005" in policy_ids
        # Must detect no audit logging
        assert "GOV-001" in policy_ids

    def test_json_output_roundtrip(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        json_str = format_json(result)
        data = json.loads(json_str)

        assert data["score"] == result.score
        assert data["grade"] == result.grade
        assert len(data["findings"]) == len(result.findings)

    def test_sarif_output(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        sarif_str = format_sarif(result)
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == len(result.findings)


class TestE2EAutoGenVulnerable:
    """Full pipeline test on autogen_vulnerable fixture."""

    def test_low_score(self):
        result = run_scan(str(FIXTURES / "autogen_vulnerable"))
        assert result.score <= 45

    def test_multiple_critical_findings(self):
        result = run_scan(str(FIXTURES / "autogen_vulnerable"))
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical) >= 2

    def test_gov006_detected(self):
        """Must detect self-modifying prompt pattern."""
        result = run_scan(str(FIXTURES / "autogen_vulnerable"))
        policy_ids = {f.policy_id for f in result.findings}
        assert "GOV-006" in policy_ids


class TestE2ELangGraphClean:
    """Full pipeline test on langgraph_clean fixture."""

    def test_high_score(self):
        result = run_scan(str(FIXTURES / "langgraph_clean"))
        assert result.score >= 60

    def test_fewer_findings(self):
        result = run_scan(str(FIXTURES / "langgraph_clean"))
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical) == 0


class TestE2EMixedFramework:
    """Full pipeline test on mixed_framework fixture."""

    def test_both_frameworks_detected(self):
        result = run_scan(str(FIXTURES / "mixed_framework"))
        fw_names = [fw.name for fw in result.bom.frameworks]
        assert "crewai" in fw_names
        assert "langgraph" in fw_names

    def test_reasonable_score(self):
        result = run_scan(str(FIXTURES / "mixed_framework"))
        assert 0 <= result.score <= 80
