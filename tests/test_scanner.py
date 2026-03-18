"""Tests for the scanner orchestrator."""
import pytest
from pathlib import Path

from drako.cli.scanner import run_scan

FIXTURES = Path(__file__).parent / "fixtures"


class TestRunScan:
    def test_crewai_basic(self):
        """CrewAI project with issues should score low (F/D)."""
        result = run_scan(str(FIXTURES / "crewai_basic"))

        assert result.score <= 55
        assert result.grade in ("F", "D")
        assert len(result.findings) >= 3
        assert len(result.bom.agents) >= 2
        assert len(result.bom.tools) >= 2
        assert result.scan_duration_ms >= 0

        # Should have critical findings
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical) >= 1

    def test_langgraph_clean(self):
        """Clean LangGraph project should score high (B/A)."""
        result = run_scan(str(FIXTURES / "langgraph_clean"))

        assert result.score >= 60
        assert result.grade in ("A", "B", "C")
        assert result.scan_duration_ms >= 0

    def test_autogen_vulnerable(self):
        """AutoGen project with vulns should score very low (F)."""
        result = run_scan(str(FIXTURES / "autogen_vulnerable"))

        assert result.score <= 45
        assert result.grade in ("F", "D")

        # Should have multiple critical findings
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical) >= 2

    def test_mixed_framework(self):
        """Mixed framework project should detect both frameworks."""
        result = run_scan(str(FIXTURES / "mixed_framework"))

        fw_names = [f.name for f in result.bom.frameworks]
        assert "crewai" in fw_names
        assert "langgraph" in fw_names

    def test_framework_filter(self):
        """Framework filter should restrict detection."""
        result = run_scan(
            str(FIXTURES / "mixed_framework"),
            framework_filter=["crewai"],
        )

        fw_names = [f.name for f in result.metadata.frameworks]
        assert "crewai" in fw_names
        assert "langgraph" not in fw_names

    def test_scan_result_has_all_fields(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))

        assert result.metadata is not None
        assert result.bom is not None
        assert result.findings is not None
        assert isinstance(result.score, int)
        assert isinstance(result.grade, str)
        assert isinstance(result.scan_duration_ms, int)

    def test_findings_have_policy_ids(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))

        for finding in result.findings:
            assert finding.policy_id
            assert finding.category
            assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert finding.message
