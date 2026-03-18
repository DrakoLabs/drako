"""Tests for output format generators (JSON, SARIF, Badge)."""
import json
import pytest
from pathlib import Path

from drako.cli.scanner import run_scan
from drako.cli.formats.json_fmt import format_json
from drako.cli.formats.sarif import format_sarif
from drako.cli.formats.badge import generate_badge_svg

FIXTURES = Path(__file__).parent / "fixtures"


class TestJSONFormat:
    def test_valid_json(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        output = format_json(result)
        data = json.loads(output)

        assert "score" in data
        assert "grade" in data
        assert "findings" in data
        assert "agent_bom" in data
        assert "summary" in data
        assert isinstance(data["findings"], list)

    def test_json_has_policy_ids(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        data = json.loads(format_json(result))

        for finding in data["findings"]:
            assert "policy_id" in finding
            assert "severity" in finding
            assert "message" in finding

    def test_json_summary_counts(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        data = json.loads(format_json(result))
        summary = data["summary"]

        assert "critical" in summary
        assert "high" in summary
        assert "total" in summary
        assert summary["total"] == len(data["findings"])


class TestSARIFFormat:
    def test_valid_sarif(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        output = format_sarif(result)
        sarif = json.loads(output)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_has_rules(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        sarif = json.loads(format_sarif(result))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        assert len(rules) >= 1
        for rule in rules:
            assert "id" in rule
            assert "shortDescription" in rule

    def test_sarif_results(self):
        result = run_scan(str(FIXTURES / "crewai_basic"))
        sarif = json.loads(format_sarif(result))
        results = sarif["runs"][0]["results"]

        assert len(results) >= 1
        for r in results:
            assert "ruleId" in r
            assert "level" in r
            assert "message" in r


class TestBadgeSVG:
    def test_generates_svg(self):
        svg = generate_badge_svg(85, "B")
        assert "<svg" in svg
        assert "85/100" in svg
        assert "[B]" in svg

    def test_grade_colors(self):
        svg_a = generate_badge_svg(95, "A")
        assert "#4c1" in svg_a  # green

        svg_f = generate_badge_svg(20, "F")
        assert "#e05d44" in svg_f  # red

    def test_all_grades(self):
        for score, grade in [(95, "A"), (80, "B"), (65, "C"), (45, "D"), (20, "F")]:
            svg = generate_badge_svg(score, grade)
            assert "<svg" in svg
            assert f"{score}/100" in svg
