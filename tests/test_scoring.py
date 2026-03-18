"""Tests for the scoring module."""
import pytest

from drako.cli.scoring import calculate_score, score_to_grade, findings_summary
from drako.cli.policies.base import Finding


def _finding(severity: str) -> Finding:
    return Finding(
        policy_id="TEST-001",
        category="Test",
        severity=severity,
        title="Test finding",
        message="Test message",
    )


class TestCalculateScore:
    def test_no_findings(self):
        assert calculate_score([]) == 100

    def test_one_critical(self):
        assert calculate_score([_finding("CRITICAL")]) == 85  # 100 - 15

    def test_one_high(self):
        assert calculate_score([_finding("HIGH")]) == 92  # 100 - 8

    def test_one_medium(self):
        assert calculate_score([_finding("MEDIUM")]) == 97  # 100 - 3

    def test_one_low(self):
        assert calculate_score([_finding("LOW")]) == 99  # 100 - 1

    def test_critical_cap(self):
        # 5 CRITICAL = 5 * 15 = 75, but cap is 60
        findings = [_finding("CRITICAL") for _ in range(5)]
        assert calculate_score(findings) == 40  # 100 - 60

    def test_high_cap(self):
        # 6 HIGH = 6 * 8 = 48, but cap is 40
        findings = [_finding("HIGH") for _ in range(6)]
        assert calculate_score(findings) == 60  # 100 - 40

    def test_medium_cap(self):
        # 8 MEDIUM = 8 * 3 = 24, but cap is 20
        findings = [_finding("MEDIUM") for _ in range(8)]
        assert calculate_score(findings) == 80  # 100 - 20

    def test_low_cap(self):
        # 15 LOW = 15 * 1 = 15, but cap is 10
        findings = [_finding("LOW") for _ in range(15)]
        assert calculate_score(findings) == 90  # 100 - 10

    def test_mixed_severities(self):
        findings = [
            _finding("CRITICAL"),  # -15
            _finding("HIGH"),      # -8
            _finding("MEDIUM"),    # -3
            _finding("LOW"),       # -1
        ]
        assert calculate_score(findings) == 73  # 100 - 15 - 8 - 3 - 1

    def test_minimum_zero(self):
        # All caps: 60 + 40 + 20 + 10 = 130, score = max(0, 100-130) = 0
        findings = (
            [_finding("CRITICAL")] * 5
            + [_finding("HIGH")] * 6
            + [_finding("MEDIUM")] * 8
            + [_finding("LOW")] * 15
        )
        assert calculate_score(findings) == 0

    def test_maximum_100(self):
        assert calculate_score([]) == 100


class TestScoreToGrade:
    def test_grade_a(self):
        assert score_to_grade(100) == "A"
        assert score_to_grade(90) == "A"

    def test_grade_b(self):
        assert score_to_grade(89) == "B"
        assert score_to_grade(75) == "B"

    def test_grade_c(self):
        assert score_to_grade(74) == "C"
        assert score_to_grade(60) == "C"

    def test_grade_d(self):
        assert score_to_grade(59) == "D"
        assert score_to_grade(40) == "D"

    def test_grade_f(self):
        assert score_to_grade(39) == "F"
        assert score_to_grade(0) == "F"


class TestFindingsSummary:
    def test_counts(self):
        findings = [
            _finding("CRITICAL"),
            _finding("CRITICAL"),
            _finding("HIGH"),
            _finding("MEDIUM"),
            _finding("MEDIUM"),
            _finding("MEDIUM"),
            _finding("LOW"),
        ]
        summary = findings_summary(findings)
        assert summary == {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3, "LOW": 1}

    def test_empty(self):
        summary = findings_summary([])
        assert summary == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
