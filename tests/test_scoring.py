"""Tests for the scoring module (CRITICAL -10 cap 40, HIGH -5 cap 30, MEDIUM -2 cap 15, LOW -1 cap 5)."""

from drako.cli.policies.base import Finding
from drako.cli.scoring import calculate_score, findings_summary, score_to_grade


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
        assert calculate_score([_finding("CRITICAL")]) == 90  # 100 - 10

    def test_one_high(self):
        assert calculate_score([_finding("HIGH")]) == 95  # 100 - 5

    def test_one_medium(self):
        assert calculate_score([_finding("MEDIUM")]) == 98  # 100 - 2

    def test_one_low(self):
        assert calculate_score([_finding("LOW")]) == 99  # 100 - 1

    def test_critical_cap(self):
        findings = [_finding("CRITICAL") for _ in range(6)]
        assert calculate_score(findings) == 60  # cap -40

    def test_high_cap(self):
        findings = [_finding("HIGH") for _ in range(8)]
        assert calculate_score(findings) == 70  # cap -30

    def test_medium_cap(self):
        findings = [_finding("MEDIUM") for _ in range(10)]
        assert calculate_score(findings) == 85  # cap -15

    def test_low_cap(self):
        findings = [_finding("LOW") for _ in range(10)]
        assert calculate_score(findings) == 95  # cap -5

    def test_mixed_severities(self):
        findings = [
            _finding("CRITICAL"),  # -10
            _finding("HIGH"),      # -5
            _finding("MEDIUM"),    # -2
            _finding("LOW"),       # -1
        ]
        assert calculate_score(findings) == 82  # 100 - 18

    def test_all_severity_caps(self):
        # 40 + 30 + 15 + 5 = 90 -> score = 10
        findings = (
            [_finding("CRITICAL")] * 6
            + [_finding("HIGH")] * 8
            + [_finding("MEDIUM")] * 10
            + [_finding("LOW")] * 10
        )
        assert calculate_score(findings) == 10

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
        assert findings_summary(findings) == {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 3, "LOW": 1}

    def test_empty(self):
        assert findings_summary([]) == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
