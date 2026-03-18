"""Governance score calculation for `drako scan`.

Scoring formula (start at 100, deduct per severity with caps):
  - CRITICAL: -15 each, cap -60
  - HIGH:     -8 each,  cap -40
  - MEDIUM:   -3 each,  cap -20
  - LOW:      -1 each,  cap -10

Score range: 0-100
Grading: A (90-100), B (75-89), C (60-74), D (40-59), F (0-39)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.policies.base import Finding

# Points deducted per finding of each severity
_PER_FINDING = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
}

# Maximum total deduction per severity category
_CAPS = {
    "CRITICAL": 60,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 10,
}


def calculate_score(findings: list[Finding]) -> int:
    """Calculate governance score from findings.

    Returns an integer 0-100.
    """
    deductions: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in findings:
        sev = finding.severity
        if sev in deductions:
            deductions[sev] = min(
                deductions[sev] + _PER_FINDING[sev],
                _CAPS[sev],
            )

    score = 100 - sum(deductions.values())
    return max(0, min(100, score))


def score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def findings_summary(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
