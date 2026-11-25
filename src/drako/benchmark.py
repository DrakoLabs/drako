"""Benchmark comparison system for Drako scan results.

Compares a project's governance score against a bundled anonymized
reference dataset of scanned AI agent projects (100% offline).

All computation is pure (no I/O in compute_benchmark). Dataset loading
is lazy and cached.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class BenchmarkResult:
    """Result of comparing a scan score against the benchmark dataset."""

    percentile: int                        # 0-100, what % of projects scored lower
    framework: str | None                  # detected framework, if any
    framework_percentile: int | None       # percentile within framework cohort
    framework_count: int | None            # projects scanned for this framework
    projects_in_benchmark: int             # total projects in dataset
    grade_distribution: dict[str, int]     # {"A": 3, "B": 8, "C": 15, ...}
    score_distribution: list[int]          # all scores for rendering


def compute_benchmark(
    score: int,
    framework: str | None,
    dataset: dict[str, Any],
) -> BenchmarkResult:
    """Compute benchmark comparison. Pure function — no I/O.

    Args:
        score: The project's governance score (0-100).
        framework: Primary detected framework name, or None.
        dataset: The benchmark dataset dict (from load_dataset()).

    Returns:
        BenchmarkResult with percentile and comparison data.
    """
    dist = dataset.get("distribution", {})
    scores = sorted(dist.get("scores", []))
    projects_in_benchmark = dataset.get("projects_scanned", len(scores))

    # Overall percentile: % of benchmark scores strictly below this score
    if scores:
        below = sum(1 for s in scores if s < score)
        percentile = round(below / len(scores) * 100)
    else:
        percentile = 0

    # Framework-specific comparison
    framework_percentile: int | None = None
    framework_count: int | None = None

    if framework:
        by_fw = dist.get("by_framework", {})
        fw_data = by_fw.get(framework.lower()) or by_fw.get("other")

        if fw_data:
            framework_count = fw_data.get("count")
            p25 = fw_data.get("p25", 0)
            median = fw_data.get("median", 0)
            p75 = fw_data.get("p75", 0)

            # Estimate percentile from quartile data
            if score < p25:
                # Linear interpolation 0-25%
                framework_percentile = round(25 * score / p25) if p25 > 0 else 0
            elif score < median:
                # Linear interpolation 25-50%
                span = median - p25
                framework_percentile = 25 + (round(25 * (score - p25) / span) if span > 0 else 0)
            elif score < p75:
                # Linear interpolation 50-75%
                span = p75 - median
                framework_percentile = 50 + (round(25 * (score - median) / span) if span > 0 else 0)
            else:
                # Linear interpolation 75-100%
                max_score = 100
                span = max_score - p75
                framework_percentile = 75 + (round(25 * (score - p75) / span) if span > 0 else 0)

            framework_percentile = max(0, min(100, framework_percentile))

    grade_distribution = dist.get("grade_distribution", {})

    return BenchmarkResult(
        percentile=percentile,
        framework=framework,
        framework_percentile=framework_percentile,
        framework_count=framework_count,
        projects_in_benchmark=projects_in_benchmark,
        grade_distribution=grade_distribution,
        score_distribution=scores,
    )


# ---------------------------------------------------------------------------
# Lazy dataset loader
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).parent / "data"
_cached_dataset: dict[str, Any] | None = None


def load_dataset() -> dict[str, Any]:
    """Load the benchmark dataset from the package data directory.

    Returns cached data after first call. Returns a minimal empty
    dataset if the file is missing or corrupt.
    """
    global _cached_dataset
    if _cached_dataset is not None:
        return _cached_dataset

    path = _DATA_DIR / "benchmark_dataset.json"
    try:
        _cached_dataset = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _cached_dataset = {
            "version": 1,
            "projects_scanned": 0,
            "distribution": {
                "scores": [],
                "by_framework": {},
                "by_severity": {},
                "grade_distribution": {},
            },
        }
    return _cached_dataset


def _reset_cache() -> None:
    """Reset cached dataset (for testing only)."""
    global _cached_dataset
    _cached_dataset = None
