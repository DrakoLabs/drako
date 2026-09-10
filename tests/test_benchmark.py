"""Tests for the benchmark comparison system."""
import json
import pytest
from pathlib import Path

from click.testing import CliRunner

from drako.benchmark import (
    BenchmarkResult,
    compute_benchmark,
    load_dataset,
    _reset_cache,
)
from drako.cli.main import cli
from drako.cli.report import render_benchmark_panel_to_string

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helper: minimal dataset for unit tests
# ---------------------------------------------------------------------------

def _mini_dataset(scores: list[int] | None = None) -> dict:
    """Create a minimal benchmark dataset for testing."""
    if scores is None:
        scores = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    return {
        "version": 1,
        "projects_scanned": len(scores),
        "distribution": {
            "scores": scores,
            "by_framework": {
                "crewai": {"count": 4, "median": 40, "p25": 25, "p75": 60},
                "other": {"count": 6, "median": 50, "p25": 30, "p75": 70},
            },
            "by_severity": {
                "critical_findings_median": 2,
                "high_findings_median": 4,
                "medium_findings_median": 6,
                "low_findings_median": 3,
            },
            "grade_distribution": {"A": 1, "B": 1, "C": 2, "D": 3, "F": 3},
        },
    }


# ---------------------------------------------------------------------------
# compute_benchmark tests
# ---------------------------------------------------------------------------

class TestComputeBenchmark:
    def test_percentile_middle(self):
        ds = _mini_dataset([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
        result = compute_benchmark(55, None, ds)
        # 5 scores below 55: 10, 20, 30, 40, 50
        assert result.percentile == 50

    def test_percentile_bottom(self):
        ds = _mini_dataset([10, 20, 30, 40, 50])
        result = compute_benchmark(5, None, ds)
        assert result.percentile == 0

    def test_percentile_top(self):
        ds = _mini_dataset([10, 20, 30, 40, 50])
        result = compute_benchmark(100, None, ds)
        assert result.percentile == 100

    def test_percentile_at_exact_score(self):
        ds = _mini_dataset([10, 20, 30, 40, 50])
        result = compute_benchmark(30, None, ds)
        # 2 scores strictly below 30: 10, 20
        assert result.percentile == 40

    def test_tied_scores(self):
        ds = _mini_dataset([30, 30, 30, 50, 50, 70, 70, 70, 70, 90])
        result = compute_benchmark(50, None, ds)
        # 3 scores below 50: 30, 30, 30
        assert result.percentile == 30

    def test_framework_percentile_when_matches(self):
        ds = _mini_dataset()
        result = compute_benchmark(55, "crewai", ds)
        assert result.framework_percentile is not None
        assert result.framework == "crewai"
        assert result.framework_count == 4
        # score=55, median=40, p75=60: should be between 50-75%
        assert 50 <= result.framework_percentile <= 75

    def test_unknown_framework_uses_other(self):
        ds = _mini_dataset()
        result = compute_benchmark(55, "some_unknown_fw", ds)
        assert result.framework_percentile is not None
        assert result.framework_count == 6  # "other" count

    def test_no_framework_returns_none(self):
        ds = _mini_dataset()
        result = compute_benchmark(55, None, ds)
        assert result.framework_percentile is None
        assert result.framework_count is None

    def test_grade_distribution_passthrough(self):
        ds = _mini_dataset()
        result = compute_benchmark(50, None, ds)
        assert result.grade_distribution == {"A": 1, "B": 1, "C": 2, "D": 3, "F": 3}

    def test_empty_dataset_graceful(self):
        ds = _mini_dataset(scores=[])
        ds["projects_scanned"] = 0
        result = compute_benchmark(50, None, ds)
        assert result.percentile == 0
        assert result.projects_in_benchmark == 0

    def test_score_distribution_is_sorted(self):
        ds = _mini_dataset([50, 10, 30, 20, 40])
        result = compute_benchmark(25, None, ds)
        assert result.score_distribution == [10, 20, 30, 40, 50]

    def test_framework_percentile_below_p25(self):
        ds = _mini_dataset()
        result = compute_benchmark(10, "crewai", ds)
        assert result.framework_percentile is not None
        assert result.framework_percentile < 25

    def test_framework_percentile_above_p75(self):
        ds = _mini_dataset()
        result = compute_benchmark(95, "crewai", ds)
        assert result.framework_percentile is not None
        assert result.framework_percentile > 75


# ---------------------------------------------------------------------------
# load_dataset tests
# ---------------------------------------------------------------------------

class TestLoadDataset:
    def setup_method(self):
        _reset_cache()

    def teardown_method(self):
        _reset_cache()

    def test_loads_valid_json(self):
        ds = load_dataset()
        assert "version" in ds
        assert "projects_scanned" in ds
        assert "distribution" in ds

    def test_has_100_scores(self):
        ds = load_dataset()
        assert len(ds["distribution"]["scores"]) == 100

    def test_scores_in_range(self):
        ds = load_dataset()
        for s in ds["distribution"]["scores"]:
            assert 0 <= s <= 100

    def test_grade_distribution_sums_to_100(self):
        ds = load_dataset()
        gd = ds["distribution"]["grade_distribution"]
        assert sum(gd.values()) == 100

    def test_has_framework_data(self):
        ds = load_dataset()
        by_fw = ds["distribution"]["by_framework"]
        assert "crewai" in by_fw
        assert "autogen" in by_fw
        assert "langgraph" in by_fw
        assert "other" in by_fw

    def test_caching_returns_same_object(self):
        ds1 = load_dataset()
        ds2 = load_dataset()
        assert ds1 is ds2


# ---------------------------------------------------------------------------
# JSON output tests
# ---------------------------------------------------------------------------

class TestBenchmarkJSON:
    def test_json_includes_benchmark(self):
        from drako.cli.scanner import run_scan
        from drako.cli.formats.json_fmt import format_json

        result = run_scan(str(FIXTURES / "crewai_basic"))
        ds = _mini_dataset()
        bench = compute_benchmark(result.score, "crewai", ds)
        output = format_json(result, benchmark=bench)
        data = json.loads(output)
        assert "benchmark" in data
        assert data["benchmark"]["percentile"] == bench.percentile
        assert data["benchmark"]["framework"] == "crewai"
        assert "projects_in_benchmark" in data["benchmark"]
        assert "grade_distribution" in data["benchmark"]

    def test_json_without_benchmark_has_no_key(self):
        from drako.cli.scanner import run_scan
        from drako.cli.formats.json_fmt import format_json

        result = run_scan(str(FIXTURES / "crewai_basic"))
        output = format_json(result)
        data = json.loads(output)
        assert "benchmark" not in data


# ---------------------------------------------------------------------------
# Terminal rendering tests
# ---------------------------------------------------------------------------

class TestBenchmarkPanel:
    def test_renders_benchmark_comparison(self):
        bench = BenchmarkResult(
            percentile=72,
            framework="crewai",
            framework_percentile=65,
            framework_count=35,
            projects_in_benchmark=100,
            grade_distribution={"A": 3, "B": 8, "C": 15, "D": 32, "F": 42},
            score_distribution=list(range(10, 110)),
        )
        output = render_benchmark_panel_to_string(bench, 58, "D")
        assert "Benchmark Comparison" in output
        assert "72%" in output
        assert "100" in output  # projects_in_benchmark
        assert "Crewai" in output  # framework name

    def test_renders_grade_distribution(self):
        bench = BenchmarkResult(
            percentile=50,
            framework=None,
            framework_percentile=None,
            framework_count=None,
            projects_in_benchmark=100,
            grade_distribution={"A": 3, "B": 8, "C": 15, "D": 32, "F": 42},
            score_distribution=list(range(10, 110)),
        )
        output = render_benchmark_panel_to_string(bench, 50, "D")
        assert "42%" in output  # F grade percentage
        assert "32%" in output  # D grade percentage

    def test_handles_empty_distribution(self):
        bench = BenchmarkResult(
            percentile=0,
            framework=None,
            framework_percentile=None,
            framework_count=None,
            projects_in_benchmark=0,
            grade_distribution={},
            score_distribution=[],
        )
        output = render_benchmark_panel_to_string(bench, 50, "D")
        assert "unavailable" in output.lower()

    def test_no_framework_omits_framework_line(self):
        bench = BenchmarkResult(
            percentile=50,
            framework=None,
            framework_percentile=None,
            framework_count=None,
            projects_in_benchmark=100,
            grade_distribution={"A": 3, "B": 8, "C": 15, "D": 32, "F": 42},
            score_distribution=list(range(10, 110)),
        )
        output = render_benchmark_panel_to_string(bench, 50, "D")
        # Should not contain framework-specific comparison
        assert "vs. None" not in output


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------

def _extract_json(result) -> dict:
    """Parse the JSON document from a CLI result's STDOUT.

    Gates and cache notices go to stderr by design (--format json stdout
    must stay machine-readable); parsing result.output (mixed streams)
    breaks the moment any gate fires.
    """
    return json.loads(result.stdout)


class TestBenchmarkCLI:
    def test_scan_with_benchmark_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(FIXTURES / "crewai_basic"), "--benchmark",
        ])
        assert result.exit_code in (0, 1)
        assert "Benchmark" in result.output

    def test_scan_json_with_benchmark(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(FIXTURES / "crewai_basic"),
            "--format", "json", "--benchmark",
        ])
        assert result.exit_code in (0, 1)
        data = _extract_json(result)
        assert "benchmark" in data
        assert "percentile" in data["benchmark"]

    def test_scan_json_without_benchmark(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(FIXTURES / "crewai_basic"), "--format", "json",
        ])
        assert result.exit_code in (0, 1)
        data = _extract_json(result)
        assert "benchmark" not in data
