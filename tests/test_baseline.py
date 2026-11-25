"""Tests for the baseline system (fingerprinting, filtering, CLI commands)."""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from drako.cli.baseline import Baseline, fingerprint
from drako.cli.main import cli
from drako.cli.policies.base import Finding

FIXTURES = Path(__file__).parent / "fixtures"


def _make_finding(
    rule_id: str = "SEC-001",
    file_path: str = "src/main.py",
    line_number: int = 42,
    snippet: str = 'API_KEY = "sk-abc123"',
    message: str = "Hardcoded secret",
    severity: str = "CRITICAL",
) -> Finding:
    return Finding(
        policy_id=rule_id,
        category="Security",
        severity=severity,
        title="Test finding",
        message=message,
        file_path=file_path,
        line_number=line_number,
        code_snippet=snippet,
    )


class TestFingerprint:
    def test_stable_across_line_changes(self):
        """Moving code to different line = same fingerprint."""
        f1 = _make_finding(line_number=10)
        f2 = _make_finding(line_number=99)
        assert fingerprint(f1) == fingerprint(f2)

    def test_different_rules_different_fingerprint(self):
        f1 = _make_finding(rule_id="SEC-001")
        f2 = _make_finding(rule_id="GOV-001")
        assert fingerprint(f1) != fingerprint(f2)

    def test_different_files_different_fingerprint(self):
        f1 = _make_finding(file_path="src/a.py")
        f2 = _make_finding(file_path="src/b.py")
        assert fingerprint(f1) != fingerprint(f2)

    def test_code_change_different_fingerprint(self):
        f1 = _make_finding(snippet='KEY = "old"')
        f2 = _make_finding(snippet='KEY = "new"')
        assert fingerprint(f1) != fingerprint(f2)

    def test_whitespace_normalization(self):
        """Whitespace changes = same fingerprint."""
        f1 = _make_finding(snippet="  x = 1  ")
        f2 = _make_finding(snippet="x = 1")
        assert fingerprint(f1) == fingerprint(f2)

    def test_none_snippet_uses_message(self):
        """When snippet is None, message is used as differentiator."""
        f1 = _make_finding(snippet=None, message="Message A")
        f2 = _make_finding(snippet=None, message="Message B")
        assert fingerprint(f1) != fingerprint(f2)

    def test_path_normalization(self):
        """Windows backslashes normalized to forward slashes."""
        f1 = _make_finding(file_path="src\\main.py")
        f2 = _make_finding(file_path="src/main.py")
        assert fingerprint(f1) == fingerprint(f2)


class TestBaseline:
    def test_save_and_load(self, tmp_path):
        bl = Baseline(str(tmp_path))
        findings = [_make_finding("SEC-001"), _make_finding("GOV-001")]
        bl.save(findings)

        assert bl.exists()
        data = bl.load()
        assert data is not None
        assert data["finding_count"] == 2
        assert len(data["fingerprints"]) == 2

    def test_filter_new_findings(self, tmp_path):
        bl = Baseline(str(tmp_path))
        old_findings = [_make_finding("SEC-001", snippet="old code")]
        bl.save(old_findings)

        current = [
            _make_finding("SEC-001", snippet="old code"),
            _make_finding("GOV-001", snippet="new code"),
        ]
        new, baselined, resolved = bl.filter_findings(current)

        assert len(new) == 1
        assert new[0].policy_id == "GOV-001"
        assert len(baselined) == 1
        assert baselined[0].policy_id == "SEC-001"
        assert len(resolved) == 0

    def test_resolved_detection(self, tmp_path):
        bl = Baseline(str(tmp_path))
        bl.save([_make_finding("SEC-001")])

        new, baselined, resolved = bl.filter_findings([])
        assert len(new) == 0
        assert len(baselined) == 0
        assert len(resolved) == 1

    def test_reset(self, tmp_path):
        bl = Baseline(str(tmp_path))
        bl.save([_make_finding("SEC-001")])
        assert bl.reset() is True
        assert bl.exists() is False
        assert bl.reset() is False

    def test_no_code_snippets_stored(self, tmp_path):
        bl = Baseline(str(tmp_path))
        bl.save([_make_finding(snippet='secret_key = "my_super_secret_value"')])
        raw = bl.path.read_text()
        assert "my_super_secret_value" not in raw
        assert "secret_key" not in raw

    def test_summary(self, tmp_path):
        bl = Baseline(str(tmp_path))
        bl.save([
            _make_finding("SEC-001", severity="CRITICAL"),
            _make_finding("GOV-001", severity="HIGH", snippet="other"),
        ])
        info = bl.summary()
        assert info is not None
        assert info["total_findings"] == 2
        assert info["severity_counts"]["CRITICAL"] == 1
        assert info["severity_counts"]["HIGH"] == 1

    def test_corrupt_baseline_returns_none(self, tmp_path):
        bl = Baseline(str(tmp_path))
        bl._dir.mkdir(exist_ok=True)
        bl.path.write_text("not valid json", encoding="utf-8")
        assert bl.load() is None

    def test_no_baseline_filter_returns_all(self, tmp_path):
        bl = Baseline(str(tmp_path))
        findings = [_make_finding("SEC-001")]
        new, baselined, resolved = bl.filter_findings(findings)
        assert len(new) == 1
        assert len(baselined) == 0


class TestBaselineCommand:
    def test_show_no_baseline(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "show", str(tmp_path)])
        assert result.exit_code == 0
        assert "No baseline" in result.output

    def test_reset_no_baseline(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "reset", str(tmp_path)])
        assert result.exit_code == 0
        assert "No baseline" in result.output

    def test_scan_with_baseline_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(FIXTURES / "crewai_basic"), "--baseline",
        ])
        assert result.exit_code in (0, 1)
        assert "baseline" in result.output.lower()

    def test_show_after_baseline(self):
        runner = CliRunner()
        # Create baseline
        runner.invoke(cli, [
            "scan", str(FIXTURES / "crewai_basic"), "--baseline",
        ])
        # Show it
        result = runner.invoke(cli, [
            "baseline", "show", str(FIXTURES / "crewai_basic"),
        ])
        assert result.exit_code == 0
        assert "Total baselined findings" in result.output


class TestBaselineSarif:
    def test_sarif_baseline_state(self):
        from drako.cli.baseline import fingerprint as fp
        from drako.cli.formats.sarif import format_sarif
        from drako.cli.scanner import run_scan

        result = run_scan(str(FIXTURES / "crewai_basic"))
        if not result.findings:
            pytest.skip("No findings in fixture")

        # Use first finding's fingerprint as baseline
        baseline_fps = {fp(result.findings[0])}
        sarif = json.loads(format_sarif(result, baseline_fingerprints=baseline_fps))

        results = sarif["runs"][0]["results"]
        states = [r.get("baselineState") for r in results]
        assert "unchanged" in states
        assert "new" in states
