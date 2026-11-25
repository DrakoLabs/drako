"""Tests for `drako validate` CLI command."""

import textwrap

import pytest
from click.testing import CliRunner

from drako.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def valid_yaml(tmp_path):
    cfg = tmp_path / ".drako.yaml"
    cfg.write_text(textwrap.dedent("""\
        version: "1.0"
        tenant_id: "t-test-001"
        api_key_env: DRAKO_API_KEY
        endpoint: https://api.getdrako.com
        framework: crewai
        agents:
          researcher:
            source: agents/researcher.py
            description: Research agent
        detected_tools:
          web_search:
            source: tools/web.py
            type: read
        dlp:
          mode: audit
        trust:
          enabled: true
        hitl:
          mode: audit
          triggers:
            tools: [web_search]
    """))
    return str(cfg)


class TestValidateCommand:
    def test_valid_config(self, runner, valid_yaml):
        result = runner.invoke(cli, ["validate", valid_yaml])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_invalid_yaml_syntax(self, runner, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("  :\n  invalid: [unterminated")
        result = runner.invoke(cli, ["validate", str(bad)])
        assert result.exit_code != 0

    def test_invalid_schema_field(self, runner, tmp_path):
        cfg = tmp_path / "invalid.yaml"
        cfg.write_text(textwrap.dedent("""\
            version: "1.0"
            tenant_id: "t-001"
            trust:
              decay_half_life_hours: [1, 2, 3]
            hitl:
              triggers:
                trust_score_below: "not-a-number"
        """))
        result = runner.invoke(cli, ["validate", str(cfg)])
        assert result.exit_code != 0
        assert "INVALID" in result.output

    def test_dlp_off_warning(self, runner, tmp_path):
        cfg = tmp_path / "warn.yaml"
        cfg.write_text(textwrap.dedent("""\
            version: "1.0"
            tenant_id: "t-001"
            dlp:
              mode: "off"
            hitl:
              mode: "off"
        """))
        result = runner.invoke(cli, ["validate", str(cfg)])
        assert result.exit_code == 0
        assert "warning" in result.output.lower()

    def test_budget_overflow_warning(self, runner, tmp_path):
        cfg = tmp_path / "budget.yaml"
        cfg.write_text(textwrap.dedent("""\
            version: "1.0"
            tenant_id: "t-001"
            finops:
              budgets:
                daily_usd: 100.0
                weekly_usd: 200.0
        """))
        result = runner.invoke(cli, ["validate", str(cfg)])
        assert result.exit_code == 0
        assert "exceeds weekly" in result.output.lower()

    def test_file_not_found(self, runner):
        result = runner.invoke(cli, ["validate", "/nonexistent/path.yaml"])
        assert result.exit_code != 0

    def test_cross_reference_warning(self, runner, tmp_path):
        cfg = tmp_path / "xref.yaml"
        cfg.write_text(textwrap.dedent("""\
            version: "1.0"
            tenant_id: "t-001"
            agents:
              researcher:
                source: agents/researcher.py
            detected_tools:
              web_search:
                source: tools/web.py
                type: read
            hitl:
              mode: audit
              triggers:
                tools: [nonexistent_tool]
        """))
        result = runner.invoke(cli, ["validate", str(cfg)])
        assert result.exit_code == 0
        assert "unknown tool" in result.output.lower()
