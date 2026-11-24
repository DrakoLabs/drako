"""Tests for offline `drako init` v4 CLI."""

from pathlib import Path

import yaml
from click.testing import CliRunner

from drako.cli.main import cli
from drako.kernel.policies import compile_profile


def test_init_generates_v4_config_and_valid_acs_profile(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        res = runner.invoke(cli, ["init", "--framework", "langgraph", "--level", "balanced", "-y"])
        assert res.exit_code == 0, res.output

        cfg_p = Path(".drako.yaml")
        prof_p = Path("drako-policy.yaml")
        assert cfg_p.exists() and prof_p.exists()

        cfg = yaml.safe_load(cfg_p.read_text(encoding="utf-8"))
        assert cfg["version"] == "4.0"
        assert cfg["framework"] == "langgraph"
        assert cfg["kernel"]["spec_pin"] == "AGENT-HOOKS-0.1"
        assert cfg["kernel"]["default_effect"] == "deny"
        assert "api_key_env" not in cfg and "endpoint" not in cfg

        prof = yaml.safe_load(prof_p.read_text(encoding="utf-8"))
        compiled = compile_profile(prof)
        assert compiled["spec_pin"] == "AGENT-HOOKS-0.1"


def test_init_strict_and_autopilot_levels(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        r1 = runner.invoke(cli, ["init", "--level", "strict", "-y"])
        assert r1.exit_code == 0
        assert yaml.safe_load(Path(".drako.yaml").read_text())["kernel"]["default_effect"] == "deny"

        r2 = runner.invoke(cli, ["init", "--level", "autopilot", "-y"])
        assert r2.exit_code == 0
        assert yaml.safe_load(Path(".drako.yaml").read_text())["kernel"]["default_effect"] == "permit"


def test_init_prompts_before_overwrite(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path(".drako.yaml").write_text("version: '4.0'\nproject_id: keep\n", encoding="utf-8")
        res = runner.invoke(cli, ["init"], input="n\n")
        assert res.exit_code == 0
        assert "Aborted" in res.output
        assert "keep" in Path(".drako.yaml").read_text(encoding="utf-8")
