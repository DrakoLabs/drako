"""Tests for `drako init` CLI command."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from drako.cli.init_command import init


@pytest.fixture()
def runner():
    return CliRunner()


class TestInitDetection:
    def test_detects_crewai_project(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "crewai.yaml").touch()

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_tenant1_secret"])

        assert result.exit_code == 0
        assert "crewai" in result.output.lower()

    def test_detects_langgraph_project(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("langgraph>=0.2.0\n")

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s"])

        assert result.exit_code == 0
        assert "langgraph" in result.output.lower()

    def test_uses_generic_when_no_framework(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s"])

        assert result.exit_code == 0
        assert "generic" in result.output.lower()


class TestInitGeneratesFiles:
    def test_generates_yaml_config(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_myorg_key123", "--framework", "crewai"])

        assert result.exit_code == 0
        config_path = tmp_path / ".drako.yaml"
        assert config_path.exists()

        config = yaml.safe_load(config_path.read_text())
        assert config["tenant_id"] == "myorg"
        assert config["framework"] == "crewai"
        # v2.0: autopilot generates governance_level and dlp
        assert config["governance_level"] == "autopilot"
        assert config["dlp"]["mode"] == "audit"

    def test_generates_autopilot_by_default(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s"])

        assert result.exit_code == 0
        config_path = tmp_path / ".drako.yaml"
        assert config_path.exists()

        config = yaml.safe_load(config_path.read_text())
        assert config["governance_level"] == "autopilot"
        assert "audit" in result.output.lower() or "autopilot" in result.output.lower()

    def test_generates_manual_config(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s", "--manual"])

        assert result.exit_code == 0
        config_path = tmp_path / ".drako.yaml"
        assert config_path.exists()

        config = yaml.safe_load(config_path.read_text())
        assert config["governance_level"] == "custom"

    def test_generates_balanced_config(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s", "--balanced"])

        assert result.exit_code == 0
        config = yaml.safe_load((tmp_path / ".drako.yaml").read_text())
        assert config["governance_level"] == "balanced"
        assert config["dlp"]["mode"] == "enforce"

    def test_generates_strict_config(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s", "--strict"])

        assert result.exit_code == 0
        config = yaml.safe_load((tmp_path / ".drako.yaml").read_text())
        assert config["governance_level"] == "strict"
        assert config["dlp"]["mode"] == "enforce"
        assert config.get("intent_verification", {}).get("mode") == "enforce"


class TestInitAPIValidation:
    def test_invalid_api_key_exits(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(401, text="Unauthorized")
            )
            result = runner.invoke(init, ["--api-key", "bad_key"])

        assert result.exit_code == 1
        assert "Invalid API key" in result.output or "invalid" in result.output.lower()

    def test_offline_mode_continues(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                side_effect=httpx.ConnectError("offline")
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s", "--framework", "generic"])

        assert result.exit_code == 0
        assert "offline" in result.output.lower() or "warn" in result.output.lower()


class TestInitOverwrite:
    def test_asks_before_overwrite(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".drako.yaml").write_text("existing: true")

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            # Say skip to overwrite
            result = runner.invoke(init, ["--api-key", "am_live_t_s"], input="s\n")

        assert result.exit_code == 0
        # File should still have the original content
        assert "existing" in (tmp_path / ".drako.yaml").read_text()


class TestInitEnvHint:
    def test_suggests_env_for_dotenv(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("OTHER_VAR=foo\n")

        import respx
        import httpx
        with respx.mock:
            respx.get("https://api.useagentmesh.com/api/v1/stats").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = runner.invoke(init, ["--api-key", "am_live_t_s", "--framework", "generic"])

        assert result.exit_code == 0
        assert "DRAKO_API_KEY" in result.output
