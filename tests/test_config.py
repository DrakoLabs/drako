"""Tests for local-first Drako v4 `.drako.yaml` configuration."""

from pathlib import Path

import pytest
import yaml

from drako.config import DrakoConfig, MCPConfig
from drako.exceptions import ConfigError


class TestConfigLoad:
    def test_load_valid_v4_config(self, tmp_path: Path):
        cfg_file = tmp_path / ".drako.yaml"
        cfg_file.write_text(
            "version: '4.0'\nproject_id: acme-agents\ngovernance_level: strict\n"
            "kernel:\n  spec_pin: AGENT-HOOKS-0.1\n  default_effect: deny\n",
            encoding="utf-8",
        )
        cfg = DrakoConfig.load(str(cfg_file))
        assert cfg.version == "4.0"
        assert cfg.project_id == "acme-agents"
        assert cfg.kernel.spec_pin == "AGENT-HOOKS-0.1"
        assert cfg.kernel.default_effect == "deny"

    def test_load_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(ConfigError, match="not found"):
            DrakoConfig.load(str(tmp_path / "missing.yaml"))

    def test_load_invalid_yaml_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(":::bad:::\n\t[", encoding="utf-8")
        with pytest.raises(ConfigError):
            DrakoConfig.load(str(bad))

    def test_ignores_deprecated_v3_saas_keys_gracefully(self):
        cfg = DrakoConfig.model_validate(
            {
                "version": "1.0",
                "tenant_id": "legacy",
                "api_key_env": "DRAKO_API_KEY",
                "endpoint": "https://api.getdrako.com",
            }
        )
        assert cfg.tenant_id == "legacy"
        assert not hasattr(cfg, "endpoint")
        assert not hasattr(cfg, "api_key_env")


class TestConfigDefaults:
    def test_v4_fail_closed_defaults(self):
        cfg = DrakoConfig()
        assert cfg.version == "4.0"
        assert cfg.kernel.spec_pin == "AGENT-HOOKS-0.1"
        assert cfg.kernel.default_effect == "deny"
        assert cfg.loop_breaker.enabled is True
        assert cfg.loop_breaker.trip_threshold == 10
        assert cfg.a2a.require_signed_cards is True
        assert cfg.proxy.host == "127.0.0.1"

    def test_mcp_defaults_deny_by_default(self):
        mcp = MCPConfig()
        assert mcp.env_allowlist == []
        assert mcp.enforce_pin is True
        assert mcp.allow_auto_install is False
        assert mcp.protocol_version == "2026-07-28"

    def test_to_yaml_roundtrip(self, tmp_path: Path):
        cfg = DrakoConfig(project_id="roundtrip-proj", framework="langgraph")
        out = tmp_path / ".drako.yaml"
        cfg.to_yaml(str(out))
        reloaded = DrakoConfig.load(str(out))
        assert reloaded.project_id == "roundtrip-proj"
        assert reloaded.framework == "langgraph"
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert "api_key_env" not in raw and "endpoint" not in raw
