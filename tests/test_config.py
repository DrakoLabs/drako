"""Tests for DrakoConfig — YAML loading, validation, defaults."""

from __future__ import annotations

import pytest
import yaml

from drako.config import DrakoConfig
from drako.exceptions import ConfigError


class TestConfigLoad:
    def test_load_valid_config(self, config_file):
        config = DrakoConfig.load(config_file)
        assert config.tenant_id == "testtenant"
        assert config.framework == "crewai"
        assert config.endpoint == "https://api.drako.test"

    def test_load_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            DrakoConfig.load(str(tmp_path / "nonexistent.yaml"))

    def test_load_invalid_yaml(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(": : : invalid yaml {{")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            DrakoConfig.load(str(bad))

    def test_load_non_mapping(self, tmp_path):
        non_map = tmp_path / "list.yaml"
        non_map.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="Expected a YAML mapping"):
            DrakoConfig.load(str(non_map))

    def test_load_missing_required_field(self, tmp_path):
        # tenant_id is required
        incomplete = tmp_path / "incomplete.yaml"
        incomplete.write_text(yaml.dump({"version": "1.0", "framework": "generic"}))
        with pytest.raises(Exception):  # Pydantic validation error
            DrakoConfig.load(str(incomplete))


class TestConfigDefaults:
    def test_default_tools(self):
        config = DrakoConfig(tenant_id="t1")
        assert config.tools.audit_log_action is True
        assert config.tools.verify_agent_identity is True
        assert config.tools.evaluate_policy is True

    def test_default_guardrails(self):
        config = DrakoConfig(tenant_id="t1")
        assert config.guardrails.prompt_injection_detection is True
        assert config.guardrails.dlp_scanning is False

    def test_default_trust(self):
        config = DrakoConfig(tenant_id="t1")
        assert config.trust.enabled is True
        assert config.trust.decay_half_life_hours == 168
        assert config.trust.circuit_breaker_threshold == 3

    def test_default_bft(self):
        config = DrakoConfig(tenant_id="t1")
        assert config.bft.enabled is False
        assert config.bft.quorum_size == 4

    def test_default_endpoint(self):
        config = DrakoConfig(tenant_id="t1")
        assert config.endpoint == "https://api.useagentmesh.com"

    def test_default_framework(self):
        config = DrakoConfig(tenant_id="t1")
        assert config.framework == "generic"


class TestConfigResolveApiKey:
    def test_resolve_from_env(self, monkeypatch):
        monkeypatch.setenv("DRAKO_API_KEY", "am_live_t_k")
        config = DrakoConfig(tenant_id="t1")
        assert config.resolve_api_key() == "am_live_t_k"

    def test_resolve_custom_env_var(self, monkeypatch):
        monkeypatch.setenv("MY_KEY", "am_test_t_k")
        config = DrakoConfig(tenant_id="t1", api_key_env="MY_KEY")
        assert config.resolve_api_key() == "am_test_t_k"

    def test_resolve_missing_raises(self):
        config = DrakoConfig(tenant_id="t1")
        with pytest.raises(ConfigError, match="not found"):
            config.resolve_api_key()


class TestConfigSerialization:
    def test_to_yaml_roundtrip(self, tmp_path):
        config = DrakoConfig(tenant_id="roundtrip", framework="langgraph")
        path = str(tmp_path / "out.yaml")
        config.to_yaml(path)
        loaded = DrakoConfig.load(path)
        assert loaded.tenant_id == "roundtrip"
        assert loaded.framework == "langgraph"
        assert loaded.tools.audit_log_action is True
