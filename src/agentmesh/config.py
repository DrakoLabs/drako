"""Load and validate .agentmesh.yaml configuration using Pydantic."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from agentmesh.exceptions import ConfigError


class ToolsConfig(BaseModel):
    audit_log_action: bool = True
    verify_agent_identity: bool = True
    evaluate_policy: bool = True


class GuardrailsConfig(BaseModel):
    prompt_injection_detection: bool = True
    dlp_scanning: bool = False


class TrustConfig(BaseModel):
    enabled: bool = True
    decay_half_life_hours: int = 168
    circuit_breaker_threshold: int = 3


class BFTConfig(BaseModel):
    enabled: bool = False
    quorum_size: int = 4


class AgentMeshConfig(BaseModel):
    version: str = "1.0"
    tenant_id: str
    api_key_env: str = "AGENTMESH_API_KEY"
    api_key: str | None = None
    endpoint: str = "https://api.useagentmesh.com"
    framework: str = "generic"
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    guardrails: GuardrailsConfig = Field(default_factory=GuardrailsConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    bft: BFTConfig = Field(default_factory=BFTConfig)

    @classmethod
    def load(cls, path: str = ".agentmesh.yaml") -> AgentMeshConfig:
        """Load config from a YAML file."""
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(
                f"Config file not found: {config_path.resolve()}\n"
                "Run 'agentmesh init' to create one."
            )
        try:
            with open(config_path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError(f"Expected a YAML mapping in {path}, got {type(data).__name__}")

        return cls.model_validate(data)

    def resolve_api_key(self) -> str:
        """Resolve the API key: env var first, then YAML-stored key."""
        # Priority 1: environment variable (for CI/CD overrides)
        key = os.environ.get(self.api_key_env)
        if key:
            return key
        # Priority 2: key stored in .agentmesh.yaml
        if self.api_key:
            return self.api_key
        raise ConfigError(
            f"API key not found. Set the environment variable {self.api_key_env} "
            f"or re-run 'agentmesh init' to store it in your config.\n"
            f"Set env var: export {self.api_key_env}=am_live_your_key_here"
        )

    def to_yaml(self, path: str = ".agentmesh.yaml") -> None:
        """Serialize config to a YAML file."""
        data = self.model_dump()
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
