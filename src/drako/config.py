"""Load and validate .drako.yaml configuration using Pydantic."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from drako.exceptions import ConfigError


# ------------------------------------------------------------------
# Legacy config models (kept for backward compatibility)
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# New config models for rich YAML (v1.0 rewrite)
# ------------------------------------------------------------------

class AgentEntry(BaseModel):
    source: str = ""
    description: str = ""


class ToolEntry(BaseModel):
    source: str = ""
    type: str = "read"  # read | write | execute | network | payment


class DLPConfig(BaseModel):
    mode: str = "audit"  # audit | enforce | off


class CircuitBreakerAgentConfig(BaseModel):
    failure_threshold: int = 10
    time_window_seconds: int = 300
    recovery_timeout_seconds: int = 60


class CircuitBreakerConfig(BaseModel):
    agent_level: CircuitBreakerAgentConfig = Field(default_factory=CircuitBreakerAgentConfig)


class GovernanceConfig(BaseModel):
    on_backend_unreachable: str = "allow"  # "allow" | "block"


class AuditNewConfig(BaseModel):
    enabled: bool = True


# ------------------------------------------------------------------
# HITL (Human-in-the-Loop) Checkpoint config  [requires Pro]
# ------------------------------------------------------------------

class HITLTriggersConfig(BaseModel):
    tool_types: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    trust_score_below: float | None = None
    spend_above_usd: float | None = None
    records_above: int | None = None
    first_time_tool: bool = False
    first_time_action: bool = False


class HITLNotificationConfig(BaseModel):
    webhook_url: str | None = None
    email: str | None = None


class HITLConfig(BaseModel):
    mode: str = "off"  # "audit" | "enforce" | "off"
    triggers: HITLTriggersConfig = Field(default_factory=HITLTriggersConfig)
    notification: HITLNotificationConfig = Field(default_factory=HITLNotificationConfig)
    approval_timeout_minutes: int = 30
    timeout_action: str = "reject"  # "reject" | "allow"


# ------------------------------------------------------------------
# Intent Fingerprinting config  [requires Pro]
# ------------------------------------------------------------------

class IntentRequiredForConfig(BaseModel):
    tool_types: list[str] = Field(default_factory=lambda: ["payment", "write", "execute"])
    tools: list[str] = Field(default_factory=list)


class IntentVerificationConfig(BaseModel):
    mode: str = "off"  # "audit" | "enforce" | "off"
    required_for: IntentRequiredForConfig = Field(default_factory=IntentRequiredForConfig)
    anti_replay: bool = True
    intent_ttl_seconds: int = 300


# ------------------------------------------------------------------
# Programmable Hooks config  [requires Pro]
# ------------------------------------------------------------------

class HookEntryConfig(BaseModel):
    name: str
    condition: str | None = None
    script: str | None = None
    timeout_ms: int = 5000
    action_on_fail: str = "allow"  # "allow" | "block"
    priority: int = 0


class HooksConfig(BaseModel):
    pre_action: list[HookEntryConfig] = Field(default_factory=list)
    post_action: list[HookEntryConfig] = Field(default_factory=list)
    on_error: list[HookEntryConfig] = Field(default_factory=list)
    on_session_end: list[HookEntryConfig] = Field(default_factory=list)


# ------------------------------------------------------------------
# Agentic FinOps config  [requires Pro]
# ------------------------------------------------------------------

class ModelCostConfig(BaseModel):
    input: float = 0.0
    output: float = 0.0


class FinOpsRoutingRuleConfig(BaseModel):
    condition: str = ""
    model: str = ""
    reason: str = ""


class FinOpsRoutingConfig(BaseModel):
    enabled: bool = False
    default_model: str = "gpt-4o"
    rules: list[FinOpsRoutingRuleConfig] = Field(default_factory=list)


class FinOpsCacheConfig(BaseModel):
    enabled: bool = False
    similarity_threshold: float = 0.92
    ttl_hours: int = 24


class FinOpsBudgetConfig(BaseModel):
    daily_usd: float | None = None
    weekly_usd: float | None = None
    monthly_usd: float | None = None
    alert_at_percent: list[int] = Field(default_factory=lambda: [50, 80, 95])


class FinOpsTrackingConfig(BaseModel):
    enabled: bool = True
    model_costs: dict[str, ModelCostConfig] = Field(default_factory=dict)


class FinOpsConfig(BaseModel):
    tracking: FinOpsTrackingConfig = Field(default_factory=FinOpsTrackingConfig)
    routing: FinOpsRoutingConfig = Field(default_factory=FinOpsRoutingConfig)
    cache: FinOpsCacheConfig = Field(default_factory=FinOpsCacheConfig)
    budgets: FinOpsBudgetConfig = Field(default_factory=FinOpsBudgetConfig)


# ------------------------------------------------------------------
# Deterministic Fallback config  [requires Pro]
# ------------------------------------------------------------------

class FallbackToolConfig(BaseModel):
    fallback_script: str | None = None
    fallback_agent: str | None = None
    fallback_action: str = "escalate_human"
    safe_default: str | None = None
    triggers: list[str] = Field(default_factory=lambda: ["circuit_breaker_open"])


class FallbackDefaultConfig(BaseModel):
    fallback_action: str = "escalate_human"
    preserve_state: bool = True
    state_ttl_hours: int = 24


class FallbackConfig(BaseModel):
    mode: str = "off"  # "audit" | "enforce" | "off"
    tools: dict[str, FallbackToolConfig] = Field(default_factory=dict)
    default: FallbackDefaultConfig = Field(default_factory=FallbackDefaultConfig)


# ------------------------------------------------------------------
# Secure A2A config  [requires Enterprise]
# ------------------------------------------------------------------

class A2AAuthConfig(BaseModel):
    method: str = "did_exchange"  # did_exchange | mtls | shared_secret
    auto_rotate: bool = True
    rotation_hours: int = 24


class A2AChannelRuleConfig(BaseModel):
    from_agent: str = Field(alias="from", default="*")
    to_agent: str = Field(alias="to", default="*")
    allowed_message_types: list[str] = Field(default_factory=list)
    max_payload_size_kb: int = 500
    require_intent_verification: bool = False
    policy: str | None = None  # "deny" for explicit block

    class Config:
        populate_by_name = True


class A2AWormDetectionConfig(BaseModel):
    enabled: bool = True
    scan_inter_agent_messages: bool = True
    max_propagation_depth: int = 3
    circular_reference_block: bool = True


class A2AConfig(BaseModel):
    mode: str = "off"  # audit | enforce | off
    auth: A2AAuthConfig = Field(default_factory=A2AAuthConfig)
    channels: list[A2AChannelRuleConfig] = Field(default_factory=list)
    worm_detection: A2AWormDetectionConfig = Field(default_factory=A2AWormDetectionConfig)


# ------------------------------------------------------------------
# Multi-Agent Topology config  [requires Enterprise]
# ------------------------------------------------------------------

class TopologyConflictDetectionConfig(BaseModel):
    resource_contention: bool = True
    contradictory_actions: bool = True
    cascade_amplification: bool = True
    resource_exhaustion: bool = True


class TopologyConfig(BaseModel):
    enabled: bool = False
    conflict_detection: TopologyConflictDetectionConfig = Field(
        default_factory=TopologyConflictDetectionConfig
    )
    alert_on: list[str | dict] = Field(default_factory=lambda: ["circular_dependency", "resource_contention"])


# ------------------------------------------------------------------
# Chaos Engineering config  [requires Enterprise]
# ------------------------------------------------------------------

class ChaosExperimentConfig(BaseModel):
    name: str
    description: str = ""
    target_tool: str | None = None
    target_agent: str | None = None
    fault_type: str = "tool_deny"
    duration_seconds: int = 60
    latency_ms: int | None = None
    remaining_usd: float | None = None


class ChaosSafetyConfig(BaseModel):
    max_blast_radius: int = 1
    auto_rollback_on_failure: bool = True
    require_approval: bool = True


class ChaosConfig(BaseModel):
    experiments: list[ChaosExperimentConfig] = Field(default_factory=list)
    safety: ChaosSafetyConfig = Field(default_factory=ChaosSafetyConfig)


# ------------------------------------------------------------------
# Main config
# ------------------------------------------------------------------

class DrakoConfig(BaseModel):
    version: str = "1.0"
    governance_level: str = "custom"  # autopilot | balanced | strict | custom
    extends: str | None = None  # policy template inheritance (e.g. "fintech")
    tenant_id: str
    api_key_env: str = "DRAKO_API_KEY"
    api_key: str | None = None
    endpoint: str = "https://api.useagentmesh.com"
    framework: str = "generic"
    # Legacy feature flags
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    guardrails: GuardrailsConfig = Field(default_factory=GuardrailsConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    bft: BFTConfig = Field(default_factory=BFTConfig)
    # New rich config fields (all optional with defaults for backward compat)
    agents: dict[str, AgentEntry] = Field(default_factory=dict)
    detected_tools: dict[str, ToolEntry] = Field(default_factory=dict)
    dlp: DLPConfig = Field(default_factory=DLPConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    audit: AuditNewConfig = Field(default_factory=AuditNewConfig)
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)
    # Sprint 2 features (Pro+)
    hitl: HITLConfig = Field(default_factory=HITLConfig)
    intent_verification: IntentVerificationConfig = Field(default_factory=IntentVerificationConfig)
    # Sprint 3 features (Pro+)
    hooks: HooksConfig = Field(default_factory=HooksConfig)
    # Sprint 4 features (Pro+)
    finops: FinOpsConfig = Field(default_factory=FinOpsConfig)
    fallback: FallbackConfig = Field(default_factory=FallbackConfig)
    # Sprint 5 features (Enterprise)
    a2a: A2AConfig = Field(default_factory=A2AConfig)
    topology: TopologyConfig = Field(default_factory=TopologyConfig)
    chaos: ChaosConfig = Field(default_factory=ChaosConfig)

    @classmethod
    def load(cls, path: str = ".drako.yaml") -> DrakoConfig:
        """Load config from a YAML file, resolving template inheritance."""
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(
                f"Config file not found: {config_path.resolve()}\n"
                "Run 'drako init' to create one."
            )
        try:
            with open(config_path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError(f"Expected a YAML mapping in {path}, got {type(data).__name__}")

        # Resolve template inheritance if extends: is set
        if "extends" in data and data["extends"]:
            from drako.templates import load_template, deep_merge
            template_name = data["extends"]
            template_data = load_template(template_name)
            data = deep_merge(template_data, data)

        return cls.model_validate(data)

    def resolve_api_key(self) -> str:
        """Resolve the API key: env var first, then YAML-stored key."""
        # Priority 1: environment variable (for CI/CD overrides)
        key = os.environ.get(self.api_key_env)
        if key:
            return key
        # Priority 2: key stored in .drako.yaml
        if self.api_key:
            return self.api_key
        raise ConfigError(
            f"API key not found. Set the environment variable {self.api_key_env} "
            f"or re-run 'drako init' to store it in your config.\n"
            f"Set env var: export {self.api_key_env}=am_live_your_key_here"
        )

    def to_yaml(self, path: str = ".drako.yaml") -> None:
        """Serialize config to a YAML file."""
        data = self.model_dump()
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
