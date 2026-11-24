"""Load and validate local-first .drako.yaml configuration using Pydantic (v4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from drako.exceptions import ConfigError


class AgentEntry(BaseModel):
    source: str = ""
    description: str = ""


class ToolEntry(BaseModel):
    source: str = ""
    type: str = "read"  # read | write | execute | network | payment


class KernelConfig(BaseModel):
    """Authority Kernel configuration (AGENT-HOOKS-0.1)."""

    spec_pin: str = "AGENT-HOOKS-0.1"
    default_effect: str = "deny"  # deny (fail-closed) | permit
    profile_path: str | None = None  # optional external ACS YAML profile
    receipt_store: str = ".drako/receipts.jsonl"
    operator_pubkey_path: str | None = None  # target-side sealed pubkey for ConsentTokens
    tiers: dict[str, str] = Field(
        default_factory=lambda: {
            "read": "auto",
            "write": "audit",
            "external_comms": "audit",
            "irreversible": "consent",
        }
    )


class LoopBreakerConfig(BaseModel):
    """Runaway repetition circuit-breaker (OWASP ASI08/ASI10)."""

    enabled: bool = True
    trip_threshold: int = 10
    window_seconds: float = 300.0


class DLPConfig(BaseModel):
    mode: str = "audit"  # audit | enforce | off


class CircuitBreakerAgentConfig(BaseModel):
    failure_threshold: int = 10
    time_window_seconds: int = 300
    recovery_timeout_seconds: int = 60


class CircuitBreakerConfig(BaseModel):
    agent_level: CircuitBreakerAgentConfig = Field(default_factory=CircuitBreakerAgentConfig)


class AuditConfig(BaseModel):
    enabled: bool = True
    cryptographic: bool = True
    receipt_store: str = ".drako/receipts.jsonl"
    retention_days: int = 90


class HITLTriggersConfig(BaseModel):
    tool_types: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    trust_score_below: float | None = None
    spend_above_usd: float | None = None
    records_above: int | None = None
    first_time_tool: bool = False
    first_time_action: bool = False


class HITLConfig(BaseModel):
    mode: str = "enforce"  # audit | enforce | off
    triggers: HITLTriggersConfig = Field(default_factory=HITLTriggersConfig)
    approval_timeout_minutes: int = 30
    timeout_action: str = "reject"  # reject | allow


class IntentRequiredForConfig(BaseModel):
    tool_types: list[str] = Field(default_factory=lambda: ["payment", "write", "execute"])
    tools: list[str] = Field(default_factory=list)


class IntentVerificationConfig(BaseModel):
    mode: str = "enforce"  # audit | enforce | off
    required_for: IntentRequiredForConfig = Field(default_factory=IntentRequiredForConfig)
    anti_replay: bool = True
    intent_ttl_seconds: int = 300


class HookEntryConfig(BaseModel):
    name: str
    condition: str | None = None
    script: str | None = None
    timeout_ms: int = 5000
    action_on_fail: str = "block"  # block | allow
    priority: int = 0


class HooksConfig(BaseModel):
    pre_action: list[HookEntryConfig] = Field(default_factory=list)
    post_action: list[HookEntryConfig] = Field(default_factory=list)
    on_error: list[HookEntryConfig] = Field(default_factory=list)
    on_session_end: list[HookEntryConfig] = Field(default_factory=list)


class ModelCostConfig(BaseModel):
    input: float = 0.0
    output: float = 0.0


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
    budgets: FinOpsBudgetConfig = Field(default_factory=FinOpsBudgetConfig)


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
    mode: str = "off"  # audit | enforce | off
    tools: dict[str, FallbackToolConfig] = Field(default_factory=dict)
    default: FallbackDefaultConfig = Field(default_factory=FallbackDefaultConfig)


class A2AChannelRuleConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_agent: str = Field(alias="from", default="*")
    to_agent: str = Field(alias="to", default="*")
    allowed_message_types: list[str] = Field(default_factory=list)
    max_payload_size_kb: int = 500
    require_intent_verification: bool = False
    policy: str | None = None


class A2AWormDetectionConfig(BaseModel):
    enabled: bool = True
    scan_inter_agent_messages: bool = True
    max_propagation_depth: int = 3
    circular_reference_block: bool = True
    block_suspicious: bool = False


class A2AConfig(BaseModel):
    mode: str = "enforce"  # audit | enforce | off
    require_signed_cards: bool = True
    trusted_pubkeys_dir: str | None = None
    channels: list[A2AChannelRuleConfig] = Field(default_factory=list)
    worm_detection: A2AWormDetectionConfig = Field(default_factory=A2AWormDetectionConfig)


class MCPConfig(BaseModel):
    """MCP supply-chain & runtime guard configuration."""

    lockfile: str = "mcp.lock"
    enforce_pin: bool = True
    env_allowlist: list[str] = Field(default_factory=list)
    allow_auto_install: bool = False
    protocol_version: str = "2026-07-28"


class EgressConfig(BaseModel):
    """Outbound network SSRF allowlist enforced by drako.kernel.egress."""

    allowed_domains: list[str] = Field(default_factory=list)


class ProxyConfig(BaseModel):
    """Local enforcement proxy settings (loopback-only by default)."""

    host: str = "127.0.0.1"
    port: int = 8990
    cors_origins: list[str] = Field(default_factory=list)


class DrakoConfig(BaseModel):
    """Root `.drako.yaml` schema for Drako v4 (100% local-first)."""

    model_config = ConfigDict(extra="ignore")

    version: str = "4.0"
    project_id: str = "default"
    tenant_id: str | None = None  # optional legacy alias kept for smooth v3 migration
    governance_level: str = "balanced"  # autopilot | balanced | strict | custom
    extends: str | None = None
    framework: str = "generic"

    kernel: KernelConfig = Field(default_factory=KernelConfig)
    loop_breaker: LoopBreakerConfig = Field(default_factory=LoopBreakerConfig)
    agents: dict[str, AgentEntry] = Field(default_factory=dict)
    detected_tools: dict[str, ToolEntry] = Field(default_factory=dict)
    dlp: DLPConfig = Field(default_factory=DLPConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    hitl: HITLConfig = Field(default_factory=HITLConfig)
    intent_verification: IntentVerificationConfig = Field(default_factory=IntentVerificationConfig)
    hooks: HooksConfig = Field(default_factory=HooksConfig)
    finops: FinOpsConfig = Field(default_factory=FinOpsConfig)
    fallback: FallbackConfig = Field(default_factory=FallbackConfig)
    a2a: A2AConfig = Field(default_factory=A2AConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)

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
            with open(config_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError(f"Expected a YAML mapping in {path}, got {type(data).__name__}")

        if "extends" in data and data["extends"]:
            from drako.templates import deep_merge, load_template

            template_data = load_template(data["extends"])
            data = deep_merge(template_data, data)

        return cls.model_validate(data)

    def to_yaml(self, path: str = ".drako.yaml") -> None:
        """Serialize config to a YAML file."""
        data: dict[str, Any] = self.model_dump(exclude_none=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
