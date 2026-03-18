"""Deterministic Fallback / Resilience policy rules (RES-001, RES-002)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class RES001(BasePolicy):
    """RES-001: No fallback defined for critical operations."""
    policy_id = "RES-001"
    category = "Resilience"
    severity = "HIGH"
    title = "No fallback defined for critical operations"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Check for tools with side-effects that lack fallback/error recovery
        critical_types = {"payment", "write", "execute"}
        critical_tools = [
            t for t in bom.tools
            if getattr(t, "type", "read") in critical_types
        ]

        if not critical_tools:
            return []

        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if config_content and "fallback:" in config_content:
            return []

        # Check source for try/except with alternative execution paths
        has_fallback_code = False
        fallback_patterns = [
            "fallback", "failover", "retry_with", "backup_",
            "safe_default", "graceful_degradation",
        ]
        for path, content in metadata.file_contents.items():
            for pat in fallback_patterns:
                if pat in content.lower():
                    has_fallback_code = True
                    break

        if not has_fallback_code:
            tool_names = ", ".join(
                getattr(t, "name", "unknown")[:30] for t in critical_tools[:3]
            )
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f"Critical tools ({tool_names}) have no fallback or error recovery path. "
                    "If circuit breaker trips or trust drops, the operation fails silently."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "fallback:\n"
                    "  mode: enforce\n"
                    "  tools:\n"
                    "    transfer_funds:\n"
                    "      fallback_action: escalate_human\n"
                    "      triggers:\n"
                    "        - circuit_breaker_open\n"
                    "        - trust_below: 30"
                ),
            )]
        return []


class RES002(BasePolicy):
    """RES-002: No state preservation on agent failure."""
    policy_id = "RES-002"
    category = "Resilience"
    severity = "MEDIUM"
    title = "No state preservation on agent failure"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        state_patterns = [
            "checkpoint", "save_state", "persist_state", "state_snapshot",
            "checkpointer", "MemorySaver", "SqliteSaver",
            "preserve_state", "agent_state",
        ]

        has_state_preservation = False
        for path, content in metadata.file_contents.items():
            for pat in state_patterns:
                if pat in content:
                    has_state_preservation = True
                    break

        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if config_content and "preserve_state:" in config_content:
            has_state_preservation = True

        if not has_state_preservation:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f"Project has {len(bom.agents)} agent(s) without state checkpointing. "
                    "If an agent fails mid-task, all progress is lost."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "fallback:\n"
                    "  mode: enforce\n"
                    "  default:\n"
                    "    preserve_state: true\n"
                    "    state_ttl_hours: 24\n"
                    "    fallback_action: escalate_human"
                ),
            )]
        return []


RESILIENCE_POLICIES: list[BasePolicy] = [
    RES001(),
    RES002(),
]
