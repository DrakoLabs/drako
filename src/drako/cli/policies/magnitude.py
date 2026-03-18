"""Pre-Action Magnitude Limits policy rules (MAG-001 through MAG-003).

Detects the ABSENCE of magnitude constraints — agents operating without
financial spend caps, rate limits, or data sensitivity classifications.

Category: "Magnitude"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# Patterns indicating spend / cost / token caps
_SPEND_CAP_PATTERNS = [
    "max_tokens", "token_limit", "budget", "max_budget", "cost_limit",
    "max_cost", "spend_limit", "max_spend", "token_budget",
    "max_completion_tokens", "max_output_tokens", "max_spend_per_action",
    "max_spend_per_session", "magnitude_limits",
]

# Patterns indicating rate limits / iteration caps
_RATE_LIMIT_PATTERNS = [
    "max_iterations", "max_steps", "rate_limit", "max_actions",
    "max_actions_per_minute", "max_requests", "throttle",
    "max_retries", "step_limit", "max_turns", "max_rounds",
    "iteration_limit", "requests_per_minute",
]

# Tool names that imply DB / file data access
_DATA_ACCESS_TOOLS = {
    "read_db", "query", "sql", "execute_sql", "run_query",
    "read_file", "file_search", "search_files", "get_records",
    "list_records", "fetch_data", "db_query", "database",
}

# Patterns indicating data sensitivity classification
_CLASSIFICATION_PATTERNS = [
    "classification", "clearance", "sensitivity", "sensitivity_level",
    "data_class", "security_level", "access_level", "confidential",
    "restricted", "max_sensitivity",
]


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    """Check if any pattern exists in the combined content."""
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


# ---------------------------------------------------------------------------
# MAG-001: No spend cap defined  (CRITICAL)
# ---------------------------------------------------------------------------

class MAG001(BasePolicy):
    policy_id = "MAG-001"
    category = "Magnitude"
    severity = "CRITICAL"
    title = "No spend cap defined"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _SPEND_CAP_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No spend cap detected across {len(bom.agents)} agent(s). "
                f"Without budget, cost, or token limits, agents can consume "
                f"unlimited financial resources. Define magnitude limits "
                f"via the Drako dashboard (requires Pro plan)."
            ),
        )]


# ---------------------------------------------------------------------------
# MAG-002: No rate limit defined  (HIGH)
# ---------------------------------------------------------------------------

class MAG002(BasePolicy):
    policy_id = "MAG-002"
    category = "Magnitude"
    severity = "HIGH"
    title = "No rate limit defined"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _RATE_LIMIT_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No rate limit detected across {len(bom.agents)} agent(s). "
                f"Without max_iterations, max_steps, or rate limiting, agents "
                f"can execute unlimited actions. Define magnitude limits "
                f"via the Drako dashboard (requires Pro plan)."
            ),
        )]


# ---------------------------------------------------------------------------
# MAG-003: Sensitive data access without clearance  (HIGH)
# ---------------------------------------------------------------------------

class MAG003(BasePolicy):
    policy_id = "MAG-003"
    category = "Magnitude"
    severity = "HIGH"
    title = "Sensitive data access without clearance"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        # Check if any agent has data-access tools
        has_data_tools = False
        for agent in bom.agents:
            for tool in agent.tools:
                tool_lower = tool.lower()
                if any(pat in tool_lower for pat in _DATA_ACCESS_TOOLS):
                    has_data_tools = True
                    break
            if has_data_tools:
                break

        if not has_data_tools:
            return []

        # Check if classification / clearance is defined
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _CLASSIFICATION_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"Agent(s) access data sources (DB/files) without a sensitivity "
                f"classification or clearance level defined. Without scope limits, "
                f"agents may access data above their authorization. Define scope "
                f"magnitude limits via the Drako dashboard (requires Pro plan)."
            ),
        )]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

MAGNITUDE_POLICIES: list[BasePolicy] = [
    MAG001(),
    MAG002(),
    MAG003(),
]
