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
    "iteration_limit", "requests_per_minute", "loop_breaker",
    "LoopBreaker",
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


def _drako_config_text(metadata: ProjectMetadata) -> str:
    """Return combined text of local .drako.yaml / drako.yaml config files."""
    parts = [
        content
        for name, content in metadata.config_files.items()
        if name in (".drako.yaml", "drako.yaml")
    ]
    return "\n".join(parts)


def _has_config_budgets(metadata: ProjectMetadata) -> bool:
    cfg = _drako_config_text(metadata).lower()
    if not cfg:
        return False
    if "magnitude:" in cfg:
        return True
    return "finops:" in cfg and any(
        k in cfg for k in ("budgets:", "daily_usd:", "weekly_usd:", "monthly_usd:")
    )


def _has_config_rate_bounds(metadata: ProjectMetadata) -> bool:
    cfg = _drako_config_text(metadata).lower()
    if not cfg:
        return False
    return any(k in cfg for k in ("loop_breaker:", "circuit_breaker:", "rate_limit:"))


def _has_config_data_controls(metadata: ProjectMetadata) -> bool:
    cfg = _drako_config_text(metadata).lower()
    profile = metadata.config_files.get("drako-policy.yaml", "").lower()
    combined = f"{cfg}\n{profile}"
    if not combined.strip():
        return False
    if _content_has_pattern(combined, _CLASSIFICATION_PATTERNS):
        return True
    return "dlp:" in cfg and "mode: enforce" in cfg


# ---------------------------------------------------------------------------
# MAG-001: No spend cap defined  (CRITICAL)
# ---------------------------------------------------------------------------

class MAG001(BasePolicy):
    policy_id = "MAG-001"
    category = "Magnitude"
    severity = "CRITICAL"
    title = "No spend cap defined"
    impact = "Without spend caps, a single agent loop can exhaust the entire LLM budget — $10K+ lost before human detection."
    attack_scenario = "Agent enters infinite reasoning loop. Without max_spend, it consumes 5M tokens ($2,500) in a single session overnight."
    references = ["https://cwe.mitre.org/data/definitions/770.html"]
    remediation_effort = "trivial"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        if _has_config_budgets(metadata):
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _SPEND_CAP_PATTERNS):
            return []

        return [self._finding(
            message=(
                f"No spend cap detected across {len(bom.agents)} agent(s). "
                f"Without budget, cost, or token limits, agents can consume "
                f"unlimited financial resources. Configure spend caps in "
                f"`.drako.yaml` (`finops.budgets`) or set `max_tokens` in code."
            ),
            fix_snippet=(
                "# Configure spend budgets in .drako.yaml:\n"
                "finops:\n"
                "  budgets:\n"
                "    daily_usd: 50.00\n"
                "    monthly_usd: 500.00"
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
    impact = "Unbounded action rates let malfunctioning agents overwhelm APIs and downstream systems with thousands of calls per minute."
    attack_scenario = "Agent retries a failing API call without backoff. 10,000 requests/minute overwhelm the service, causing outage for all users."
    references = ["https://cwe.mitre.org/data/definitions/770.html"]
    remediation_effort = "trivial"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        if _has_config_rate_bounds(metadata):
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _RATE_LIMIT_PATTERNS):
            return []

        return [self._finding(
            message=(
                f"No rate limit detected across {len(bom.agents)} agent(s). "
                f"Without max_iterations, max_steps, or loop bounds, agents "
                f"can execute unlimited actions. Configure `loop_breaker` or "
                f"`circuit_breaker` in `.drako.yaml`, or add rate limits in code."
            ),
            fix_snippet=(
                "# Configure loop protection in .drako.yaml:\n"
                "loop_breaker:\n"
                "  enabled: true\n"
                "  trip_threshold: 10\n"
                "  window_seconds: 300.0"
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
    impact = "Agents accessing databases without clearance levels can read data above their authorization, violating data governance."
    attack_scenario = "Research agent with DB access queries PII table meant only for compliance team. No clearance check prevents the access."
    references = ["https://cwe.mitre.org/data/definitions/863.html"]
    remediation_effort = "moderate"

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

        if _has_config_data_controls(metadata):
            return []

        # Check if classification / clearance is defined
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _CLASSIFICATION_PATTERNS):
            return []

        return [self._finding(
            message=(
                "Agent(s) access data sources (DB/files) without a sensitivity "
                "classification or clearance level defined. Without scope limits, "
                "agents may access data above their authorization. Enable "
                "`dlp.mode: enforce` in `.drako.yaml` and restrict data tools "
                "in `drako-policy.yaml`."
            ),
            fix_snippet=(
                "# Enforce DLP and least-privilege tool rules in .drako.yaml:\n"
                "dlp:\n"
                "  mode: enforce"
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
