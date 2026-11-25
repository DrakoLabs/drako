"""Operational Design Domain (ODD) policy rules (ODD-001 through ODD-004).

Detects the ABSENCE of operational boundaries — agents operating without
defined local authority constraints (drako-policy.yaml / .drako.yaml).

Category: "Operational"
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# Patterns indicating tool allowlisting / filtering
_TOOL_ALLOWLIST_PATTERNS = [
    "permitted_tools", "allowed_tools", "tool_whitelist", "tool_allowlist",
    "tools_allowed", "tool_filter", "restrict_tools", "approved_tools",
    "available_tools", "tool_access_control", "drako.guard", "build_host",
]

# Patterns indicating spend / cost / token caps
_SPEND_CAP_PATTERNS = [
    "max_tokens", "token_limit", "budget", "max_budget", "cost_limit",
    "max_cost", "spend_limit", "max_spend", "token_budget",
    "max_completion_tokens", "max_output_tokens",
]

# Patterns indicating time constraints
_TIME_CONSTRAINT_PATTERNS = [
    "timeout", "max_iterations", "max_steps", "time_limit",
    "max_execution_time", "deadline", "max_retries", "step_limit",
    "max_turns", "max_rounds", "iteration_limit", "loop_breaker",
    "LoopBreaker",
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


def _acs_profile_text(metadata: ProjectMetadata) -> str:
    """Return text of local drako-policy.yaml if present."""
    return metadata.config_files.get("drako-policy.yaml", "")


def _has_local_odd(metadata: ProjectMetadata) -> bool:
    """Return True if a local ACS policy profile or .drako.yaml boundary exists."""
    profile = _acs_profile_text(metadata)
    if profile and ("tools:" in profile or "default_effect:" in profile):
        return True
    cfg = _drako_config_text(metadata)
    return bool(cfg and ("kernel:" in cfg or "odd:" in cfg))


def _has_local_spend_cap(metadata: ProjectMetadata) -> bool:
    """Return True if .drako.yaml declares finops budgets or magnitude limits."""
    cfg = _drako_config_text(metadata)
    if not cfg:
        return False
    lower = cfg.lower()
    if "magnitude:" in lower:
        return True
    return "finops:" in lower and any(
        k in lower for k in ("budgets:", "daily_usd:", "weekly_usd:", "monthly_usd:")
    )


def _has_local_time_or_loop_bounds(metadata: ProjectMetadata) -> bool:
    """Return True if .drako.yaml declares loop_breaker or circuit_breaker."""
    cfg = _drako_config_text(metadata)
    if not cfg:
        return False
    lower = cfg.lower()
    return "loop_breaker:" in lower or "circuit_breaker:" in lower


def _agent_init_has_keyword(content: str, keywords: set[str]) -> bool:
    """Check if any Agent() constructor call has one of the given keyword args."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False

    from drako.cli.bom import _AGENT_CONSTRUCTORS

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in _AGENT_CONSTRUCTORS:
                for kw in node.keywords:
                    if kw.arg and kw.arg.lower() in keywords:
                        return True
    return False


# ---------------------------------------------------------------------------
# ODD-001: No operational boundary definition  (CRITICAL)
# ---------------------------------------------------------------------------

class ODD001(BasePolicy):
    policy_id = "ODD-001"
    category = "Operational"
    severity = "CRITICAL"
    title = "No operational boundary definition"
    impact = "Agents without declared operational boundaries can access any tool, spend any amount, and run indefinitely."
    attack_scenario = "Agent given broad tool access autonomously accesses production database and deletes records outside its intended scope."
    references = ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
    remediation_effort = "moderate"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        if _has_local_odd(metadata):
            return []

        agent_names = ", ".join(a.name for a in bom.agents[:5])
        count = len(bom.agents)
        suffix = f" (and {count - 5} more)" if count > 5 else ""

        return [self._finding(
            message=(
                f"No Operational Design Domain (ODD) defined for {count} agent(s): "
                f"{agent_names}{suffix}. Agents operate without declared boundaries. "
                f"Run `drako init` to generate a local ACS policy profile "
                f"(`drako-policy.yaml`) and `.drako.yaml` boundary configuration."
            ),
            fix_snippet=(
                "# Initialize local fail-closed boundaries:\n"
                "#   drako init\n"
                "# Or configure drako-policy.yaml directly:\n"
                "spec_pin: AGENT-HOOKS-0.1\n"
                "default_effect: deny\n"
                "tools:\n"
                "  search_docs:\n"
                "    id: tool:search_docs\n"
                "    effect: allow"
            ),
        )]


# ---------------------------------------------------------------------------
# ODD-002: Unrestricted tool access  (HIGH)
# ---------------------------------------------------------------------------

class ODD002(BasePolicy):
    policy_id = "ODD-002"
    category = "Operational"
    severity = "HIGH"
    title = "Unrestricted tool access"
    impact = "Without a tool allowlist, agents can use any registered tool \u2014 including dangerous ones outside their intended scope."
    attack_scenario = "Research agent intended only for web search also has access to delete_file tool. Prompt injection triggers file deletion."
    references = ["https://cwe.mitre.org/data/definitions/269.html"]
    remediation_effort = "trivial"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Only relevant if agents have tools
        agents_with_tools = [a for a in bom.agents if a.tools]
        if not agents_with_tools:
            return []

        profile = _acs_profile_text(metadata)
        if profile and "tools:" in profile and "default_effect: deny" in profile:
            return []

        cfg = _drako_config_text(metadata)
        if cfg and "permitted_tools" in cfg:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        if not all_content.strip():
            return []

        if _content_has_pattern(all_content, _TOOL_ALLOWLIST_PATTERNS):
            return []

        findings: list[Finding] = []
        for agent in agents_with_tools:
            tool_list = ", ".join(agent.tools[:5])
            suffix = f" (+{len(agent.tools) - 5} more)" if len(agent.tools) > 5 else ""
            findings.append(self._finding(
                message=(
                    f'Agent "{agent.name}" has {len(agent.tools)} tool(s) '
                    f"({tool_list}{suffix}) without a tool allowlist. "
                    f"Restrict access with `drako.guard(agent, allow=[...])` "
                    f"or a fail-closed `drako-policy.yaml` profile."
                ),
                file_path=agent.file_path,
                line_number=agent.line_number,
            ))

        return findings


# ---------------------------------------------------------------------------
# ODD-003: No spend cap  (HIGH)
# ---------------------------------------------------------------------------

class ODD003(BasePolicy):
    policy_id = "ODD-003"
    category = "Operational"
    severity = "HIGH"
    title = "No spend cap"
    impact = "Without token/cost limits, a single malfunctioning agent can exhaust the entire LLM budget in one session."
    attack_scenario = "Agent enters a reasoning loop, generating 500K tokens. Without spend cap, the session costs $2,000 before detection."
    references = ["https://cwe.mitre.org/data/definitions/770.html"]
    remediation_effort = "trivial"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        if _has_local_spend_cap(metadata):
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        if not all_content.strip():
            return []

        # Check globally for any spend-cap pattern
        if _content_has_pattern(all_content, _SPEND_CAP_PATTERNS):
            return []

        return [self._finding(
            message=(
                f"No spend cap detected across {len(bom.agents)} agent(s). "
                f"Without max_tokens, budget, or cost limits, agents can "
                f"consume unlimited resources. Configure spend budgets in "
                f"`.drako.yaml` (`finops.budgets`) or set `max_tokens` in code."
            ),
            fix_snippet=(
                "# Configure spend caps in .drako.yaml:\n"
                "finops:\n"
                "  budgets:\n"
                "    daily_usd: 25.00\n"
                "    monthly_usd: 500.00"
            ),
        )]


# ---------------------------------------------------------------------------
# ODD-004: No time constraints  (MEDIUM)
# ---------------------------------------------------------------------------

class ODD004(BasePolicy):
    policy_id = "ODD-004"
    category = "Operational"
    severity = "MEDIUM"
    title = "No time constraints"
    impact = "Agents without iteration/time limits can run indefinitely, consuming compute and blocking downstream workflows."
    attack_scenario = "Agent stuck in a retry loop runs for 8 hours overnight. Without max_iterations, nobody notices until morning."
    references = ["https://cwe.mitre.org/data/definitions/835.html"]
    remediation_effort = "trivial"
    finding_type = "recommendation"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        if _has_local_time_or_loop_bounds(metadata):
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        if not all_content.strip():
            return []

        if _content_has_pattern(all_content, _TIME_CONSTRAINT_PATTERNS):
            return []

        return [self._finding(
            message=(
                f"No time constraints detected across {len(bom.agents)} agent(s). "
                f"Without timeout, max_iterations, or loop bounds, agents can "
                f"run indefinitely. Configure `loop_breaker` or `circuit_breaker` "
                f"in `.drako.yaml`, or set `max_iterations` / `timeout` in code."
            ),
            fix_snippet=(
                "# Configure loop and time bounds in .drako.yaml:\n"
                "loop_breaker:\n"
                "  enabled: true\n"
                "  trip_threshold: 10\n"
                "  window_seconds: 300.0"
            ),
        )]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

OPERATIONAL_POLICIES: list[BasePolicy] = [
    ODD001(),
    ODD002(),
    ODD003(),
    ODD004(),
]
