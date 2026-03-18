"""Operational Design Domain (ODD) policy rules (ODD-001 through ODD-004).

Detects the ABSENCE of operational boundaries — agents operating without
defined constraints. These rules always fire in offline scan because ODD
enforcement requires the Drako platform (PRO tier).

Category: "Operational"
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# Patterns indicating tool allowlisting / filtering
_TOOL_ALLOWLIST_PATTERNS = [
    "permitted_tools", "allowed_tools", "tool_whitelist", "tool_allowlist",
    "tools_allowed", "tool_filter", "restrict_tools", "approved_tools",
    "available_tools", "tool_access_control",
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
    "max_turns", "max_rounds", "iteration_limit",
]


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    """Check if any pattern exists in the combined content."""
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


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

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # ODD requires the Drako platform — offline scan ALWAYS fires
        # because there is no way to define/verify ODD without the SaaS.
        if not bom.agents:
            return []

        agent_names = ", ".join(a.name for a in bom.agents[:5])
        count = len(bom.agents)
        suffix = f" (and {count - 5} more)" if count > 5 else ""

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No Operational Design Domain (ODD) defined for {count} agent(s): "
                f"{agent_names}{suffix}. Agents operate without declared boundaries. "
                f"Define permitted tools, spend limits, and operational constraints "
                f"via the Drako dashboard (requires Pro plan)."
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

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        # Only relevant if agents have tools
        agents_with_tools = [a for a in bom.agents if a.tools]
        if not agents_with_tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _TOOL_ALLOWLIST_PATTERNS):
            return []

        findings: list[Finding] = []
        for agent in agents_with_tools:
            tool_list = ", ".join(agent.tools[:5])
            suffix = f" (+{len(agent.tools) - 5} more)" if len(agent.tools) > 5 else ""
            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f'Agent "{agent.name}" has {len(agent.tools)} tool(s) '
                    f"({tool_list}{suffix}) without a tool allowlist. "
                    f"Define permitted_tools in an ODD to restrict access."
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

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        # Check globally for any spend-cap pattern
        if _content_has_pattern(all_content, _SPEND_CAP_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No spend cap detected across {len(bom.agents)} agent(s). "
                f"Without max_tokens, budget, or cost limits, agents can "
                f"consume unlimited resources. Define magnitude limits "
                f"via the Drako dashboard (requires Pro plan)."
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

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if _content_has_pattern(all_content, _TIME_CONSTRAINT_PATTERNS):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No time constraints detected across {len(bom.agents)} agent(s). "
                f"Without timeout, max_iterations, or step limits, agents can "
                f"run indefinitely. Define operational time bounds "
                f"via the Drako dashboard (requires Pro plan)."
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
