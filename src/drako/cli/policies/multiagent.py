"""Multi-Agent Topology policy rules — Sprint 5.

MULTI-001: Multi-agent system without topology monitoring
MULTI-002: Circular agent dependency detected
MULTI-003: Shared resource without contention protection
MULTI-004: No chaos testing configured
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


# ---------------------------------------------------------------------------
# MULTI-001: Multi-agent system without topology monitoring
# ---------------------------------------------------------------------------

_TOPOLOGY_PATTERNS = re.compile(
    r"(?:topology|agent.*monitor|fleet.*health|"
    r"agent.*graph|communication.*graph|"
    r"drako.*topology|observability)",
    re.IGNORECASE,
)


class MULTI001(BasePolicy):
    policy_id = "MULTI-001"
    category = "Operational"
    severity = "HIGH"
    title = "Multi-agent system without topology monitoring"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        all_config = "\n".join(metadata.config_files.values())
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        combined = all_content + "\n" + all_config

        if _TOPOLOGY_PATTERNS.search(combined):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"Multi-agent system with {len(bom.agents)} agents has no "
                f"topology monitoring or observability configured. Cannot "
                f"detect conflicts, cascading failures, or circular dependencies."
            ),
            fix_snippet=(
                "# Add topology monitoring in .drako.yaml:\n"
                "topology:\n"
                "  enabled: true\n"
                "  conflict_detection:\n"
                "    resource_contention: true\n"
                "    contradictory_actions: true\n"
                "    cascade_amplification: true\n"
                "  alert_on:\n"
                "    - circular_dependency\n"
                "    - resource_contention"
            ),
        )]


# ---------------------------------------------------------------------------
# MULTI-002: Circular agent dependency detected
# ---------------------------------------------------------------------------

_DELEGATION_PATTERNS = re.compile(
    r"(?:delegate|handoff|forward|send_to|pass_to|invoke_agent|"
    r"call_agent|agent\.run|execute_agent)",
    re.IGNORECASE,
)


class MULTI002(BasePolicy):
    policy_id = "MULTI-002"
    category = "Security"
    severity = "CRITICAL"
    title = "Circular agent dependency detected"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        # Build dependency graph from AST: who calls/delegates to whom
        agent_names = {a.name.lower() for a in bom.agents}
        adjacency: dict[str, set[str]] = defaultdict(set)

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_str = ast.dump(node)
                    for name_a in agent_names:
                        if name_a in call_str.lower():
                            for name_b in agent_names:
                                if name_b != name_a and name_b in call_str.lower():
                                    adjacency[name_a].add(name_b)

        # DFS cycle detection
        visited: set[str] = set()
        rec_stack: set[str] = set()
        cycles: list[list[str]] = []

        def dfs(node: str, path: list[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            for neighbor in adjacency.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor, path + [neighbor])
                elif neighbor in rec_stack:
                    idx = path.index(neighbor) if neighbor in path else 0
                    cycles.append(path[idx:] + [neighbor])
            rec_stack.discard(node)

        for node in list(adjacency.keys()):
            if node not in visited:
                dfs(node, [node])

        findings = []
        seen: set[str] = set()
        for cycle in cycles:
            key = "->".join(sorted(set(cycle)))
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f"Circular dependency: {'->'.join(cycle)}. "
                    f"This can cause infinite loops, resource exhaustion, "
                    f"or cascade amplification in multi-agent systems."
                ),
                fix_snippet=(
                    "# Break circular dependencies by:\n"
                    "# 1. Using unidirectional data flows\n"
                    "# 2. Adding a coordinator/orchestrator agent\n"
                    "# 3. Setting max_propagation_depth in A2A config:\n"
                    "a2a:\n"
                    "  worm_detection:\n"
                    "    max_propagation_depth: 3\n"
                    "    circular_reference_block: true"
                ),
            ))
        return findings


# ---------------------------------------------------------------------------
# MULTI-003: Shared resource without contention protection
# ---------------------------------------------------------------------------

class MULTI003(BasePolicy):
    policy_id = "MULTI-003"
    category = "Operational"
    severity = "HIGH"
    title = "Shared resource without contention protection"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        # Cross-reference tool usage per agent
        tool_to_agents: dict[str, list[str]] = defaultdict(list)
        for agent in bom.agents:
            for tool_name in getattr(agent, "tools", []):
                tool_to_agents[tool_name].append(agent.name)

        findings = []
        for tool_name, agents in tool_to_agents.items():
            if len(agents) < 2:
                continue
            # Check if the tool is write-type
            tool_obj = next((t for t in bom.tools if t.name == tool_name), None)
            if tool_obj and getattr(tool_obj, "tool_type", "read") in ("write", "execute", "payment"):
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Write tool '{tool_name}' is used by multiple agents: "
                        f"{', '.join(agents)}. Without contention protection, "
                        f"concurrent writes can cause data corruption."
                    ),
                    fix_snippet=(
                        "# Enable resource contention detection:\n"
                        "topology:\n"
                        "  enabled: true\n"
                        "  conflict_detection:\n"
                        "    resource_contention: true"
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# MULTI-004: No chaos testing configured
# ---------------------------------------------------------------------------

_CHAOS_PATTERNS = re.compile(
    r"(?:chaos|fault.inject|resilience.test|"
    r"circuit.breaker.test|failure.inject|"
    r"drako.*chaos|chaos_experiment)",
    re.IGNORECASE,
)


class MULTI004(BasePolicy):
    policy_id = "MULTI-004"
    category = "Operational"
    severity = "MEDIUM"
    title = "No chaos testing configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_config = "\n".join(metadata.config_files.values())
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        combined = all_content + "\n" + all_config

        if _CHAOS_PATTERNS.search(combined):
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                "No resilience or chaos testing detected. Without chaos "
                "engineering, you cannot verify that governance controls "
                "(circuit breakers, fallbacks, HITL) actually work under stress."
            ),
            fix_snippet=(
                "# Add chaos engineering in .drako.yaml:\n"
                "chaos:\n"
                "  experiments:\n"
                "    - name: db-tool-failure\n"
                "      description: Test resilience when database tool fails\n"
                "      target_tool: database_query\n"
                "      fault_type: tool_deny\n"
                "      duration_seconds: 60\n"
                "  safety:\n"
                "    max_blast_radius: 1\n"
                "    auto_rollback_on_failure: true\n"
                "    require_approval: true"
            ),
        )]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

MULTIAGENT_POLICIES: list[BasePolicy] = [
    MULTI001(),
    MULTI002(),
    MULTI003(),
    MULTI004(),
]
