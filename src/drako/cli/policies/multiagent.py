"""Multi-Agent Topology and Resilience policy rules (MULTI-001 through MULTI-004).

MULTI-001: Multi-agent system without topology monitoring
MULTI-002: Circular agent dependency detected
MULTI-003: Shared resource without contention protection
MULTI-004: No resilience / benchmark testing configured
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
    r"drako.*topology|observability|worm_detection|a2a:\s*\n\s*mode:\s*enforce)",
    re.IGNORECASE,
)


class MULTI001(BasePolicy):
    policy_id = "MULTI-001"
    category = "Operational"
    severity = "HIGH"
    title = "Multi-agent system without topology monitoring"
    impact = "Unmonitored multi-agent systems hide cascading failures, conflicts, and circular dependencies until production incidents."
    attack_scenario = "Two agents write conflicting data to the same resource. Without topology monitoring, the corruption goes undetected."
    references = ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
    remediation_effort = "moderate"

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

        return [self._finding(
            message=(
                f"Multi-agent system with {len(bom.agents)} agents has no "
                f"inter-agent channel governance or observability configured. "
                f"Cannot detect conflicts, cascading failures, or circular dependencies."
            ),
            fix_snippet=(
                "# Configure A2A channels and worm/loop detection in .drako.yaml:\n"
                "a2a:\n"
                "  mode: enforce\n"
                "  require_signed_cards: true\n"
                "  channels:\n"
                "    - from: researcher\n"
                "      to: writer\n"
                "      allowed_message_types: [task_result]\n"
                "  worm_detection:\n"
                "    enabled: true\n"
                "    max_propagation_depth: 3\n"
                "    circular_reference_block: true"
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
    impact = "Circular delegation between agents causes infinite loops, resource exhaustion, and amplification of prompt injections."
    attack_scenario = "Agent A delegates to B, B delegates back to A. The loop amplifies a prompt injection across the entire agent fleet."
    references = ["https://cwe.mitre.org/data/definitions/835.html"]
    remediation_effort = "significant"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        # Build dependency graph from AST: who calls/delegates to whom
        agent_names = {a.name.lower() for a in bom.agents}
        adjacency: dict[str, set[str]] = defaultdict(set)

        # Constructors that group agents (not delegation)
        _constructor_names = {"Crew", "Task", "Agent", "Pipeline", "GroupChat",
                              "RoundRobinGroupChat", "SelectorGroupChat"}

        for rel_path, content in metadata.file_contents.items():
            if not rel_path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Skip constructor calls — agents in same Crew/Task is not delegation
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    if func_name in _constructor_names:
                        continue

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
            findings.append(self._finding(
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
    impact = "Multiple agents writing to shared resources without locking causes data corruption, lost updates, and race conditions."
    attack_scenario = "Two agents simultaneously update the same database record. Without contention protection, one update silently overwrites the other."
    references = ["https://cwe.mitre.org/data/definitions/362.html"]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if len(bom.agents) < 2:
            return []

        # Cross-reference tool usage per agent
        tool_to_agents: dict[str, list[str]] = defaultdict(list)
        for agent in bom.agents:
            for tool_name in getattr(agent, "tools", []):
                tool_to_agents[tool_name].append(agent.name)

        _WRITE_NAME_PATTERNS = {
            "write", "update", "delete", "create", "insert", "remove",
            "send", "transfer", "deploy", "execute", "payment", "submit",
        }

        findings = []
        for tool_name, agents in tool_to_agents.items():
            if len(agents) < 2:
                continue
            # Check if the tool is write-type via capabilities or name heuristics
            tool_obj = next((t for t in bom.tools if t.name == tool_name), None)
            is_write = False
            if tool_obj:
                is_write = (
                    getattr(tool_obj, "has_filesystem_access", False)
                    or getattr(tool_obj, "has_network_access", False)
                    or getattr(tool_obj, "has_code_execution", False)
                )
            if not is_write:
                is_write = any(pat in tool_name.lower() for pat in _WRITE_NAME_PATTERNS)
            if is_write:
                findings.append(self._finding(
                    message=(
                        f"Write tool '{tool_name}' is used by multiple agents: "
                        f"{', '.join(agents)}. Without contention protection, "
                        f"concurrent writes can cause data corruption."
                    ),
                    fix_snippet=(
                        "# Isolate shared write tools with explicit A2A channels and loop protection:\n"
                        "a2a:\n"
                        "  mode: enforce\n"
                        "  channels:\n"
                        "    - from: writer_agent\n"
                        "      to: reviewer_agent\n"
                        "      allowed_message_types: [write_request]\n"
                        "loop_breaker:\n"
                        "  enabled: true\n"
                        "  trip_threshold: 10"
                    ),
                ))
        return findings


# ---------------------------------------------------------------------------
# MULTI-004: No chaos testing configured
# ---------------------------------------------------------------------------

_CHAOS_PATTERNS = re.compile(
    r"(?:chaos|fault.inject|resilience.test|"
    r"circuit.breaker.test|failure.inject|"
    r"drako.*chaos|chaos_experiment|kernel.*bench|loop_breaker)",
    re.IGNORECASE,
)


class MULTI004(BasePolicy):
    policy_id = "MULTI-004"
    category = "Operational"
    severity = "MEDIUM"
    title = "No chaos testing configured"
    impact = "Without chaos testing, governance controls (circuit breakers, fallbacks, HITL) are untested and may fail when needed."
    attack_scenario = "Circuit breaker is configured but never tested. In production, it fails to trip during an outage, causing cascading failure."
    references = ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
    remediation_effort = "moderate"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        all_config = "\n".join(metadata.config_files.values())
        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )
        combined = all_content + "\n" + all_config

        if _CHAOS_PATTERNS.search(combined):
            return []

        return [self._finding(
            message=(
                "No resilience or stress testing detected. Verify governance "
                "controls (loop breaker, fallbacks, authority checks) offline "
                "using `drako kernel bench` and `loop_breaker:` in `.drako.yaml`."
            ),
            fix_snippet=(
                "# Run offline adversarial/latency stress tests:\n"
                "#   drako kernel bench --iterations 500\n"
                "# Configure loop_breaker and fallback in .drako.yaml:\n"
                "loop_breaker:\n"
                "  enabled: true\n"
                "  trip_threshold: 10\n"
                "  window_seconds: 300.0\n"
                "fallback:\n"
                "  mode: enforce"
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
