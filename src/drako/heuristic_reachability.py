"""HEURISTIC reachability analysis for agent tools (P1-6, 2026-09-04).

Honesty contract: this is string-matching + tools= list lookup, NOT dataflow
analysis. No CFG, no call-graph, no import resolution, no taint tracking.
False positives: name in comments/strings. False negatives: getattr/dynamic
registration. Do NOT use REACHABLE as a severity signal until call-graph or
taint analysis lands. Formerly `drako.reachability` (kept as deprecated shim).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class ReachabilityStatus(Enum):
    """Classification of tool reachability from agent entry points."""

    REACHABLE = "reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    UNREACHABLE = "unreachable"


@dataclass
class ToolReachability:
    """Reachability result for a single tool."""

    tool_name: str
    status: ReachabilityStatus
    referencing_agents: list[str] = field(default_factory=list)
    referencing_tasks: list[str] = field(default_factory=list)
    file_path: str | None = None
    line_number: int | None = None


def analyze_reachability(
    bom: AgentBOM,
    metadata: ProjectMetadata,
) -> list[ToolReachability]:
    """Analyze which tools are reachable from agents.

    Classification logic:
      - REACHABLE: tool appears in an agent's tools= list
      - POTENTIALLY_REACHABLE: tool name appears in source code strings
        near agent definitions but not in an explicit tools= list
      - UNREACHABLE: no agent references the tool

    Args:
        bom: Agent BOM with detected agents and tools.
        metadata: Project metadata with file contents.

    Returns:
        List of ToolReachability for each detected tool.
    """
    if not bom.tools:
        return []

    # Build agent-to-tools map from BOM
    agent_tools: dict[str, set[str]] = {}
    for agent in bom.agents:
        tools_set = set()
        for t in agent.tools:
            # Normalize: agent.tools may contain function names or strings
            tools_set.add(t.lower().strip())
        agent_tools[agent.name] = tools_set

    # Build a set of all tool names mentioned in source code (broader check)
    all_source = "\n".join(metadata.file_contents.values()).lower()

    # Check task assignments for CrewAI (look for Task(..., tools=[...]))
    task_tools: dict[str, set[str]] = {}
    _extract_task_tools(metadata, task_tools)

    results: list[ToolReachability] = []
    for tool in bom.tools:
        tool_name_lower = tool.name.lower().strip()

        # Check which agents explicitly list this tool
        refs_agents: list[str] = []
        for agent_name, tools_set in agent_tools.items():
            if tool_name_lower in tools_set:
                refs_agents.append(agent_name)

        # Check which tasks reference this tool
        refs_tasks: list[str] = []
        for task_name, tools_set in task_tools.items():
            if tool_name_lower in tools_set:
                refs_tasks.append(task_name)

        if refs_agents:
            status = ReachabilityStatus.REACHABLE
        elif tool_name_lower in all_source:
            # Tool name appears somewhere in source but not in agent tools= list
            status = ReachabilityStatus.POTENTIALLY_REACHABLE
        else:
            status = ReachabilityStatus.UNREACHABLE

        results.append(ToolReachability(
            tool_name=tool.name,
            status=status,
            referencing_agents=refs_agents,
            referencing_tasks=refs_tasks,
            file_path=tool.file_path,
            line_number=tool.line_number,
        ))

    return results


def _extract_task_tools(
    metadata: ProjectMetadata,
    task_tools: dict[str, set[str]],
) -> None:
    """Extract tool assignments from Task() constructors in source code.

    Supports CrewAI Task(description=..., tools=[tool1, tool2]) pattern.
    """
    import ast

    for rel_path, content in metadata.file_contents.items():
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Check if this is a Task() call
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name != "Task":
                continue

            # Extract task description (for naming)
            task_name = f"task_{rel_path}:{getattr(node, 'lineno', '?')}"
            for kw in node.keywords:
                if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                    desc = str(kw.value.value)[:40]
                    task_name = desc

            # Extract tools list
            for kw in node.keywords:
                if kw.arg == "tools" and isinstance(kw.value, ast.List):
                    tools_set: set[str] = set()
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Name):
                            tools_set.add(elt.id.lower())
                        elif isinstance(elt, ast.Attribute):
                            tools_set.add(elt.attr.lower())
                    if tools_set:
                        task_tools[task_name] = tools_set
