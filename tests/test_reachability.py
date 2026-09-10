"""Tests for the heuristic reachability analysis module (P1-6)."""

from __future__ import annotations

import warnings
from pathlib import Path

from drako.heuristic_reachability import (
    ReachabilityStatus,
    ToolReachability,
    analyze_reachability,
)
from drako.cli.bom import AgentBOM, DetectedAgent, DetectedTool, DetectedModel, DetectedPrompt
from drako.cli.discovery import ProjectMetadata, FrameworkInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_metadata(files: dict[str, str] | None = None) -> ProjectMetadata:
    return ProjectMetadata(
        root=Path("/fake"),
        python_files=[],
        config_files={},
        file_contents=files or {},
        dependencies={},
        frameworks=[],
    )


def _make_bom(
    agents: list[DetectedAgent] | None = None,
    tools: list[DetectedTool] | None = None,
) -> AgentBOM:
    return AgentBOM(
        agents=agents or [],
        tools=tools or [],
        models=[],
        mcp_servers=[],
        prompts=[],
        permissions=[],
        frameworks=[],
        dependencies={},
    )


def _agent(name: str, tools: list[str]) -> DetectedAgent:
    return DetectedAgent(
        name=name,
        class_name="Agent",
        file_path="agents.py",
        line_number=1,
        framework="crewai",
        tools=tools,
        model="gpt-4",
    )


def _tool(name: str) -> DetectedTool:
    return DetectedTool(
        name=name,
        file_path="tools.py",
        line_number=1,
        has_filesystem_access=False,
        has_network_access=False,
        has_code_execution=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestReachabilityAnalysis:
    def test_tool_in_agent_tools_is_reachable(self):
        bom = _make_bom(
            agents=[_agent("researcher", ["search_tool"])],
            tools=[_tool("search_tool")],
        )
        metadata = _make_metadata()
        results = analyze_reachability(bom, metadata)

        assert len(results) == 1
        assert results[0].status == ReachabilityStatus.REACHABLE
        assert "researcher" in results[0].referencing_agents

    def test_tool_not_in_any_agent_is_unreachable(self):
        bom = _make_bom(
            agents=[_agent("researcher", ["other_tool"])],
            tools=[_tool("unused_tool")],
        )
        metadata = _make_metadata()
        results = analyze_reachability(bom, metadata)

        assert len(results) == 1
        assert results[0].status == ReachabilityStatus.UNREACHABLE

    def test_tool_mentioned_in_source_is_potentially_reachable(self):
        bom = _make_bom(
            agents=[_agent("researcher", ["other_tool"])],
            tools=[_tool("search_web")],
        )
        # Tool name appears in source but not in agent.tools
        metadata = _make_metadata({"main.py": "# TODO: add search_web to agent"})
        results = analyze_reachability(bom, metadata)

        assert len(results) == 1
        assert results[0].status == ReachabilityStatus.POTENTIALLY_REACHABLE

    def test_empty_project_returns_empty(self):
        bom = _make_bom()
        metadata = _make_metadata()
        results = analyze_reachability(bom, metadata)
        assert results == []

    def test_multiple_tools_classified_correctly(self):
        bom = _make_bom(
            agents=[_agent("researcher", ["tool_a"])],
            tools=[_tool("tool_a"), _tool("tool_b"), _tool("tool_c")],
        )
        metadata = _make_metadata()
        results = analyze_reachability(bom, metadata)

        statuses = {r.tool_name: r.status for r in results}
        assert statuses["tool_a"] == ReachabilityStatus.REACHABLE
        assert statuses["tool_b"] == ReachabilityStatus.UNREACHABLE
        assert statuses["tool_c"] == ReachabilityStatus.UNREACHABLE

    def test_tool_reachable_from_multiple_agents(self):
        bom = _make_bom(
            agents=[
                _agent("researcher", ["search"]),
                _agent("analyst", ["search"]),
            ],
            tools=[_tool("search")],
        )
        metadata = _make_metadata()
        results = analyze_reachability(bom, metadata)

        assert len(results) == 1
        assert results[0].status == ReachabilityStatus.REACHABLE
        assert len(results[0].referencing_agents) == 2

    def test_task_tools_detection(self):
        bom = _make_bom(
            agents=[_agent("researcher", ["my_tool"])],
            tools=[_tool("my_tool")],
        )
        source = '''
from crewai import Task
task = Task(description="Research", tools=[my_tool])
'''
        metadata = _make_metadata({"tasks.py": source})
        results = analyze_reachability(bom, metadata)

        assert len(results) == 1
        assert results[0].status == ReachabilityStatus.REACHABLE


def test_deprecated_shim_still_works_with_warning():
    """P1-6: old import path keeps working (no breakage) but warns."""
    import importlib

    import drako.reachability as shim

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        importlib.reload(shim)  # re-execute to capture the import-time warning
    assert shim.analyze_reachability is analyze_reachability
    assert shim.ReachabilityStatus is ReachabilityStatus
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
