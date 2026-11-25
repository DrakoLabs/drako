"""Unit tests for framework-specific governance rules (FW-* policies).

Tests each rule class directly with synthetic metadata, verifying:
1. Rule fires on vulnerable patterns
2. Rule is silent on safe patterns
3. Rule is skipped when framework is not detected
4. Scoring regression: existing findings produce identical scores
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drako.cli.bom import AgentBOM, generate_bom
from drako.cli.discovery import FrameworkInfo, ProjectMetadata
from drako.cli.policies.base import Finding
from drako.cli.policies.frameworks.autogen import (
    FW_AUTOGEN_001,
    FW_AUTOGEN_002,
)
from drako.cli.policies.frameworks.crewai import (
    FW_CREWAI_001,
    FW_CREWAI_002,
    FW_CREWAI_003,
)
from drako.cli.policies.frameworks.langgraph import (
    FW_LANGGRAPH_001,
    FW_LANGGRAPH_002,
)
from drako.cli.policies.frameworks.pydantic_ai import FW_PYDANTIC_001
from drako.cli.policies.frameworks.semantic_kernel import (
    FW_SK_001,
    FW_SK_002,
)
from drako.cli.scoring import calculate_score

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_metadata(
    files: dict[str, str],
    frameworks: list[FrameworkInfo] | None = None,
    dependencies: dict[str, str | None] | None = None,
) -> tuple[ProjectMetadata, AgentBOM]:
    """Create metadata + BOM from inline file contents."""
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = frameworks or []
    metadata.dependencies = dependencies or {}
    bom = generate_bom(metadata)
    bom.frameworks = metadata.frameworks
    return metadata, bom


_CREWAI_FW = [FrameworkInfo(name="crewai", version="0.40.0", confidence=0.9)]
_LANGGRAPH_FW = [FrameworkInfo(name="langgraph", version="0.2.0", confidence=0.9)]
_AUTOGEN_FW = [FrameworkInfo(name="autogen", version="0.2.0", confidence=0.9)]
_SK_FW = [FrameworkInfo(name="semantic_kernel", version="1.0.0", confidence=0.9)]
_PYDANTIC_AI_FW = [FrameworkInfo(name="pydantic_ai", version="0.0.10", confidence=0.9)]


# ---------------------------------------------------------------------------
# Framework rule skip test
# ---------------------------------------------------------------------------

class TestFrameworkSkip:
    """Rules must return [] when framework is not detected."""

    @pytest.mark.parametrize("rule_cls", [
        FW_CREWAI_001, FW_CREWAI_002, FW_CREWAI_003,
        FW_LANGGRAPH_001, FW_LANGGRAPH_002,
        FW_AUTOGEN_001, FW_AUTOGEN_002,
        FW_SK_001, FW_SK_002,
        FW_PYDANTIC_001,
    ])
    def test_skips_when_framework_absent(self, rule_cls):
        rule = rule_cls()
        metadata, bom = _make_metadata(
            {"main.py": "x = 1\n"},
            frameworks=[],
        )
        assert rule.evaluate(bom, metadata) == []


# ---------------------------------------------------------------------------
# FW-CREWAI-001
# ---------------------------------------------------------------------------

class TestFWCrewAI001:
    def test_fires_on_allow_code_execution_true(self):
        code = '''
from crewai import Agent
agent = Agent(
    role="coder",
    allow_code_execution=True,
)
'''
        rule = FW_CREWAI_001()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_silent_when_sandbox_keyword_present(self):
        code = '''
from crewai import Agent
agent = Agent(
    role="coder",
    allow_code_execution=True,
    code_execution_mode="docker",
)
'''
        rule = FW_CREWAI_001()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 0

    def test_silent_when_code_execution_false(self):
        code = '''
from crewai import Agent
agent = Agent(role="researcher", allow_code_execution=False)
'''
        rule = FW_CREWAI_001()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-CREWAI-002
# ---------------------------------------------------------------------------

class TestFWCrewAI002:
    def test_fires_on_shared_memory(self):
        code = '''
from crewai import Agent, Crew
a1 = Agent(role="researcher", goal="r", backstory="b")
a2 = Agent(role="writer", goal="w", backstory="b")
crew = Crew(agents=[a1, a2], memory=True)
'''
        rule = FW_CREWAI_002()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_memory_config(self):
        code = '''
from crewai import Agent, Crew
from crewai.memory import ShortTermMemory
a1 = Agent(role="researcher", goal="r", backstory="b")
a2 = Agent(role="writer", goal="w", backstory="b")
crew = Crew(agents=[a1, a2], memory=True, memory_config={"short_term": ShortTermMemory()})
'''
        rule = FW_CREWAI_002()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-CREWAI-003
# ---------------------------------------------------------------------------

class TestFWCrewAI003:
    def test_fires_on_delegation_without_tool_boundary(self):
        code = '''
from crewai import Agent
a1 = Agent(role="boss", allow_delegation=True, tools=[search])
a2 = Agent(role="worker", goal="work")
'''
        rule = FW_CREWAI_003()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_when_all_agents_have_tools(self):
        code = '''
from crewai import Agent
a1 = Agent(role="boss", allow_delegation=True, tools=[search])
a2 = Agent(role="worker", tools=[write_tool])
'''
        rule = FW_CREWAI_003()
        meta, bom = _make_metadata({"main.py": code}, _CREWAI_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-LANGGRAPH-001
# ---------------------------------------------------------------------------

class TestFWLangGraph001:
    def test_fires_on_toolnode_without_human_gate(self):
        code = '''
from langgraph.prebuilt import ToolNode
from langgraph.graph import StateGraph
tools = ToolNode([search])
graph = StateGraph()
app = graph.compile()
'''
        rule = FW_LANGGRAPH_001()
        meta, bom = _make_metadata({"main.py": code}, _LANGGRAPH_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_interrupt_before(self):
        code = '''
from langgraph.prebuilt import ToolNode
from langgraph.graph import StateGraph
tools = ToolNode([search])
graph = StateGraph()
app = graph.compile(interrupt_before=["tools"])
'''
        rule = FW_LANGGRAPH_001()
        meta, bom = _make_metadata({"main.py": code}, _LANGGRAPH_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-LANGGRAPH-002
# ---------------------------------------------------------------------------

class TestFWLangGraph002:
    def test_fires_on_destructive_tools_without_checkpointer(self):
        code = '''
from langchain_core.tools import tool
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

@tool
def delete_file(path: str) -> str:
    return "deleted"

graph = StateGraph()
tool_node = ToolNode([delete_file])
app = graph.compile()
'''
        rule = FW_LANGGRAPH_002()
        meta, bom = _make_metadata({"main.py": code}, _LANGGRAPH_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_checkpointer(self):
        code = '''
from langchain_core.tools import tool
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

@tool
def delete_file(path: str) -> str:
    return "deleted"

graph = StateGraph()
tool_node = ToolNode([delete_file])
app = graph.compile(checkpointer=MemorySaver())
'''
        rule = FW_LANGGRAPH_002()
        meta, bom = _make_metadata({"main.py": code}, _LANGGRAPH_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-AUTOGEN-001
# ---------------------------------------------------------------------------

class TestFWAutoGen001:
    def test_fires_on_local_executor(self):
        code = '''
from autogen.coding import LocalCommandLineCodeExecutor
executor = LocalCommandLineCodeExecutor(work_dir="./output")
'''
        rule = FW_AUTOGEN_001()
        meta, bom = _make_metadata({"main.py": code}, _AUTOGEN_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_silent_with_docker_executor(self):
        code = '''
from autogen.coding import DockerCommandLineCodeExecutor
executor = DockerCommandLineCodeExecutor(image="python:3.12-slim")
'''
        rule = FW_AUTOGEN_001()
        meta, bom = _make_metadata({"main.py": code}, _AUTOGEN_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-AUTOGEN-002
# ---------------------------------------------------------------------------

class TestFWAutoGen002:
    def test_fires_on_groupchat_without_validation(self):
        code = '''
from autogen import AssistantAgent, GroupChat
a1 = AssistantAgent(name="a1")
a2 = AssistantAgent(name="a2")
chat = GroupChat(agents=[a1, a2], messages=[])
'''
        rule = FW_AUTOGEN_002()
        meta, bom = _make_metadata({"main.py": code}, _AUTOGEN_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_register_reply(self):
        code = '''
from autogen import AssistantAgent, GroupChat
a1 = AssistantAgent(name="a1")
a2 = AssistantAgent(name="a2")
a1.register_reply([AssistantAgent], validate_fn)
chat = GroupChat(agents=[a1, a2], messages=[])
'''
        rule = FW_AUTOGEN_002()
        meta, bom = _make_metadata({"main.py": code}, _AUTOGEN_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-SK-001
# ---------------------------------------------------------------------------

class TestFWSK001:
    def test_fires_on_bulk_plugin_import(self):
        code = '''
from semantic_kernel import Kernel
kernel = Kernel()
kernel.import_plugin_from_module("my_module")
'''
        rule = FW_SK_001()
        meta, bom = _make_metadata({"main.py": code}, _SK_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_function_filtering(self):
        code = '''
from semantic_kernel import Kernel
kernel = Kernel()
kernel.add_plugin(plugin=my_plugin, plugin_name="safe", functions=["read_only"])
'''
        rule = FW_SK_001()
        meta, bom = _make_metadata({"main.py": code}, _SK_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-SK-002
# ---------------------------------------------------------------------------

class TestFWSK002:
    def test_fires_on_planner_without_cost_guard(self):
        code = '''
from semantic_kernel.planners import SequentialPlanner
planner = SequentialPlanner(kernel=kernel)
'''
        rule = FW_SK_002()
        meta, bom = _make_metadata({"main.py": code}, _SK_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_max_steps(self):
        code = '''
from semantic_kernel.planners import SequentialPlanner
planner = SequentialPlanner(kernel=kernel, max_steps=10)
'''
        rule = FW_SK_002()
        meta, bom = _make_metadata({"main.py": code}, _SK_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# FW-PYDANTIC-001
# ---------------------------------------------------------------------------

class TestFWPydanticAI001:
    def test_fires_on_untyped_tool_return(self):
        code = '''
from pydantic_ai import Agent
my_agent = Agent("openai:gpt-4o")

@my_agent.tool
def search(query: str) -> dict:
    return {"result": query}
'''
        rule = FW_PYDANTIC_001()
        meta, bom = _make_metadata({"main.py": code}, _PYDANTIC_AI_FW)
        findings = rule.evaluate(bom, meta)
        assert len(findings) == 1

    def test_silent_with_pydantic_model_return(self):
        code = '''
from pydantic import BaseModel
from pydantic_ai import Agent

class SearchResult(BaseModel):
    data: str

my_agent = Agent("openai:gpt-4o")

@my_agent.tool
def search(query: str) -> SearchResult:
    return SearchResult(data=query)
'''
        rule = FW_PYDANTIC_001()
        meta, bom = _make_metadata({"main.py": code}, _PYDANTIC_AI_FW)
        assert rule.evaluate(bom, meta) == []


# ---------------------------------------------------------------------------
# Scoring regression
# ---------------------------------------------------------------------------

class TestScoringRegression:
    """Ensure the category cap does not change existing non-Framework scores."""

    def test_existing_findings_score_unchanged(self):
        """Pure Security/Governance findings should score identically."""
        findings = [
            Finding(policy_id="SEC-001", category="Security", severity="CRITICAL",
                    title="test", message="test"),
            Finding(policy_id="GOV-001", category="Governance", severity="HIGH",
                    title="test", message="test"),
            Finding(policy_id="SEC-002", category="Security", severity="CRITICAL",
                    title="test", message="test"),
        ]
        score = calculate_score(findings)
        # 100 - 10 - 10 - 5 = 75
        assert score == 75

    def test_framework_cap_at_30(self):
        """Framework findings should not exceed -30 deduction."""
        findings = [
            Finding(policy_id="FW-CREWAI-001", category="Framework", severity="CRITICAL",
                    title="t", message="m"),
            Finding(policy_id="FW-AUTOGEN-001", category="Framework", severity="CRITICAL",
                    title="t", message="m"),
            Finding(policy_id="FW-CREWAI-002", category="Framework", severity="CRITICAL",
                    title="t", message="m"),
            Finding(policy_id="FW-CREWAI-003", category="Framework", severity="CRITICAL",
                    title="t", message="m"),
        ]
        score = calculate_score(findings)
        # Without cap: 40 deduction -> 60; with Framework cap (-30) -> 70
        assert score == 70

    def test_mixed_framework_and_security(self):
        """Mix of Framework and non-Framework findings."""
        findings = [
            Finding(policy_id="SEC-001", category="Security", severity="CRITICAL",
                    title="t", message="m"),
            Finding(policy_id="FW-CREWAI-001", category="Framework", severity="CRITICAL",
                    title="t", message="m"),
            Finding(policy_id="FW-AUTOGEN-001", category="Framework", severity="CRITICAL",
                    title="t", message="m"),
        ]
        score = calculate_score(findings)
        # Security: 10 deduction; Framework: min(10+10=20, 30) = 20 -> 100 - 30 = 70
        assert score == 70
