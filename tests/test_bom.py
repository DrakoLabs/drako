"""Tests for the BOM (Bill of Materials) generation module."""
import pytest
from pathlib import Path

from drako.cli.discovery import collect_project_files, detect_frameworks
from drako.cli.bom import (
    generate_bom,
    _extract_agents_ast,
    _extract_tools_ast,
    _extract_models_ast,
    _extract_prompts_ast,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestExtractAgents:
    def test_crewai_agents(self):
        code = '''
from crewai import Agent
research = Agent(name="Researcher", role="Research", model="gpt-4")
writer = Agent(name="Writer", role="Writing")
'''
        agents = _extract_agents_ast("test.py", code)
        assert len(agents) >= 2
        names = [a.name for a in agents]
        assert "Researcher" in names
        assert "Writer" in names

    def test_autogen_agents(self):
        code = '''
from autogen import AssistantAgent, UserProxyAgent
assistant = AssistantAgent(name="Helper")
proxy = UserProxyAgent(name="User")
'''
        agents = _extract_agents_ast("test.py", code)
        assert len(agents) >= 2
        names = [a.name for a in agents]
        assert "Helper" in names

    def test_class_based_agent(self):
        code = '''
from crewai import Agent
class MyAgent(Agent):
    pass
'''
        agents = _extract_agents_ast("test.py", code)
        assert len(agents) >= 1
        assert agents[0].name == "MyAgent"

    def test_agent_with_model(self):
        code = '''
from crewai import Agent
agent = Agent(name="Test", model="gpt-4o")
'''
        agents = _extract_agents_ast("test.py", code)
        assert len(agents) >= 1
        assert agents[0].model == "gpt-4o"


class TestExtractTools:
    def test_decorated_tools(self):
        code = '''
from crewai_tools import tool

@tool
def search_web(query):
    import requests
    return requests.get(f"https://api.search.com/q={query}")

@tool
def read_file(path):
    with open(path) as f:
        return f.read()
'''
        tools = _extract_tools_ast("test.py", code)
        assert len(tools) >= 2
        names = [t.name for t in tools]
        assert "search_web" in names
        assert "read_file" in names

    def test_tool_filesystem_detection(self):
        code = '''
@tool
def write_data(path, data):
    with open(path, "w") as f:
        f.write(data)
'''
        tools = _extract_tools_ast("test.py", code)
        assert len(tools) >= 1
        assert tools[0].has_filesystem_access is True

    def test_tool_network_detection(self):
        code = '''
@tool
def fetch(url):
    import requests
    return requests.get(url)
'''
        tools = _extract_tools_ast("test.py", code)
        assert len(tools) >= 1
        assert tools[0].has_network_access is True

    def test_tool_code_exec_detection(self):
        code = '''
@tool
def run_code(code):
    exec(code)
'''
        tools = _extract_tools_ast("test.py", code)
        assert len(tools) >= 1
        assert tools[0].has_code_execution is True


class TestExtractModels:
    def test_model_strings(self):
        code = '''
model = "gpt-4o"
other_model = "claude-3-sonnet-20240229"
'''
        models = _extract_models_ast("test.py", code)
        names = [m.name for m in models]
        assert any("gpt-4o" in n for n in names)
        assert any("claude-3" in n for n in names)

    def test_no_false_positives(self):
        code = '''
name = "hello world"
version = "1.2.3"
'''
        models = _extract_models_ast("test.py", code)
        assert len(models) == 0


class TestExtractPrompts:
    def test_system_prompt_keyword(self):
        code = '''
agent = Agent(
    name="Test",
    system_prompt="You are a helpful research assistant that analyzes data carefully."
)
'''
        prompts = _extract_prompts_ast("test.py", code)
        assert len(prompts) >= 1

    def test_prompt_variable(self):
        code = '''
SYSTEM_PROMPT = "You are an AI assistant that helps with code review and analysis."
'''
        prompts = _extract_prompts_ast("test.py", code)
        assert len(prompts) >= 1


class TestGenerateBOM:
    def test_crewai_basic_bom(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)

        assert len(bom.agents) >= 2
        assert len(bom.tools) >= 2
        assert len(bom.models) >= 1
        assert "filesystem" in bom.permissions or "network" in bom.permissions

    def test_langgraph_clean_bom(self):
        metadata = collect_project_files(FIXTURES / "langgraph_clean")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)

        assert len(bom.frameworks) >= 1

    def test_autogen_bom(self):
        metadata = collect_project_files(FIXTURES / "autogen_vulnerable")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)

        assert len(bom.agents) >= 2
        assert len(bom.models) >= 1
