"""Tests for best practices policy rules (BP-001 through BP-005)."""
import pytest
from pathlib import Path

from drako.cli.discovery import collect_project_files, detect_frameworks, ProjectMetadata, FrameworkInfo
from drako.cli.bom import generate_bom, AgentBOM, DetectedAgent
from drako.cli.policies.bestpractices import (
    BP001, BP002, BP003, BP004, BP005,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_metadata(files: dict[str, str]) -> tuple[ProjectMetadata, AgentBOM]:
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = []
    metadata.dependencies = {}
    bom = generate_bom(metadata)
    return metadata, bom


class TestBP002:
    """No tests for agents."""

    def test_no_test_files(self):
        files = {"main.py": 'from crewai import Agent\nagent = Agent(name="Test")\n'}
        metadata, bom = _make_metadata(files)
        findings = BP002().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "BP-002"

    def test_has_test_files(self):
        files = {
            "main.py": 'from crewai import Agent\nagent = Agent(name="TestAgent")\n',
            "tests/test_agents.py": 'def test_testagent():\n    assert True\n',
        }
        metadata, bom = _make_metadata(files)
        findings = BP002().evaluate(bom, metadata)
        assert len(findings) == 0


class TestBP003:
    """No retry/fallback in LLM calls."""

    def test_no_retry(self):
        files = {"main.py": 'model = "gpt-4o"\nresult = client.chat(prompt)\n'}
        metadata, bom = _make_metadata(files)
        findings = BP003().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "BP-003"

    def test_has_retry(self):
        files = {"main.py": 'model = "gpt-4o"\nfrom tenacity import retry\n@retry\ndef call():\n    pass\n'}
        metadata, bom = _make_metadata(files)
        findings = BP003().evaluate(bom, metadata)
        assert len(findings) == 0


class TestBP005:
    """Too many tools on single agent."""

    def test_too_many_tools(self):
        tools_list = ", ".join(f'"tool_{i}"' for i in range(12))
        files = {"main.py": f'from crewai import Agent\nagent = Agent(name="Big", tools=[{tools_list}])\n'}
        metadata, bom = _make_metadata(files)
        findings = BP005().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "BP-005"

    def test_reasonable_tools(self):
        files = {"main.py": 'from crewai import Agent\nagent = Agent(name="Small", tools=["a", "b", "c"])\n'}
        metadata, bom = _make_metadata(files)
        findings = BP005().evaluate(bom, metadata)
        assert len(findings) == 0
