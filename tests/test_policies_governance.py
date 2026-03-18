"""Tests for governance policy rules (GOV-001 through GOV-006)."""
import pytest
from pathlib import Path

from drako.cli.discovery import collect_project_files, detect_frameworks, ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies.governance import (
    GOV001, GOV002, GOV003, GOV004, GOV005, GOV006,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_metadata(files: dict[str, str]) -> tuple[ProjectMetadata, AgentBOM]:
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = []
    metadata.dependencies = {}
    bom = generate_bom(metadata)
    return metadata, bom


class TestGOV001:
    """No audit logging configured."""

    def test_no_audit_logging(self):
        files = {"main.py": 'from crewai import Agent\nagent = Agent(name="Test")\n'}
        metadata, bom = _make_metadata(files)
        findings = GOV001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "GOV-001"

    def test_has_audit_logging(self):
        files = {"main.py": 'from drako import with_compliance\ncrew = with_compliance(my_crew)\n'}
        metadata, bom = _make_metadata(files)
        findings = GOV001().evaluate(bom, metadata)
        assert len(findings) == 0


class TestGOV004:
    """No human-in-the-loop for destructive actions."""

    def test_destructive_tools_no_hitl(self):
        files = {"tools.py": '@tool\ndef write_file(path, content):\n    with open(path, "w") as f:\n        f.write(content)\n'}
        metadata, bom = _make_metadata(files)
        findings = GOV004().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "GOV-004"

    def test_no_finding_with_hitl(self):
        files = {"tools.py": '@tool\ndef write_file(path, content):\n    require_approval()\n    with open(path, "w") as f:\n        f.write(content)\n'}
        metadata, bom = _make_metadata(files)
        findings = GOV004().evaluate(bom, metadata)
        assert len(findings) == 0


class TestGOV006:
    """Agent can modify its own system prompt."""

    def test_detects_self_prompt_modification(self):
        files = {"agent.py": 'class MyAgent:\n    def __init__(self):\n        self.system_prompt = "initial"\n    def update(self, p):\n        self.system_prompt = p\n'}
        metadata, bom = _make_metadata(files)
        findings = GOV006().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "GOV-006"

    def test_init_assignment_ok(self):
        files = {"agent.py": 'class MyAgent:\n    def __init__(self, prompt):\n        self.system_prompt = prompt\n'}
        metadata, bom = _make_metadata(files)
        findings = GOV006().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_on_fixture_autogen(self):
        metadata = collect_project_files(FIXTURES / "autogen_vulnerable")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)
        findings = GOV006().evaluate(bom, metadata)
        assert len(findings) >= 1
