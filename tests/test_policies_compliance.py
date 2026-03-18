"""Tests for compliance policy rules (COM-001 through COM-005)."""
import pytest
from pathlib import Path

from drako.cli.discovery import collect_project_files, detect_frameworks, ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies.compliance import (
    COM001, COM002, COM003, COM004, COM005,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_metadata(files: dict[str, str], root: Path = Path("/fake")) -> tuple[ProjectMetadata, AgentBOM]:
    metadata = ProjectMetadata(root=root)
    metadata.file_contents = files
    metadata.frameworks = []
    metadata.dependencies = {}
    bom = generate_bom(metadata)
    return metadata, bom


class TestCOM001:
    """No automatic logging (EU AI Act Art. 12)."""

    def test_no_logging(self):
        files = {"main.py": 'from crewai import Agent\nagent = Agent(name="Test")\n'}
        metadata, bom = _make_metadata(files)
        findings = COM001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "COM-001"

    def test_has_logging(self):
        files = {"main.py": 'from drako import with_compliance\ncrew = with_compliance(my_crew)\n'}
        metadata, bom = _make_metadata(files)
        findings = COM001().evaluate(bom, metadata)
        assert len(findings) == 0


class TestCOM005:
    """No Agent BOM / inventory maintained."""

    def test_no_bom_file(self):
        files = {"main.py": 'print("hello")\n'}
        metadata, bom = _make_metadata(files)
        findings = COM005().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "COM-005"

    def test_has_drako_yaml(self):
        metadata = collect_project_files(FIXTURES / "langgraph_clean")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)
        findings = COM005().evaluate(bom, metadata)
        assert len(findings) == 0
