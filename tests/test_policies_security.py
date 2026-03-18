"""Tests for security policy rules (SEC-001 through SEC-007)."""
import pytest
from pathlib import Path

from drako.cli.discovery import collect_project_files, detect_frameworks, ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies.security import (
    SEC001, SEC002, SEC003, SEC004, SEC005, SEC006, SEC007,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _make_metadata(files: dict[str, str]) -> tuple[ProjectMetadata, AgentBOM]:
    """Helper: create metadata + BOM from inline file contents."""
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = []
    metadata.dependencies = {}
    bom = generate_bom(metadata)
    return metadata, bom


class TestSEC001:
    """API keys hardcoded in source code."""

    def test_detects_hardcoded_openai_key(self):
        files = {"main.py": 'OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl0123456"'}
        metadata, bom = _make_metadata(files)
        findings = SEC001().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "SEC-001"
        assert findings[0].severity == "CRITICAL"

    def test_no_finding_for_env_var(self):
        files = {"main.py": 'import os\nAPI_KEY = os.environ["OPENAI_API_KEY"]'}
        metadata, bom = _make_metadata(files)
        findings = SEC001().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_detects_aws_key(self):
        files = {"main.py": 'aws_key = "AKIAIOSFODNN7EXAMPLE1"'}
        metadata, bom = _make_metadata(files)
        findings = SEC001().evaluate(bom, metadata)
        assert len(findings) >= 1

    def test_on_fixture_crewai(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)
        findings = SEC001().evaluate(bom, metadata)
        assert len(findings) >= 1


class TestSEC003:
    """Unrestricted filesystem access in tools."""

    def test_detects_unvalidated_open(self):
        files = {"tools.py": '@tool\ndef read_file(path):\n    with open(path) as f:\n        return f.read()\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC003().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "SEC-003"

    def test_no_finding_with_validation(self):
        files = {"tools.py": '@tool\ndef read_file(path):\n    resolved = Path(path).resolve()\n    if not str(resolved).startswith(str(ALLOWED_DIR)):\n        raise ValueError("bad")\n    with open(resolved) as f:\n        return f.read()\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC003().evaluate(bom, metadata)
        assert len(findings) == 0


class TestSEC005:
    """Arbitrary code execution."""

    def test_detects_exec(self):
        files = {"main.py": 'def run(code):\n    exec(code)\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC005().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "SEC-005"
        assert findings[0].severity == "CRITICAL"

    def test_detects_eval(self):
        files = {"main.py": 'result = eval(user_input)\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC005().evaluate(bom, metadata)
        assert len(findings) >= 1

    def test_detects_subprocess(self):
        files = {"main.py": 'import subprocess\nsubprocess.run(cmd, shell=True)\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC005().evaluate(bom, metadata)
        assert len(findings) >= 1

    def test_on_fixture_autogen(self):
        metadata = collect_project_files(FIXTURES / "autogen_vulnerable")
        metadata.frameworks = detect_frameworks(metadata)
        bom = generate_bom(metadata)
        findings = SEC005().evaluate(bom, metadata)
        assert len(findings) >= 1


class TestSEC006:
    """No input validation on tool parameters."""

    def test_detects_untyped_tool(self):
        files = {"tools.py": '@tool\ndef search(query):\n    return query\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC006().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "SEC-006"

    def test_no_finding_with_types(self):
        files = {"tools.py": '@tool\ndef search(query: str) -> str:\n    return query\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC006().evaluate(bom, metadata)
        assert len(findings) == 0


class TestSEC007:
    """Prompt injection vulnerability."""

    def test_detects_fstring_prompt(self):
        files = {"main.py": 'user_input = "test"\nprompt = f"System: {user_input}"\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC007().evaluate(bom, metadata)
        assert len(findings) >= 1
        assert findings[0].policy_id == "SEC-007"

    def test_detects_format_prompt(self):
        files = {"main.py": 'prompt = "System: {}".format(user_input)\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC007().evaluate(bom, metadata)
        assert len(findings) >= 1

    def test_no_finding_for_static_prompt(self):
        files = {"main.py": 'system_message = "You are a helpful assistant."\n'}
        metadata, bom = _make_metadata(files)
        findings = SEC007().evaluate(bom, metadata)
        assert len(findings) == 0
