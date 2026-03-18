"""Tests for programmable hooks policy rules (HOOK-001, HOOK-002, HOOK-003)."""
import pytest
from pathlib import Path

from drako.cli.discovery import ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies.hooks import HOOK001, HOOK002, HOOK003


def _make_metadata(
    files: dict[str, str],
    config_files: dict[str, str] | None = None,
) -> tuple[ProjectMetadata, AgentBOM]:
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = []
    metadata.dependencies = {}
    if config_files is not None:
        metadata.config_files = config_files
    bom = generate_bom(metadata)
    return metadata, bom


# Use a file that defines a tool so bom.tools is non-empty
TOOL_FILE = '@tool\ndef send_email(to, body):\n    """Send an email."""\n    pass\n'


class TestHOOK001:
    """No pre-action validation hooks."""

    def test_tools_no_config(self):
        metadata, bom = _make_metadata(
            {"tools.py": TOOL_FILE},
            config_files={},
        )
        findings = HOOK001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "HOOK-001"

    def test_tools_config_with_pre_action(self):
        metadata, bom = _make_metadata(
            {"tools.py": TOOL_FILE},
            config_files={".drako.yaml": "hooks:\n  pre_action:\n    - name: block\n"},
        )
        findings = HOOK001().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_tools_config_without_hooks(self):
        metadata, bom = _make_metadata(
            {"tools.py": TOOL_FILE},
            config_files={".drako.yaml": "version: '1.0'\n"},
        )
        findings = HOOK001().evaluate(bom, metadata)
        assert len(findings) == 1

    def test_no_tools_no_finding(self):
        metadata, bom = _make_metadata(
            {"main.py": 'print("hi")\n'},
            config_files={},
        )
        findings = HOOK001().evaluate(bom, metadata)
        assert len(findings) == 0


class TestHOOK002:
    """No session-end gate (Stop hook)."""

    def test_config_without_session_end(self):
        metadata, bom = _make_metadata(
            {"main.py": 'x=1\n'},
            config_files={".drako.yaml": "hooks:\n  pre_action:\n    - name: block\n"},
        )
        findings = HOOK002().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "HOOK-002"

    def test_config_with_session_end(self):
        metadata, bom = _make_metadata(
            {"main.py": 'x=1\n'},
            config_files={".drako.yaml": "hooks:\n  on_session_end:\n    - name: check\n"},
        )
        findings = HOOK002().evaluate(bom, metadata)
        assert len(findings) == 0


class TestHOOK003:
    """Hook without timeout configured."""

    def test_script_without_timeout(self):
        metadata, bom = _make_metadata(
            {"main.py": 'x=1\n'},
            config_files={".drako.yaml": "hooks:\n  pre_action:\n    - name: check\n      script: check.py\n"},
        )
        findings = HOOK003().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "HOOK-003"

    def test_script_with_timeout(self):
        metadata, bom = _make_metadata(
            {"main.py": 'x=1\n'},
            config_files={".drako.yaml": "hooks:\n  pre_action:\n    - name: check\n      script: check.py\n      timeout_ms: 5000\n"},
        )
        findings = HOOK003().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_condition_only_no_finding(self):
        metadata, bom = _make_metadata(
            {"main.py": 'x=1\n'},
            config_files={".drako.yaml": "hooks:\n  pre_action:\n    - name: check\n      condition: \"True\"\n"},
        )
        findings = HOOK003().evaluate(bom, metadata)
        assert len(findings) == 0
