"""Tests for context versioning policy rules (CV-001, CV-002)."""
import pytest
from pathlib import Path

from drako.cli.discovery import ProjectMetadata
from drako.cli.bom import generate_bom, AgentBOM
from drako.cli.policies.versioning import CV001, CV002


def _make_metadata(files: dict[str, str], config_files: dict[str, str] | None = None) -> tuple[ProjectMetadata, AgentBOM]:
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = []
    metadata.dependencies = {}
    if config_files is not None:
        metadata.config_files = config_files
    bom = generate_bom(metadata)
    return metadata, bom


class TestCV001:
    """No policy versioning configured."""

    def test_no_config_file(self):
        metadata, bom = _make_metadata(
            {"main.py": 'from crewai import Agent\n'},
            config_files={},
        )
        findings = CV001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "CV-001"

    def test_config_without_endpoint(self):
        metadata, bom = _make_metadata(
            {"main.py": 'from crewai import Agent\n'},
            config_files={".drako.yaml": "version: '1.0'\ntenant_id: test\n"},
        )
        findings = CV001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "CV-001"

    def test_config_with_endpoint(self):
        metadata, bom = _make_metadata(
            {"main.py": 'from crewai import Agent\n'},
            config_files={".drako.yaml": "version: '1.0'\ntenant_id: test\nendpoint: https://api.useagentmesh.com\napi_key_env: DRAKO_API_KEY\n"},
        )
        findings = CV001().evaluate(bom, metadata)
        assert len(findings) == 0


class TestCV002:
    """Audit logs without policy version reference."""

    def test_audit_without_connection(self):
        metadata, bom = _make_metadata(
            {"main.py": 'print("hi")\n'},
            config_files={".drako.yaml": "version: '1.0'\naudit:\n  enabled: true\n"},
        )
        findings = CV002().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "CV-002"

    def test_audit_with_connection(self):
        metadata, bom = _make_metadata(
            {"main.py": 'print("hi")\n'},
            config_files={".drako.yaml": "version: '1.0'\naudit:\n  enabled: true\napi_key_env: DRAKO_API_KEY\n"},
        )
        findings = CV002().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_no_config(self):
        metadata, bom = _make_metadata({"main.py": 'x=1\n'}, config_files={})
        findings = CV002().evaluate(bom, metadata)
        assert len(findings) == 0  # CV-001 handles missing config
