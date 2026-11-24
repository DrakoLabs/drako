"""Tests for local-first Context Versioning policy rules (CV-001, CV-002) in v4."""

from pathlib import Path

from drako.cli.bom import AgentBOM, generate_bom
from drako.cli.discovery import ProjectMetadata
from drako.cli.policies.versioning import CV001, CV002


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


class TestCV001:
    def test_no_config_file(self):
        metadata, bom = _make_metadata({"main.py": "from crewai import Agent\n"}, config_files={})
        findings = CV001().evaluate(bom, metadata)
        assert len(findings) == 1 and findings[0].policy_id == "CV-001"

    def test_config_without_policy_pin(self):
        metadata, bom = _make_metadata(
            {"main.py": "from crewai import Agent\n"},
            config_files={".drako.yaml": "version: '1.0'\nproject_id: test\n"},
        )
        findings = CV001().evaluate(bom, metadata)
        assert len(findings) == 1 and findings[0].policy_id == "CV-001"

    def test_config_with_kernel_spec_pin(self):
        metadata, bom = _make_metadata(
            {"main.py": "from crewai import Agent\n"},
            config_files={".drako.yaml": "version: '4.0'\nkernel:\n  spec_pin: AGENT-HOOKS-0.1\n"},
        )
        assert CV001().evaluate(bom, metadata) == []


class TestCV002:
    def test_audit_without_receipt_binding(self):
        metadata, bom = _make_metadata(
            {"main.py": 'print("hi")\n'},
            config_files={".drako.yaml": "version: '1.0'\naudit:\n  enabled: true\n"},
        )
        findings = CV002().evaluate(bom, metadata)
        assert len(findings) == 1 and findings[0].policy_id == "CV-002"

    def test_audit_with_receipt_store_binding(self):
        metadata, bom = _make_metadata(
            {"main.py": 'print("hi")\n'},
            config_files={
                ".drako.yaml": "version: '4.0'\naudit:\n  enabled: true\n  cryptographic: true\n  receipt_store: .drako/receipts.jsonl\n"
            },
        )
        assert CV002().evaluate(bom, metadata) == []

    def test_no_config(self):
        metadata, bom = _make_metadata({"main.py": "x=1\n"}, config_files={})
        assert CV002().evaluate(bom, metadata) == []
