"""Tests for the discovery module (framework & dependency detection)."""
import pytest
from pathlib import Path

from drako.cli.discovery import (
    collect_project_files,
    detect_frameworks,
    _parse_requirements_txt,
    _parse_pyproject_toml,
    ProjectMetadata,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseRequirementsTxt:
    def test_basic_packages(self):
        content = "crewai>=0.80.0\nlangchain>=0.3.0\nrequests\n"
        deps = _parse_requirements_txt(content)
        assert "crewai" in deps
        assert deps["crewai"] == "0.80.0"
        assert "langchain" in deps
        assert "requests" in deps

    def test_comments_and_blanks(self):
        content = "# comment\n\ncrewai>=0.1.0\n-r base.txt\n"
        deps = _parse_requirements_txt(content)
        assert "crewai" in deps
        assert len(deps) == 1

    def test_extras(self):
        content = "crewai[tools]>=0.80.0\n"
        deps = _parse_requirements_txt(content)
        assert "crewai" in deps

    def test_no_version(self):
        content = "requests\nhttpx\n"
        deps = _parse_requirements_txt(content)
        assert "requests" in deps
        assert deps["requests"] is None


class TestParsePyprojectToml:
    def test_basic_deps(self):
        content = '''
[project]
dependencies = [
    "crewai>=0.80.0",
    "langchain>=0.3.0",
]
'''
        deps = _parse_pyproject_toml(content)
        assert "crewai" in deps
        assert deps["crewai"] == "0.80.0"

    def test_empty(self):
        deps = _parse_pyproject_toml("")
        assert deps == {}


class TestCollectProjectFiles:
    def test_crewai_basic(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        assert len(metadata.python_files) >= 2
        assert "main.py" in metadata.file_contents
        assert "tools.py" in metadata.file_contents
        assert "requirements.txt" in metadata.config_files

    def test_langgraph_clean(self):
        metadata = collect_project_files(FIXTURES / "langgraph_clean")
        assert len(metadata.python_files) >= 2
        assert ".drako.yaml" in metadata.config_files

    def test_dependencies_parsed(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        assert "crewai" in metadata.dependencies


class TestDetectFrameworks:
    def test_crewai_detected(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        frameworks = detect_frameworks(metadata)
        names = [f.name for f in frameworks]
        assert "crewai" in names

    def test_langgraph_detected(self):
        metadata = collect_project_files(FIXTURES / "langgraph_clean")
        frameworks = detect_frameworks(metadata)
        names = [f.name for f in frameworks]
        assert "langgraph" in names

    def test_autogen_detected(self):
        metadata = collect_project_files(FIXTURES / "autogen_vulnerable")
        frameworks = detect_frameworks(metadata)
        names = [f.name for f in frameworks]
        assert "autogen" in names

    def test_mixed_frameworks(self):
        metadata = collect_project_files(FIXTURES / "mixed_framework")
        frameworks = detect_frameworks(metadata)
        names = [f.name for f in frameworks]
        assert "crewai" in names
        assert "langgraph" in names

    def test_version_detected(self):
        metadata = collect_project_files(FIXTURES / "crewai_basic")
        frameworks = detect_frameworks(metadata)
        crewai = next(f for f in frameworks if f.name == "crewai")
        assert crewai.version is not None
        assert "0.80" in crewai.version
