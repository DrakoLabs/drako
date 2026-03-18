"""Tests for framework auto-detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from drako.utils.detection import detect_framework


class TestDetectCrewAI:
    def test_detect_by_crewai_yaml(self, tmp_path):
        (tmp_path / "crewai.yaml").touch()
        assert detect_framework(str(tmp_path)) == "crewai"

    def test_detect_by_crew_py(self, tmp_path):
        (tmp_path / "crew.py").write_text("from crewai import Crew")
        assert detect_framework(str(tmp_path)) == "crewai"

    def test_detect_by_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("crewai>=0.70.0\nhttpx\n")
        assert detect_framework(str(tmp_path)) == "crewai"

    def test_detect_by_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["crewai"]\n')
        assert detect_framework(str(tmp_path)) == "crewai"

    def test_detect_by_import(self, tmp_path):
        src = tmp_path / "agent.py"
        src.write_text("from crewai import Agent, Task\n")
        assert detect_framework(str(tmp_path)) == "crewai"


class TestDetectLangGraph:
    def test_detect_by_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("langgraph>=0.2.0\n")
        assert detect_framework(str(tmp_path)) == "langgraph"

    def test_detect_by_import(self, tmp_path):
        src = tmp_path / "graph.py"
        src.write_text("from langgraph.graph import StateGraph\n")
        assert detect_framework(str(tmp_path)) == "langgraph"

    def test_detect_by_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["langgraph>=0.2"]\n')
        assert detect_framework(str(tmp_path)) == "langgraph"


class TestDetectAutoGen:
    def test_detect_by_requirements_autogen(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("pyautogen>=0.4.0\n")
        assert detect_framework(str(tmp_path)) == "autogen"

    def test_detect_by_requirements_autogen_alt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("autogen>=0.4.0\n")
        assert detect_framework(str(tmp_path)) == "autogen"

    def test_detect_by_import(self, tmp_path):
        src = tmp_path / "chat.py"
        src.write_text("from autogen import AssistantAgent\n")
        assert detect_framework(str(tmp_path)) == "autogen"


class TestDetectPriority:
    def test_crewai_over_langgraph(self, tmp_path):
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("crewai>=0.70\nlanggraph>=0.2\n")
        assert detect_framework(str(tmp_path)) == "crewai"

    def test_langgraph_over_autogen(self, tmp_path):
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("langgraph>=0.2\npyautogen>=0.4\n")
        assert detect_framework(str(tmp_path)) == "langgraph"

    def test_no_framework(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')\n")
        assert detect_framework(str(tmp_path)) is None

    def test_empty_directory(self, tmp_path):
        assert detect_framework(str(tmp_path)) is None


class TestDetectSkipsIgnoredDirs:
    def test_ignores_venv(self, tmp_path):
        venv = tmp_path / "venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "autogen_thing.py").write_text("from autogen import foo")
        assert detect_framework(str(tmp_path)) is None

    def test_ignores_pycache(self, tmp_path):
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "cached.py").write_text("from crewai import Agent")
        assert detect_framework(str(tmp_path)) is None
