"""Tests for the `drako bom` CLI command."""
import json
from pathlib import Path

from click.testing import CliRunner

from drako.cli.main import cli

FIXTURES = Path(__file__).parent / "fixtures"


class TestBomCommand:
    def test_text_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(FIXTURES / "crewai_basic")])
        assert result.exit_code == 0
        assert "Agent BOM" in result.output

    def test_json_output_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(FIXTURES / "crewai_basic"), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "project" in data
        assert "agents" in data
        assert "tools" in data
        assert "models" in data
        assert "prompts" in data
        assert "permissions" in data
        assert "dependencies" in data
        assert "scan_metadata" in data

    def test_json_prompts_use_hash(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(FIXTURES / "crewai_basic"), "--format", "json"])
        data = json.loads(result.output)
        for p in data["prompts"]:
            assert "content_hash" in p
            assert p["content_hash"].startswith("sha256:")
            assert "content_preview" not in p

    def test_markdown_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(FIXTURES / "crewai_basic"), "--format", "markdown"])
        assert result.exit_code == 0
        assert "| Component" in result.output
        assert "Agent BOM" in result.output

    def test_output_to_file(self, tmp_path):
        out = tmp_path / "bom.json"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "bom", str(FIXTURES / "crewai_basic"),
            "--format", "json",
            "-o", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "agents" in data

    def test_empty_project(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["agents"] == []
        assert data["tools"] == []

    def test_crewai_basic_has_agents(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(FIXTURES / "crewai_basic"), "--format", "json"])
        data = json.loads(result.output)
        assert len(data["agents"]) >= 2

    def test_json_has_scan_metadata(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["bom", str(FIXTURES / "crewai_basic"), "--format", "json"])
        data = json.loads(result.output)
        meta = data["scan_metadata"]
        assert "timestamp" in meta
        assert "drako_version" in meta
        assert "duration_ms" in meta
        assert isinstance(meta["duration_ms"], int)
