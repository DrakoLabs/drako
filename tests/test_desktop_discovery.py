"""Tests for desktop agent discovery and MCP security rules."""

from __future__ import annotations

import json

import pytest

from drako.desktop.discovery import (
    DesktopAgent,
    DesktopBOM,
    MCPServerConfig,
    _parse_claude_code,
    _parse_claude_desktop,
    _parse_cursor,
    _parse_generic_mcp_config,
    _parse_vscode,
    discover_agents,
)
from drako.desktop.mcp_rules import evaluate_mcp_rules

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bom(servers: list[MCPServerConfig]) -> DesktopBOM:
    """Build a minimal DesktopBOM from a flat list of server configs."""
    return DesktopBOM(
        agents=[
            DesktopAgent(
                client_name="test",
                display_name="Test",
                config_path="/test",
                mcp_servers=servers,
            ),
        ],
        total_mcp_servers=len(servers),
    )


# ===================================================================
# MCPServerConfig property tests
# ===================================================================


class TestMCPServerConfig:
    """Validate heuristic capability detection on MCPServerConfig."""

    def test_filesystem_detection(self) -> None:
        s = MCPServerConfig(
            name="fs",
            command="npx",
            args=["@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        assert s.has_filesystem_access
        assert not s.has_shell_access

    def test_shell_detection(self) -> None:
        s = MCPServerConfig(name="sh", command="npx", args=["mcp-shell-server"])
        assert s.has_shell_access

    def test_network_detection(self) -> None:
        s = MCPServerConfig(name="web", command="npx", args=["mcp-fetch-server"])
        assert s.has_network_access

    def test_package_name_npx(self) -> None:
        s = MCPServerConfig(name="t", command="npx", args=["@company/mcp-server"])
        assert s.package_name == "@company/mcp-server"

    def test_package_name_uvx(self) -> None:
        s = MCPServerConfig(name="t", command="uvx", args=["some-tool"])
        assert s.package_name == "some-tool"

    def test_package_name_python(self) -> None:
        s = MCPServerConfig(name="t", command="python", args=["server.py"])
        assert s.package_name == "server.py"

    def test_package_name_bare_command(self) -> None:
        s = MCPServerConfig(name="t", command="my-server", args=[])
        assert s.package_name == "my-server"

    def test_no_capabilities(self) -> None:
        s = MCPServerConfig(
            name="safe",
            command="npx",
            args=["@modelcontextprotocol/server-memory"],
        )
        assert not s.has_filesystem_access
        assert not s.has_shell_access
        assert not s.has_network_access


# ===================================================================
# Parser tests
# ===================================================================


class TestParsers:
    """Validate config file parsers for each supported AI client."""

    def test_claude_desktop(self) -> None:
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": [
                        "@modelcontextprotocol/server-filesystem",
                        "/tmp",
                    ],
                },
                "github": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "ghp_abc123"},
                },
            },
        }
        servers = _parse_claude_desktop(data, "/test/config.json")
        assert len(servers) == 2
        assert servers[0].name == "filesystem"
        assert servers[0].client == "claude_desktop"
        assert servers[1].env["GITHUB_TOKEN"] == "ghp_abc123"

    def test_claude_code_root_and_project(self) -> None:
        data = {
            "mcpServers": {
                "root-server": {"command": "npx", "args": ["root-pkg"]},
            },
            "projects": {
                "/my/project": {
                    "mcpServers": {
                        "proj-server": {"command": "node", "args": ["s.js"]},
                    },
                },
            },
        }
        servers = _parse_claude_code(data, "/test/.claude.json")
        assert len(servers) == 2
        assert servers[0].name == "root-server"
        assert "proj-server" in servers[1].name

    def test_cursor(self) -> None:
        data = {"mcpServers": {"db": {"command": "npx", "args": ["mcp-db"]}}}
        servers = _parse_cursor(data, "/test/mcp.json")
        assert len(servers) == 1
        assert servers[0].client == "cursor"

    def test_vscode_copilot_format(self) -> None:
        data = {
            "github.copilot.chat.mcp.servers": {
                "search": {"command": "npx", "args": ["mcp-search"]},
            },
        }
        servers = _parse_vscode(data, "/test/settings.json")
        assert len(servers) == 1
        assert servers[0].client == "vscode"

    def test_vscode_multiple_sections(self) -> None:
        data = {
            "mcp.servers": {
                "a": {"command": "npx", "args": ["pkg-a"]},
            },
            "mcpServers": {
                "b": {"command": "npx", "args": ["pkg-b"]},
            },
        }
        servers = _parse_vscode(data, "/test/settings.json")
        assert len(servers) == 2

    def test_generic_mcp_config(self) -> None:
        data = {
            "mcpServers": {
                "tool": {"command": "python3", "args": ["tool.py"]},
            },
        }
        servers = _parse_generic_mcp_config(data, "/home/user/.kiro/mcp.json")
        assert len(servers) == 1

    def test_empty_config(self) -> None:
        assert _parse_claude_desktop({}, "/test/config.json") == []
        assert _parse_cursor({}, "/test/mcp.json") == []
        assert _parse_vscode({}, "/test/settings.json") == []

    def test_malformed_server_entry_skipped(self) -> None:
        data = {
            "mcpServers": {
                "valid": {"command": "npx", "args": ["pkg"]},
                "invalid": "not-a-dict",
            },
        }
        servers = _parse_claude_desktop(data, "/test/config.json")
        assert len(servers) == 1
        assert servers[0].name == "valid"


# ===================================================================
# Discovery integration tests
# ===================================================================


class TestDiscovery:
    """End-to-end discovery tests with mocked filesystem."""

    def test_no_clients_installed(self) -> None:
        """Discovery with no client paths returns empty BOM."""
        from unittest.mock import patch

        with patch(
            "drako.desktop.discovery._get_client_paths", return_value=[]
        ):
            bom = discover_agents(scan_project_mcp=False)
            assert bom.total_mcp_servers == 0
            assert bom.agents == []

    def test_project_mcp_json(self, tmp_path: pytest.TempPathFactory) -> None:
        """Discovers .mcp.json in project directory."""
        mcp_file = tmp_path / ".mcp.json"  # type: ignore[operator]
        mcp_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "local": {"command": "python", "args": ["server.py"]},
                    },
                }
            )
        )
        bom = discover_agents(project_dir=str(tmp_path))
        project_agents = [
            a for a in bom.agents if a.client_name == "project_mcp"
        ]
        assert len(project_agents) == 1
        assert project_agents[0].mcp_servers[0].name == "local"

    def test_malformed_json_skipped(self, tmp_path: pytest.TempPathFactory) -> None:
        """Malformed config files are silently skipped."""
        mcp_file = tmp_path / ".mcp.json"  # type: ignore[operator]
        mcp_file.write_text("not json {{{")
        bom = discover_agents(project_dir=str(tmp_path))
        project_agents = [
            a for a in bom.agents if a.client_name == "project_mcp"
        ]
        assert len(project_agents) == 0

    def test_bom_totals(self) -> None:
        """BOM computes aggregate totals correctly."""
        bom = _make_bom([
            MCPServerConfig(
                name="fs",
                command="npx",
                args=["@modelcontextprotocol/server-filesystem"],
            ),
            MCPServerConfig(
                name="sh",
                command="npx",
                args=["mcp-shell-server"],
            ),
        ])
        assert bom.total_mcp_servers == 2


# ===================================================================
# MCP rule tests
# ===================================================================


class TestMCP001:
    """MCP-001: Filesystem access without path restriction."""

    def test_fires_unrestricted(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="fs",
                command="npx",
                args=["@modelcontextprotocol/server-filesystem"],
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-001" for f in findings)

    def test_no_fire_restricted(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="fs",
                command="npx",
                args=[
                    "@modelcontextprotocol/server-filesystem",
                    "/safe/path",
                ],
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-001" for f in findings)


class TestMCP002:
    """MCP-002: Shell / exec capability."""

    def test_fires_shell(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="sh",
                command="npx",
                args=["mcp-shell-server"],
                client="cursor",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-002" for f in findings)

    def test_no_fire_safe(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="safe",
                command="npx",
                args=["@modelcontextprotocol/server-memory"],
                client="cursor",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-002" for f in findings)


class TestMCP003:
    """MCP-003: Server from unverified source."""

    def test_fires_unknown_package(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="unk",
                command="npx",
                args=["random-unknown-pkg"],
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-003" for f in findings)

    def test_no_fire_trusted_prefix(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="trusted",
                command="npx",
                args=["@modelcontextprotocol/server-memory"],
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-003" for f in findings)

    def test_no_fire_local_path(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="local",
                command="./my-server",
                args=[],
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-003" for f in findings)


class TestMCP004:
    """MCP-004: Network access without domain allowlist."""

    def test_fires_network(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="web",
                command="npx",
                args=["mcp-fetch-server"],
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-004" for f in findings)


class TestMCP005:
    """MCP-005: Credentials in plaintext config."""

    def test_fires_plaintext_creds(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="gh",
                command="npx",
                args=["mcp-github"],
                env={"GITHUB_TOKEN": "ghp_realtoken123"},
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-005" for f in findings)

    def test_no_fire_env_reference(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="gh",
                command="npx",
                args=["mcp-github"],
                env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-005" for f in findings)

    def test_no_fire_non_sensitive_key(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="gh",
                command="npx",
                args=["mcp-github"],
                env={"LOG_LEVEL": "debug"},
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-005" for f in findings)


class TestMCP006:
    """MCP-006: Unencrypted transport (HTTP)."""

    def test_fires_http(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="remote",
                command="",
                transport="sse",
                url="http://evil.example.com/mcp",
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-006" for f in findings)

    def test_no_fire_https(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="remote",
                command="",
                transport="sse",
                url="https://safe.example.com/mcp",
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-006" for f in findings)

    def test_no_fire_localhost(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="local",
                command="",
                transport="sse",
                url="http://localhost:3000/mcp",
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-006" for f in findings)


class TestMCP007:
    """MCP-007: Server running with elevated privileges."""

    def test_fires_sudo(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="root",
                command="sudo",
                args=["python", "server.py"],
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-007" for f in findings)

    def test_fires_doas(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="root",
                command="doas",
                args=["python", "server.py"],
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-007" for f in findings)

    def test_no_fire_normal(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="normal",
                command="npx",
                args=["@modelcontextprotocol/server-memory"],
                client="vscode",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-007" for f in findings)


class TestMCP008:
    """MCP-008: Multiple high-risk capabilities combined."""

    def test_fires_compound_risk(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="danger",
                command="npx",
                args=["mcp-shell-filesystem-fetch"],
                client="cursor",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert any(f.rule_id == "MCP-008" for f in findings)

    def test_no_fire_single_risk(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="sh",
                command="npx",
                args=["mcp-shell-server"],
                client="cursor",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert not any(f.rule_id == "MCP-008" for f in findings)


class TestCleanServer:
    """A completely safe server produces zero findings."""

    def test_no_findings(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="safe",
                command="npx",
                args=["@modelcontextprotocol/server-memory"],
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        assert len(findings) == 0


class TestFindingSorting:
    """Findings are sorted by severity: CRITICAL first."""

    def test_critical_before_medium(self) -> None:
        bom = _make_bom([
            MCPServerConfig(
                name="gh",
                command="npx",
                args=["mcp-github"],
                env={"API_KEY": "sk-secret"},
                client="claude_desktop",
                source_file="/test",
            ),
        ])
        findings = evaluate_mcp_rules(bom)
        severities = [f.severity for f in findings]
        assert severities == sorted(
            severities,
            key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[s],
        )
