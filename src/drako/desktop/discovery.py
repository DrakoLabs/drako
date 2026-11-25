"""Desktop AI agent discovery.

Discovers all AI agents, MCP servers, and skills installed on the
user's machine by reading known configuration paths.

Supported clients:
- Claude Desktop (Anthropic)
- Claude Code (.claude/, .mcp.json)
- Cursor (.cursor/mcp.json)
- VS Code / Copilot (settings.json MCP configs)
- Windsurf (.windsurf/, .codeium/)
- Codex CLI (.codex/)
- Gemini CLI (.gemini/)
- Kiro (.kiro/)

All operations are read-only, offline, and deterministic.
No data leaves the machine.
"""

from __future__ import annotations

import json
import os
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MCPServerConfig:
    """A single MCP server declared in a client configuration file."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"
    url: str | None = None
    source_file: str = ""
    client: str = ""

    @property
    def package_name(self) -> str:
        """Extract the package being invoked.

        For runners like ``npx``, ``uvx``, or ``bunx`` the first argument
        is the actual package.  For interpreters (``python``, ``node``) the
        first argument is the script path.  Otherwise fall back to the
        command itself.
        """
        if self.command in ("npx", "uvx", "bunx"):
            return self.args[0] if self.args else "unknown"
        if self.command in ("python", "python3", "node"):
            return self.args[0] if self.args else "unknown"
        return self.command

    @property
    def has_filesystem_access(self) -> bool:
        """Heuristic: does this server likely have filesystem access?"""
        indicators = ["filesystem", "fs", "file", "directory", "path"]
        searchable = f"{self.package_name} {' '.join(self.args)}".lower()
        return any(ind in searchable for ind in indicators)

    @property
    def has_shell_access(self) -> bool:
        """Heuristic: does this server likely have shell/exec access?"""
        indicators = ["shell", "exec", "terminal", "command", "bash", "run"]
        searchable = f"{self.package_name} {' '.join(self.args)}".lower()
        return any(ind in searchable for ind in indicators)

    @property
    def has_network_access(self) -> bool:
        """Heuristic: does this server likely have network access?"""
        indicators = ["fetch", "http", "api", "web", "request", "curl", "browser"]
        searchable = f"{self.package_name} {' '.join(self.args)}".lower()
        return any(ind in searchable for ind in indicators)


@dataclass
class DesktopAgent:
    """A desktop AI client with its MCP servers."""

    client_name: str
    display_name: str
    config_path: str
    mcp_servers: list[MCPServerConfig] = field(default_factory=list)
    installed: bool = True


@dataclass
class DesktopBOM:
    """Bill of Materials for the entire desktop."""

    agents: list[DesktopAgent] = field(default_factory=list)
    total_mcp_servers: int = 0
    total_with_filesystem: int = 0
    total_with_shell: int = 0
    total_with_network: int = 0
    platform: str = ""
    scan_duration_ms: float = 0


# ---------------------------------------------------------------------------
# Client configuration path definitions
# ---------------------------------------------------------------------------

ClientParser = Callable[[dict[str, Any], str], list[MCPServerConfig]]


def _parse_claude_desktop(data: dict[str, Any], config_path: str) -> list[MCPServerConfig]:
    """Parse Claude Desktop config: ``{mcpServers: {name: {command, args, env}}}``."""
    servers: list[MCPServerConfig] = []
    for name, cfg in data.get("mcpServers", {}).items():
        if not isinstance(cfg, dict):
            continue
        servers.append(MCPServerConfig(
            name=name,
            command=cfg.get("command", ""),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            transport="stdio",
            source_file=config_path,
            client="claude_desktop",
        ))
    return servers


def _parse_claude_code(data: dict[str, Any], config_path: str) -> list[MCPServerConfig]:
    """Parse Claude Code config: root ``mcpServers`` + per-project servers."""
    servers: list[MCPServerConfig] = []
    # Root level
    for name, cfg in data.get("mcpServers", {}).items():
        if not isinstance(cfg, dict):
            continue
        servers.append(MCPServerConfig(
            name=name,
            command=cfg.get("command", ""),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            source_file=config_path,
            client="claude_code",
        ))
    # Project level
    for project_path, project_cfg in data.get("projects", {}).items():
        if not isinstance(project_cfg, dict):
            continue
        for name, cfg in project_cfg.get("mcpServers", {}).items():
            if not isinstance(cfg, dict):
                continue
            servers.append(MCPServerConfig(
                name=f"{name} ({project_path})",
                command=cfg.get("command", ""),
                args=cfg.get("args", []),
                env=cfg.get("env", {}),
                source_file=config_path,
                client="claude_code",
            ))
    return servers


def _parse_cursor(data: dict[str, Any], config_path: str) -> list[MCPServerConfig]:
    """Parse Cursor MCP config: ``{mcpServers: {name: {command, args}}}``."""
    servers: list[MCPServerConfig] = []
    for name, cfg in data.get("mcpServers", {}).items():
        if not isinstance(cfg, dict):
            continue
        servers.append(MCPServerConfig(
            name=name,
            command=cfg.get("command", ""),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            source_file=config_path,
            client="cursor",
        ))
    return servers


def _parse_vscode(data: dict[str, Any], config_path: str) -> list[MCPServerConfig]:
    """Parse VS Code settings.json for MCP-related configurations."""
    servers: list[MCPServerConfig] = []
    for key in (
        "mcp.servers",
        "github.copilot.chat.mcp.servers",
        "mcp",
        "mcpServers",
    ):
        section = data.get(key, {})
        if isinstance(section, dict):
            for name, cfg in section.items():
                if isinstance(cfg, dict) and "command" in cfg:
                    servers.append(MCPServerConfig(
                        name=name,
                        command=cfg.get("command", ""),
                        args=cfg.get("args", []),
                        env=cfg.get("env", {}),
                        source_file=config_path,
                        client="vscode",
                    ))
    return servers


def _parse_generic_mcp_config(data: dict[str, Any], config_path: str) -> list[MCPServerConfig]:
    """Generic parser for configs with ``mcpServers`` / ``mcp_servers``."""
    servers: list[MCPServerConfig] = []
    section = data.get("mcpServers", data.get("mcp_servers", {}))
    if not isinstance(section, dict):
        return servers
    for name, cfg in section.items():
        if isinstance(cfg, dict):
            servers.append(MCPServerConfig(
                name=name,
                command=cfg.get("command", ""),
                args=cfg.get("args", []),
                env=cfg.get("env", {}),
                source_file=config_path,
                client=Path(config_path).parent.name,
            ))
    return servers


def _get_client_paths() -> list[dict[str, Any]]:
    """Return client definitions with config paths per platform.

    Paths use ``~`` for the home directory (expanded at scan time).
    """
    return [
        {
            "name": "claude_desktop",
            "display": "Claude Desktop",
            "paths": {
                "Darwin": "~/Library/Application Support/Claude/claude_desktop_config.json",
                "Linux": "~/.config/claude/claude_desktop_config.json",
                "Windows": "~\\AppData\\Roaming\\Claude\\claude_desktop_config.json",
            },
            "parser": _parse_claude_desktop,
        },
        {
            "name": "claude_code",
            "display": "Claude Code",
            "paths": {
                "Darwin": "~/.claude.json",
                "Linux": "~/.claude.json",
                "Windows": "~\\.claude.json",
            },
            "parser": _parse_claude_code,
            "extra_paths": [".mcp.json"],
        },
        {
            "name": "cursor",
            "display": "Cursor",
            "paths": {
                "Darwin": "~/.cursor/mcp.json",
                "Linux": "~/.cursor/mcp.json",
                "Windows": "~\\.cursor\\mcp.json",
            },
            "parser": _parse_cursor,
        },
        {
            "name": "vscode",
            "display": "VS Code",
            "paths": {
                "Darwin": "~/Library/Application Support/Code/User/settings.json",
                "Linux": "~/.config/Code/User/settings.json",
                "Windows": "~\\AppData\\Roaming\\Code\\User\\settings.json",
            },
            "parser": _parse_vscode,
        },
        {
            "name": "windsurf",
            "display": "Windsurf",
            "paths": {
                "Darwin": "~/.codeium/windsurf/mcp_config.json",
                "Linux": "~/.codeium/windsurf/mcp_config.json",
                "Windows": "~\\.codeium\\windsurf\\mcp_config.json",
            },
            "parser": _parse_generic_mcp_config,
        },
        {
            "name": "codex",
            "display": "Codex CLI",
            "paths": {
                "Darwin": "~/.codex/config.json",
                "Linux": "~/.codex/config.json",
                "Windows": "~\\.codex\\config.json",
            },
            "parser": _parse_generic_mcp_config,
        },
        {
            "name": "gemini_cli",
            "display": "Gemini CLI",
            "paths": {
                "Darwin": "~/.gemini/settings.json",
                "Linux": "~/.gemini/settings.json",
                "Windows": "~\\.gemini\\settings.json",
            },
            "parser": _parse_generic_mcp_config,
        },
        {
            "name": "kiro",
            "display": "Kiro",
            "paths": {
                "Darwin": "~/.kiro/mcp.json",
                "Linux": "~/.kiro/mcp.json",
                "Windows": "~\\.kiro\\mcp.json",
            },
            "parser": _parse_generic_mcp_config,
        },
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def discover_agents(
    scan_project_mcp: bool = True,
    project_dir: str = ".",
) -> DesktopBOM:
    """Discover all AI agents and MCP servers on this machine.

    Scans known client configuration paths for each supported platform.
    Optionally scans the current project directory for ``.mcp.json`` files.

    Returns a :class:`DesktopBOM` with all discovered agents and servers.
    """
    start = time.perf_counter()

    system = platform.system()
    agents: list[DesktopAgent] = []

    for client_def in _get_client_paths():
        path_template = client_def["paths"].get(system)
        if not path_template:
            continue

        config_path = Path(os.path.expanduser(path_template))

        if not config_path.exists():
            continue

        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        parser: ClientParser = client_def["parser"]
        servers = parser(data, str(config_path))

        if servers:
            agents.append(DesktopAgent(
                client_name=client_def["name"],
                display_name=client_def["display"],
                config_path=str(config_path),
                mcp_servers=servers,
            ))

    # Project-level .mcp.json
    if scan_project_mcp:
        project_mcp = Path(project_dir) / ".mcp.json"
        if project_mcp.exists():
            try:
                data = json.loads(project_mcp.read_text(encoding="utf-8"))
                servers = _parse_generic_mcp_config(data, str(project_mcp))
                if servers:
                    agents.append(DesktopAgent(
                        client_name="project_mcp",
                        display_name="Project MCP (.mcp.json)",
                        config_path=str(project_mcp),
                        mcp_servers=servers,
                    ))
            except (json.JSONDecodeError, OSError):
                pass

    # Compute totals
    all_servers = [s for a in agents for s in a.mcp_servers]
    elapsed = (time.perf_counter() - start) * 1000

    return DesktopBOM(
        agents=agents,
        total_mcp_servers=len(all_servers),
        total_with_filesystem=sum(1 for s in all_servers if s.has_filesystem_access),
        total_with_shell=sum(1 for s in all_servers if s.has_shell_access),
        total_with_network=sum(1 for s in all_servers if s.has_network_access),
        platform=f"{system} ({platform.machine()})",
        scan_duration_ms=elapsed,
    )
