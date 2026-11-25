"""Output formatters for `drako bom` — text, JSON, and Markdown."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from io import StringIO
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


def format_bom_text(bom: AgentBOM, metadata: ProjectMetadata, duration_ms: int) -> str:
    """Render BOM as Rich terminal output to a string."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100, legacy_windows=True)

    framework_str = ", ".join(
        f"{fw.name} {fw.version or ''}" for fw in bom.frameworks
    ) if bom.frameworks else "No framework detected"

    # Header
    header = Text()
    header.append(f"{metadata.root.name}", style="bold cyan")
    header.append(f" | {framework_str}", style="white")
    header.append(f" | scanned in {duration_ms / 1000:.1f}s", style="dim")

    console.print(Panel(header, title="[bold]Agent BOM[/bold]", border_style="cyan"))
    console.print()

    # Summary table
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Component", style="bold", width=14)
    table.add_column("Count", style="cyan", width=6, justify="right")
    table.add_column("Details", style="white")

    agent_names = ", ".join(a.name for a in bom.agents[:6])
    if len(bom.agents) > 6:
        agent_names += ", ..."
    table.add_row("Agents", str(len(bom.agents)), agent_names or "none")

    tool_names = ", ".join(t.name for t in bom.tools[:6])
    if len(bom.tools) > 6:
        tool_names += ", ..."
    table.add_row("Tools", str(len(bom.tools)), tool_names or "none")

    model_names = ", ".join(m.name for m in bom.models[:5])
    table.add_row("Models", str(len(bom.models)), model_names or "none")

    mcp_str = ", ".join(bom.mcp_servers[:5]) if bom.mcp_servers else "none"
    table.add_row("MCP", str(len(bom.mcp_servers)), mcp_str)

    table.add_row("Prompts", str(len(bom.prompts)), "system prompts detected")
    table.add_row("Permissions", "", ", ".join(bom.permissions) if bom.permissions else "none")
    table.add_row("Framework", "", framework_str)

    console.print(table)

    # Dependencies
    if bom.dependencies:
        console.print()
        dep_strs = []
        for pkg, ver in sorted(bom.dependencies.items())[:15]:
            if ver:
                dep_strs.append(f"{pkg}=={ver}")
            else:
                dep_strs.append(pkg)
        console.print(f"[dim]Dependencies ({len(bom.dependencies)}): {', '.join(dep_strs)}[/dim]")
        if len(bom.dependencies) > 15:
            console.print(f"[dim]  ... and {len(bom.dependencies) - 15} more[/dim]")

    console.print()
    return buf.getvalue()


def format_bom_json(bom: AgentBOM, metadata: ProjectMetadata, duration_ms: int) -> str:
    """Serialize BOM to structured JSON."""
    from drako import __version__

    data = {
        "project": metadata.root.name,
        "framework": [
            {"name": fw.name, "version": fw.version, "confidence": fw.confidence}
            for fw in bom.frameworks
        ],
        "agents": [
            {
                "name": a.name,
                "source": a.file_path,
                "line": a.line_number,
                "framework": a.framework,
                "tools": a.tools,
                "model": a.model,
            }
            for a in bom.agents
        ],
        "tools": [
            {
                "name": t.name,
                "source": t.file_path,
                "line": t.line_number,
                "has_filesystem_access": t.has_filesystem_access,
                "has_network_access": t.has_network_access,
                "has_code_execution": t.has_code_execution,
            }
            for t in bom.tools
        ],
        "models": [
            {"name": m.name, "source": m.file_path, "line": m.line_number}
            for m in bom.models
        ],
        "mcp_servers": bom.mcp_servers,
        "prompts": [
            {
                "content_hash": "sha256:" + hashlib.sha256(
                    p.content_preview.encode()
                ).hexdigest()[:16],
                "source": p.file_path,
                "line": p.line_number,
            }
            for p in bom.prompts
        ],
        "permissions": bom.permissions,
        "dependencies": [
            {"name": pkg, "version": ver}
            for pkg, ver in sorted(bom.dependencies.items())
        ],
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "drako_version": __version__,
            "duration_ms": duration_ms,
            "files_scanned": len(metadata.python_files),
        },
    }

    return json.dumps(data, indent=2, default=str)


def format_bom_markdown(bom: AgentBOM, metadata: ProjectMetadata, duration_ms: int) -> str:
    """Render BOM as Markdown tables."""
    lines: list[str] = []
    lines.append(f"## Agent BOM — {metadata.root.name}\n")

    framework_str = ", ".join(
        f"{fw.name} {fw.version or ''}" for fw in bom.frameworks
    ) if bom.frameworks else "No framework detected"

    lines.append(f"**Framework**: {framework_str}  ")
    lines.append(f"**Scanned in**: {duration_ms / 1000:.1f}s\n")

    # Summary table
    lines.append("| Component | Count | Details |")
    lines.append("|-----------|------:|---------|")

    agent_names = ", ".join(a.name for a in bom.agents[:6])
    if len(bom.agents) > 6:
        agent_names += ", ..."
    lines.append(f"| Agents | {len(bom.agents)} | {agent_names or 'none'} |")

    tool_names = ", ".join(t.name for t in bom.tools[:6])
    if len(bom.tools) > 6:
        tool_names += ", ..."
    lines.append(f"| Tools | {len(bom.tools)} | {tool_names or 'none'} |")

    model_names = ", ".join(m.name for m in bom.models[:5])
    lines.append(f"| Models | {len(bom.models)} | {model_names or 'none'} |")

    lines.append(f"| MCP Servers | {len(bom.mcp_servers)} | {', '.join(bom.mcp_servers[:5]) or 'none'} |")
    lines.append(f"| Prompts | {len(bom.prompts)} | system prompts detected |")
    lines.append(f"| Permissions | — | {', '.join(bom.permissions) or 'none'} |")

    # Dependencies
    if bom.dependencies:
        lines.append("")
        lines.append(f"### Dependencies ({len(bom.dependencies)})")
        lines.append("")
        dep_strs = []
        for pkg, ver in sorted(bom.dependencies.items()):
            if ver:
                dep_strs.append(f"`{pkg}=={ver}`")
            else:
                dep_strs.append(f"`{pkg}`")
        lines.append(", ".join(dep_strs))

    lines.append("")
    return "\n".join(lines)
