"""``drako desktop`` — Desktop agent discovery, scanning, and governance.

Commands::

    drako desktop scan      Discover and scan all desktop AI agents
    drako desktop govern    Scan + activate runtime protection
    drako desktop bom       Export desktop Agent BOM
"""

from __future__ import annotations

import json
import sys

import click

from drako.desktop.discovery import DesktopBOM, discover_agents
from drako.desktop.mcp_rules import MCPFinding, evaluate_mcp_rules


@click.group()
def desktop() -> None:
    """Discover, scan, and govern AI agents on your desktop."""


# ---------------------------------------------------------------------------
# drako desktop scan
# ---------------------------------------------------------------------------


@desktop.command()
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Exit code 1 if findings at this severity or above.",
)
@click.option(
    "--project-dir",
    default=".",
    help="Also scan project .mcp.json in this directory.",
)
def scan(fmt: str, fail_on: str | None, project_dir: str) -> None:
    """Discover all desktop AI agents and scan for security issues."""
    bom = discover_agents(project_dir=project_dir)

    if bom.total_mcp_servers == 0:
        click.echo("\n  No MCP servers found on this machine.")
        click.echo("  Drako scans configs for: Claude Desktop, Cursor, VS Code,")
        click.echo("  Windsurf, Claude Code, Codex, Gemini CLI, Kiro.\n")
        sys.exit(0)

    findings = evaluate_mcp_rules(bom)
    score = _compute_desktop_score(findings)
    grade = _score_to_grade(score)

    if fmt == "json":
        _output_json(bom, findings, score, grade)
    elif fmt == "sarif":
        _output_sarif(bom, findings)
    else:
        _output_text(bom, findings, score, grade)

    if fail_on:
        severity_order = ["low", "medium", "high", "critical"]
        threshold = severity_order.index(fail_on)
        for f in findings:
            if severity_order.index(f.severity.lower()) >= threshold:
                sys.exit(1)


# ---------------------------------------------------------------------------
# drako desktop bom
# ---------------------------------------------------------------------------


@desktop.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Exit code 1 if any finding meets or exceeds this severity.",
)
def skills(directory: str, fmt: str, fail_on: str | None) -> None:
    """Scan SKILL.md, CLAUDE.md, AGENTS.md, .cursor/rules, and settings for poisoning (INST-001..005)."""
    from drako.desktop.instruction_rules import scan_instruction_files

    files, findings = scan_instruction_files(directory)
    if fmt == "json":
        click.echo(
            json.dumps(
                {
                    "scanned_files": [str(f) for f in files],
                    "finding_count": len(findings),
                    "findings": [
                        {
                            "rule_id": f.rule_id,
                            "severity": f.severity,
                            "owasp_asi": f.owasp_asi,
                            "file_path": f.file_path,
                            "line_number": f.line_number,
                            "title": f.title,
                            "message": f.message,
                            "snippet": f.snippet,
                        }
                        for f in findings
                    ],
                },
                indent=2,
            )
        )
    else:
        click.echo()
        click.secho("  Drako Instruction & Skill File Scan (INST-001..005)", fg="cyan", bold=True)
        click.echo(f"  Scanned {len(files)} instruction file(s) in {directory}")
        if not findings:
            click.secho("  [clean]  No poisoning or supply-chain issues found.", fg="green")
        for f in findings:
            color = "red" if f.severity in ("CRITICAL", "HIGH") else "yellow"
            click.echo(
                click.style(f"  [{f.severity:8s}] ", fg=color)
                + f"{f.rule_id} ({f.owasp_asi}) {f.title} — {f.file_path}:{f.line_number}"
            )
            if f.snippet:
                click.echo(f"             {f.snippet}")
        click.echo()

    if fail_on and findings:
        order = ["low", "medium", "high", "critical"]
        thresh = order.index(fail_on.lower())
        if any(order.index(f.severity.lower()) >= thresh for f in findings):
            sys.exit(1)


@desktop.command()
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json", "markdown"]),
    default="text",
    help="Output format.",
)
def bom(fmt: str) -> None:
    """Export a Bill of Materials for all desktop AI agents."""
    desktop_bom = discover_agents()

    if fmt == "json":
        _output_bom_json(desktop_bom)
    elif fmt == "markdown":
        _output_bom_markdown(desktop_bom)
    else:
        _output_bom_text(desktop_bom)


# ---------------------------------------------------------------------------
# drako desktop govern
# ---------------------------------------------------------------------------


@desktop.command()
@click.option("--port", default=8990, help="Proxy port.")
@click.option("--project-dir", default=".", help="Project directory for .drako.yaml.")
def govern(port: int, project_dir: str) -> None:
    """Scan desktop agents + activate runtime protection via proxy.

    \b
    This command:
    1. Discovers all MCP servers on your machine
    2. Scans them for security issues
    3. Starts the Drako proxy to intercept and govern MCP traffic
    4. Applies ODD, DLP, and circuit breaker policies automatically
    """
    bom = discover_agents(project_dir=project_dir)
    findings = evaluate_mcp_rules(bom)
    score = _compute_desktop_score(findings)

    _output_text(bom, findings, score, _score_to_grade(score))

    if bom.total_mcp_servers == 0:
        return

    risky = [
        s for a in bom.agents for s in a.mcp_servers
        if s.has_shell_access or s.has_filesystem_access
    ]

    click.echo(f"\n  Activating governance for {len(risky)} risky servers:")
    for s in risky:
        perms: list[str] = []
        if s.has_filesystem_access:
            perms.append("fs")
        if s.has_shell_access:
            perms.append("exec")
        if s.has_network_access:
            perms.append("net")
        click.echo(f"    {s.name} ({s.client}) — [{', '.join(perms)}]")

    click.echo(f"\n  Starting Drako proxy on port {port}...")
    click.echo("  MCP traffic will be intercepted and governed.")
    click.echo("  Press Ctrl+C to stop.\n")

    try:
        from drako.proxy.proxy_server import run_server
        run_server(port=port)
    except ImportError:
        click.echo("  Proxy module not available. Install: pip install drako[proxy]")
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\n  Proxy stopped. Governance session ended.")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

_SEVERITY_DEDUCTIONS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def _compute_desktop_score(findings: list[MCPFinding]) -> int:
    """Compute governance score for desktop configuration (0-100)."""
    total = sum(_SEVERITY_DEDUCTIONS.get(f.severity, 0) for f in findings)
    return max(0, 100 - total)


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def _output_text(
    bom: DesktopBOM,
    findings: list[MCPFinding],
    score: int,
    grade: str,
) -> None:
    click.echo()
    click.echo("  Drako Desktop Scan")
    click.echo(f"  Platform: {bom.platform}")
    click.echo(f"  Scan time: {bom.scan_duration_ms:.0f}ms")
    click.echo()

    for agent in bom.agents:
        click.echo(f"  {agent.display_name} ({agent.config_path})")
        for server in agent.mcp_servers:
            perms: list[str] = []
            if server.has_filesystem_access:
                perms.append("fs")
            if server.has_shell_access:
                perms.append("exec")
            if server.has_network_access:
                perms.append("net")
            perm_str = f" [{', '.join(perms)}]" if perms else ""
            click.echo(f"    {server.name}: {server.package_name}{perm_str}")

    click.echo()
    click.echo(f"  DESKTOP GOVERNANCE SCORE: {score}/100 [{grade}]")
    click.echo(
        f"  MCP Servers: {bom.total_mcp_servers} total, "
        f"{bom.total_with_shell} with exec, "
        f"{bom.total_with_filesystem} with filesystem"
    )
    click.echo()

    if not findings:
        click.echo("  No issues found.")
        return

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sev_findings = [f for f in findings if f.severity == severity]
        if not sev_findings:
            continue
        click.echo(f"  {severity} ({len(sev_findings)}):")
        for f in sev_findings:
            click.echo(f"    {f.rule_id} {f.title}")
            click.echo(f"      {f.server_name} ({f.client})")
            click.echo(f"      Fix: {f.remediation[:80]}")
            click.echo()

    click.echo("  Next steps:")
    click.echo("    drako desktop govern    Activate runtime protection")
    click.echo("    drako desktop bom       Export desktop Agent BOM")
    click.echo()


def _output_json(
    bom: DesktopBOM,
    findings: list[MCPFinding],
    score: int,
    grade: str,
) -> None:
    output = {
        "platform": bom.platform,
        "scan_duration_ms": bom.scan_duration_ms,
        "desktop_governance_score": score,
        "grade": grade,
        "agents": [
            {
                "client": a.client_name,
                "display_name": a.display_name,
                "config_path": a.config_path,
                "mcp_servers": [
                    {
                        "name": s.name,
                        "package": s.package_name,
                        "command": s.command,
                        "args": s.args,
                        "transport": s.transport,
                        "has_filesystem": s.has_filesystem_access,
                        "has_shell": s.has_shell_access,
                        "has_network": s.has_network_access,
                    }
                    for s in a.mcp_servers
                ],
            }
            for a in bom.agents
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "server_name": f.server_name,
                "client": f.client,
                "config_file": f.config_file,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "summary": {
            "total_mcp_servers": bom.total_mcp_servers,
            "with_filesystem": bom.total_with_filesystem,
            "with_shell": bom.total_with_shell,
            "with_network": bom.total_with_network,
        },
    }
    click.echo(json.dumps(output, indent=2))


def _output_sarif(bom: DesktopBOM, findings: list[MCPFinding]) -> None:
    """SARIF 2.1.0 output for CI/CD integration."""
    from drako import __version__ as drako_version

    sarif = {
        "$schema": (
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
            "errata01/os/schemas/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "drako-desktop",
                        "informationUri": "https://github.com/DrakoLabs/drako",
                        "version": drako_version,
                        "rules": [
                            {
                                "id": f"MCP-{i:03d}",
                                "shortDescription": {"text": f"MCP rule {i}"},
                            }
                            for i in range(1, 9)
                        ],
                    },
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": {
                            "CRITICAL": "error",
                            "HIGH": "error",
                            "MEDIUM": "warning",
                            "LOW": "note",
                        }.get(f.severity, "warning"),
                        "message": {"text": f.description},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f.config_file,
                                    },
                                },
                            },
                        ],
                    }
                    for f in findings
                ],
            },
        ],
    }
    click.echo(json.dumps(sarif, indent=2))


# ---------------------------------------------------------------------------
# BOM formatters
# ---------------------------------------------------------------------------


def _output_bom_json(bom: DesktopBOM) -> None:
    click.echo(json.dumps(
        {
            "platform": bom.platform,
            "agents": [
                {
                    "client": a.client_name,
                    "mcp_servers": [
                        {
                            "name": s.name,
                            "package": s.package_name,
                            "filesystem": s.has_filesystem_access,
                            "shell": s.has_shell_access,
                            "network": s.has_network_access,
                        }
                        for s in a.mcp_servers
                    ],
                }
                for a in bom.agents
            ],
            "total_servers": bom.total_mcp_servers,
        },
        indent=2,
    ))


def _output_bom_text(bom: DesktopBOM) -> None:
    click.echo(f"\n  Desktop Agent BOM — {bom.platform}\n")
    for agent in bom.agents:
        click.echo(f"  {agent.display_name}")
        for s in agent.mcp_servers:
            click.echo(f"    {s.name}: {s.package_name}")
    click.echo(f"\n  Total: {bom.total_mcp_servers} MCP servers\n")


def _output_bom_markdown(bom: DesktopBOM) -> None:
    click.echo("# Desktop Agent BOM\n")
    click.echo(f"Platform: {bom.platform}\n")
    click.echo("| Client | Server | Package | FS | Exec | Net |")
    click.echo("|--------|--------|---------|:--:|:----:|:---:|")
    for agent in bom.agents:
        for s in agent.mcp_servers:
            fs = "Yes" if s.has_filesystem_access else "-"
            sh = "Yes" if s.has_shell_access else "-"
            net = "Yes" if s.has_network_access else "-"
            click.echo(
                f"| {agent.display_name} | {s.name} | "
                f"{s.package_name} | {fs} | {sh} | {net} |"
            )
    click.echo(f"\nTotal: {bom.total_mcp_servers} servers")
