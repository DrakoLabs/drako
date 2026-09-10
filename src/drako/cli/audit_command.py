"""`drako mcp audit` — audit configured MCP servers against lock+rules."""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.command(name="audit")
@click.option("--lock", "lock_path", default="mcp.lock",
              help="Lock file to cross-check (default: ./mcp.lock)")
@click.option("--project-dir", default=".",
              help="Project directory for .mcp.json discovery")
@click.option("--format", "output_format", default="text",
              type=click.Choice(["text", "json"]))
def audit(lock_path: str, project_dir: str, output_format: str) -> None:
    """Audit configured MCP servers (unpinned/unlisted/risky)."""
    from drako.desktop.discovery import discover_agents
    from drako.desktop.mcp_audit import audit_servers
    from drako.desktop.mcp_rules import evaluate_mcp_rules

    bom = discover_agents(project_dir=project_dir)
    servers = [s for agent in bom.agents for s in agent.mcp_servers]

    lock: dict = {}
    lock_file = Path(lock_path)
    if lock_file.exists():
        try:
            data = json.loads(lock_file.read_text(encoding="utf-8"))
            lock = data.get("servers", {}) or {}
        except (json.JSONDecodeError, OSError) as e:
            click.secho(f"  [error]  lock unreadable: {e}", fg="red")
            raise SystemExit(1)

    findings: dict[str, list[str]] = {}
    for finding in evaluate_mcp_rules(bom):
        findings.setdefault(finding.server_name, []).append(finding.rule_id)

    results = audit_servers(servers, lock=lock, rule_findings=findings)

    if output_format == "json":
        click.echo(json.dumps([
            {"name": r.name, "package": r.package,
             "source_file": r.source_file, "verdict": r.verdict,
             "details": r.details}
            for r in results
        ], indent=2))
    else:
        if not results:
            click.echo("  No MCP servers discovered.")
        for r in results:
            color = {"ok": "green", "unpinned": "yellow",
                     "unlisted": "yellow", "risky": "red"}[r.verdict]
            click.secho(f"  [{r.verdict}] {r.name} ({r.package or 'unknown'})",
                        fg=color)
            for d in r.details:
                click.echo(f"           - {d}")

    bad = [r for r in results if r.verdict != "ok"]
    if bad:
        raise SystemExit(1)
