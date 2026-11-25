"""`drako bom` — Extract Agent Bill of Materials from a project.

Standalone BOM extraction tool. No rules, no scoring, no governance
evaluation — just an inventory of agents, tools, models, and permissions.
"""

from __future__ import annotations

import time

import click


@click.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "markdown", "cyclonedx"]),
    default="text",
    help="Output format (default: text; cyclonedx emits CycloneDX 1.7)",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout",
)
def bom(directory: str, output_format: str, output: str | None) -> None:
    """Extract Agent Bill of Materials from your project.

    Analyzes the project at DIRECTORY (defaults to current directory)
    and outputs an inventory of agents, tools, models, MCP servers,
    prompts, permissions, and dependencies.

    No governance rules are evaluated — this is a pure inventory tool.
    """
    from drako.cli.bom import generate_bom
    from drako.cli.discovery import collect_project_files, detect_frameworks

    start = time.monotonic()

    # Phase 1: Collect project files & detect frameworks
    from pathlib import Path
    root = Path(directory).resolve()
    metadata = collect_project_files(root)
    metadata.frameworks = detect_frameworks(metadata)

    # Phase 2: Generate BOM
    agent_bom = generate_bom(metadata)

    duration_ms = int((time.monotonic() - start) * 1000)

    # Phase 3: Format output
    from drako.cli.formats.bom_fmt import (
        format_bom_json,
        format_bom_markdown,
        format_bom_text,
    )

    if output_format == "json":
        content = format_bom_json(agent_bom, metadata, duration_ms)
    elif output_format == "markdown":
        content = format_bom_markdown(agent_bom, metadata, duration_ms)
    elif output_format == "cyclonedx":
        import json as _json
        from datetime import datetime, timezone

        components = [
            {"type": "application", "bom-ref": f"agent:{a.name}", "name": a.name, "properties": [{"name": "drako:kind", "value": "agent"}]}
            for a in agent_bom.agents
        ] + [
            {"type": "library", "bom-ref": f"tool:{t.name}", "name": t.name, "properties": [{"name": "drako:kind", "value": "tool"}]}
            for t in agent_bom.tools
        ] + [
            {"type": "machine-learning-model", "bom-ref": f"model:{m.name}", "name": m.name}
            for m in agent_bom.models
        ]
        from drako import __version__ as _drako_version

        content = _json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "tools": [{"vendor": "DrakoLabs", "name": "drako-bom", "version": _drako_version}],
                },
                "components": components,
            },
            indent=2,
        )
    else:
        content = format_bom_text(agent_bom, metadata, duration_ms)

    # Phase 4: Output
    if output:
        from pathlib import Path as P
        P(output).write_text(content, encoding="utf-8")
        click.echo(f"BOM written to {output}")
    else:
        import sys
        try:
            click.echo(content)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(content.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")
