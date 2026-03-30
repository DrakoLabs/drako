"""Shared CLI helpers — config resolution and version parsing."""
from __future__ import annotations

import sys
from pathlib import Path

import click

from drako.cli.push_command import _load_client as _raw_load_client

_CONFIG_FILENAME = ".drako.yaml"


def find_config(start: str | None = None) -> Path | None:
    """Search for .drako.yaml in cwd and up to 3 parent directories."""
    cwd = Path(start).resolve() if start else Path.cwd().resolve()
    for d in [cwd, *list(cwd.parents)[:3]]:
        candidate = d / _CONFIG_FILENAME
        if candidate.exists():
            return candidate
    return None


def require_config(config_path: str | None) -> str:
    """Resolve config path or exit with a friendly message."""
    if config_path:
        p = Path(config_path)
        if p.exists():
            return str(p)
        click.secho(f"  [error]  Config file not found: {config_path}", fg="red")
        raise SystemExit(1)

    found = find_config()
    if found:
        return str(found)

    click.echo()
    click.secho("  No .drako.yaml found.", fg="yellow")
    click.echo("  Run " + click.style("drako init", fg="cyan") + " to set up Drako for this project.")
    click.echo()
    raise SystemExit(1)


def load_client_safe(config_path: str | None):
    """Load DrakoClient, resolving config first (never passes None)."""
    resolved = require_config(config_path)
    return _raw_load_client(resolved)


def parse_version(value: str) -> int:
    """Accept 'v3', 'V3', or '3' as version input."""
    cleaned = value.strip().lower().lstrip("v")
    try:
        return int(cleaned)
    except ValueError:
        raise click.BadParameter(
            f"'{value}' is not a valid version. Use a number like 3 or v3."
        )
