"""CLI command: drako diff — compare two policy versions."""

from __future__ import annotations

import click

from drako.cli.push_command import _load_client


@click.command()
@click.argument("from_version", type=int)
@click.argument("to_version", type=int)
@click.option("--config", "-c", "config_path", default=None, help="Path to .drako.yaml")
def diff(from_version: int, to_version: int, config_path: str | None) -> None:
    """Compare two policy versions (requires Pro)."""
    client = _load_client(config_path)
    if not client:
        return

    try:
        resp = client._request_sync(
            "GET",
            "/api/v1/policies/snapshots/diff",
            params={"from": from_version, "to": to_version},
        )
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        return

    click.echo()
    click.secho(f"v{from_version} → v{to_version}", bold=True)
    click.echo()

    added = resp.get("added", [])
    removed = resp.get("removed", [])
    changed = resp.get("changed", [])

    for item in added:
        click.secho(f"  + {item['path']}: {_fmt(item.get('value'))}", fg="green")

    for item in removed:
        click.secho(f"  - {item['path']}: {_fmt(item.get('value'))}", fg="red")

    for item in changed:
        click.secho(
            f"  ~ {item['path']}: {_fmt(item.get('old'))} → {_fmt(item.get('new'))}",
            fg="yellow",
        )

    if not added and not removed and not changed:
        click.echo("  No differences found.")

    click.echo()


def _fmt(val: object) -> str:
    """Format a value for display, truncating long strings."""
    s = str(val)
    return s[:60] + "..." if len(s) > 60 else s
