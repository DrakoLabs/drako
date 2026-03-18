"""CLI command: drako rollback — revert to a previous policy version."""

from __future__ import annotations

import click

from drako.cli.push_command import _load_client


@click.command()
@click.argument("version", type=int)
@click.option("--config", "-c", "config_path", default=None, help="Path to .drako.yaml")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def rollback(version: int, config_path: str | None, yes: bool) -> None:
    """Rollback to a previous policy version (requires Pro)."""
    client = _load_client(config_path)
    if not client:
        return

    if not yes:
        click.echo(f"Rolling back to v{version}...")
        if not click.confirm("This will create a new version with old content. Continue?"):
            click.echo("Aborted.")
            return

    try:
        resp = client._request_sync(
            "POST",
            "/api/v1/policies/snapshots/rollback",
            json={"version": version},
        )
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        return

    new_version = resp.get("version", "?")
    click.echo()
    click.secho(f"✓ Rolled back to v{version}. New version: v{new_version}", fg="green")
    click.secho("✓ Config pushed to platform", fg="green")
