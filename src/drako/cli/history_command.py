"""CLI command: drako history — show policy version history."""

from __future__ import annotations

import click

from drako.cli.push_command import _load_client


@click.command()
@click.option("--config", "-c", "config_path", default=None, help="Path to .drako.yaml")
@click.option("--limit", "-n", default=20, help="Number of versions to show")
def history(config_path: str | None, limit: int) -> None:
    """Show policy version history."""
    client = _load_client(config_path)
    if not client:
        return

    try:
        resp = client._request_sync(
            "GET",
            "/api/v1/policies/snapshots",
            params={"limit": limit, "offset": 0},
        )
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        return

    if not resp:
        click.echo("No policy versions found. Run `drako push` first.")
        return

    click.echo()
    click.secho("Policy Version History", bold=True)
    click.echo()

    for snap in resp:
        version = snap.get("version", "?")
        created = snap.get("created_at", "")[:16].replace("T", " ")
        summary = snap.get("change_summary", "—") or "—"
        # Truncate summary for display
        if len(summary) > 60:
            summary = summary[:57] + "..."
        click.echo(f"  v{version}  {created}  {summary}")

    click.echo()
    click.echo("View details: drako history       (already shown)")
    click.echo("Compare:      drako diff v1 v2    [requires Pro]")
    click.echo("Rollback:     drako rollback v1   [requires Pro]")
