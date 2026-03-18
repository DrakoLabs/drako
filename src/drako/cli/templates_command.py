"""`drako templates` — List and inspect policy templates."""

from __future__ import annotations

import click
import yaml


@click.group()
def templates() -> None:
    """Manage policy templates."""


@templates.command("list")
def list_templates() -> None:
    """List available policy templates."""
    from drako.templates import list_templates as _list

    click.echo()
    click.secho("  Available Policy Templates", fg="cyan", bold=True)
    click.echo()

    for t in _list():
        level_color = {
            "strict": "red",
            "balanced": "yellow",
            "autopilot": "green",
        }.get(t["governance_level"], "white")

        click.echo(
            f"    {click.style(t['name'], fg='white', bold=True):20s}"
            f"  {click.style(t['governance_level'], fg=level_color):12s}"
            f"  {t['description']}"
        )

    click.echo()
    click.echo("  Usage: " + click.style("drako init --template fintech", fg="cyan"))
    click.echo("     or: " + click.style('extends: fintech', fg="cyan") + "  in .drako.yaml")
    click.echo()


@templates.command("show")
@click.argument("name")
def show_template(name: str) -> None:
    """Show the contents of a policy template."""
    from drako.templates import load_template

    try:
        data = load_template(name)
    except Exception as exc:
        click.secho(f"  [error]  {exc}", fg="red")
        raise SystemExit(1)

    click.echo()
    click.secho(f"  Template: {name}", fg="cyan", bold=True)
    click.echo()
    click.echo(yaml.dump(data, default_flow_style=False, sort_keys=False))
