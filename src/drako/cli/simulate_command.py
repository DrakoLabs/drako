"""`drako simulate` — Replay historical audit data against a proposed policy.

Sends the policy YAML to the Drako backend, which re-evaluates
recent audit log entries under the new rules and returns a diff summary
showing what *would* have changed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click


@click.command("simulate")
@click.option(
    "--policy",
    default=None,
    type=click.Path(dir_okay=False),
    help="Path to .drako.yaml policy file (default: auto-detect in current directory).",
)
@click.option(
    "--hours",
    default=24,
    type=int,
    show_default=True,
    help="Number of hours of historical data to replay.",
)
@click.option(
    "--api-key",
    envvar="DRAKO_API_KEY",
    default=None,
    help="API key for authentication (env: DRAKO_API_KEY).",
)
@click.option(
    "--endpoint",
    default="https://api.getdrako.com",
    envvar="DRAKO_ENDPOINT",
    show_default=True,
    help="Drako backend endpoint.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    show_default=True,
    help="Output format.",
)
def simulate(
    policy: str | None,
    hours: int,
    api_key: str | None,
    endpoint: str,
    output_format: str,
) -> None:
    """Simulate a policy change against historical audit data.

    Replays the last --hours of audit log entries through the proposed
    policy and reports which decisions would change (blocked, escalated,
    modified, or allowed).
    """
    import httpx

    # ---- Resolve the policy file ----
    if policy is None:
        from drako.cli._helpers import find_config

        found = find_config()
        if found is None:
            click.echo()
            click.secho("  No .drako.yaml found.", fg="yellow")
            click.echo(
                "  Run " + click.style("drako init", fg="cyan") + " to create one."
            )
            click.echo(
                "  Or:  "
                + click.style("drako simulate --policy path/to/.drako.yaml", fg="cyan")
            )
            click.echo()
            sys.exit(1)
        policy = str(found)

    policy_path = Path(policy)
    if not policy_path.exists():
        click.secho(f"  [error]  Policy file not found: {policy}", fg="red")
        sys.exit(1)
    try:
        policy_yaml = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        click.secho(f"  [error]  Could not read policy file: {exc}", fg="red")
        sys.exit(1)

    # ---- Build request ----
    url = f"{endpoint.rstrip('/')}/api/v1/simulate"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    body = {
        "policy_yaml": policy_yaml,
        "hours": hours,
    }

    # ---- Call backend ----
    try:
        with httpx.Client(timeout=60) as client:
            resp = client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        detail = ""
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            detail = exc.response.text[:200]

        if status == 401:
            click.secho("  [error]  Authentication failed. Check your --api-key.", fg="red")
        elif status == 400:
            click.secho(f"  [error]  Bad request: {detail}", fg="red")
        else:
            click.secho(f"  [error]  Server returned HTTP {status}: {detail}", fg="red")
        sys.exit(1)
    except httpx.ConnectError:
        click.secho("  [error]  Could not connect to Drako backend.", fg="red")
        click.echo("           Try: --endpoint http://localhost:8000")
        sys.exit(1)
    except httpx.ReadTimeout:
        click.secho("  [error]  Request timed out.", fg="red")
        sys.exit(1)

    # ---- Output ----
    if output_format == "json":
        click.echo(json.dumps(data, indent=2))
        return

    _render_terminal(data, hours)


def _render_terminal(data: dict, hours: int) -> None:
    """Render simulation results as Rich tables in the terminal."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    total = data.get("total_replayed", 0)
    if total == 0:
        console.print(
            f"\n[yellow]No historical audit data found for the last {hours} hour(s).[/yellow]\n"
        )
        return

    # ---- Summary table ----
    summary_table = Table(
        title=f"Simulation Summary (last {hours}h)",
        show_header=True,
        header_style="bold cyan",
    )
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Count", justify="right")

    summary_table.add_row("Total replayed", str(total))
    summary_table.add_row("Blocked", str(data.get("blocked", 0)))
    summary_table.add_row("Escalated", str(data.get("escalated", 0)))
    summary_table.add_row("Modified", str(data.get("modified", 0)))
    summary_table.add_row("Allowed", str(data.get("allowed", 0)))

    console.print()
    console.print(summary_table)

    # ---- Blocked breakdown ----
    breakdown = data.get("blocked_breakdown", [])
    if breakdown:
        bd_table = Table(
            title="Blocked Breakdown",
            show_header=True,
            header_style="bold red",
        )
        bd_table.add_column("Reason", style="bold")
        bd_table.add_column("Count", justify="right")
        bd_table.add_column("Example Transaction ID")

        for entry in breakdown:
            bd_table.add_row(
                entry.get("reason", "unknown"),
                str(entry.get("count", 0)),
                entry.get("example_transaction_id", "-"),
            )

        console.print()
        console.print(bd_table)

    console.print()
