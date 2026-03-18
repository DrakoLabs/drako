"""`drako verify` — Verify the integrity of the audit hash chain."""

from __future__ import annotations

import click

from drako.client import DrakoClient
from drako.config import DrakoConfig
from drako.exceptions import DrakoError, ConfigError


@click.command()
@click.option("--config", "config_path", default=".drako.yaml", help="Path to config file")
@click.option("--last-n", type=int, default=None, help="Only verify the last N entries")
def verify(config_path: str, last_n: int | None) -> None:
    """Verify the integrity of your audit hash chain."""

    click.echo()
    click.secho("  Drako — Audit Chain Verification", fg="cyan", bold=True)
    click.echo()

    try:
        config = DrakoConfig.load(config_path)
        api_key = config.resolve_api_key()
    except ConfigError as exc:
        click.echo(click.style("  [error]  ", fg="red") + str(exc))
        raise SystemExit(1)

    client = DrakoClient(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id)

    click.echo(click.style("  [verify] ", fg="green") + "Verifying audit chain...")

    try:
        result = client.verify_chain_sync(last_n=last_n)
    except DrakoError as exc:
        click.echo(click.style("  [error]  ", fg="red") + f"Verification failed: {exc}")
        raise SystemExit(1)

    if not isinstance(result, dict):
        click.echo(click.style("  [error]  ", fg="red") + "Unexpected response from server")
        raise SystemExit(1)

    is_valid = result.get("valid", False)
    entries = result.get("entries_checked", 0)
    chain_head = result.get("chain_head", "N/A")

    if is_valid:
        click.echo(click.style("  [verify] ", fg="green") + f"Chain is VALID ({entries} entries verified)")
        click.echo(f"           Chain head: {chain_head}")
    else:
        click.echo(click.style("  [verify] ", fg="red") + f"Chain is BROKEN ({entries} entries checked)")
        broken = result.get("broken_links", [])
        if broken:
            click.echo(f"           Broken links: {len(broken)}")
            for link in broken[:5]:
                click.echo(f"             - {link}")
        invalid_sigs = result.get("invalid_signatures", [])
        if invalid_sigs:
            click.echo(f"           Invalid signatures: {len(invalid_sigs)}")
        raise SystemExit(1)

    click.echo()
