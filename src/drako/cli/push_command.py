"""`drako push` — Upload local config to the Drako platform."""

from __future__ import annotations

from pathlib import Path

import click
import yaml

from drako.config import DrakoConfig
from drako.exceptions import ConfigError


_CONFIG_FILENAME = ".drako.yaml"


def _load_client(config_path: str | None = None) -> "DrakoClient | None":
    """Load config and return an authenticated DrakoClient, or None on error."""
    from drako.client import DrakoClient

    path = Path(config_path or _CONFIG_FILENAME)
    if not path.exists():
        click.secho(f"  [error]  {path} not found. Run 'drako init' first.", fg="red")
        return None

    try:
        config = DrakoConfig.load(str(path))
        api_key = config.resolve_api_key()
    except ConfigError as exc:
        click.secho(f"  [error]  {exc}", fg="red")
        return None

    return DrakoClient(
        api_key=api_key,
        endpoint=config.endpoint,
        tenant_id=config.tenant_id,
    )


@click.command()
@click.option("--config", "config_path", default=_CONFIG_FILENAME, help="Path to config file")
@click.option("--endpoint", default=None, help="Override endpoint from config")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def push(config_path: str, endpoint: str | None, yes: bool) -> None:
    """Upload your .drako.yaml config to the Drako platform."""

    click.echo()
    click.secho("  Drako Push", fg="cyan", bold=True)
    click.echo()

    # ---- Load config ----
    if not Path(config_path).exists():
        click.echo(click.style("  [error]  ", fg="red") + f"{config_path} not found. Run 'drako init' first.")
        raise SystemExit(1)

    try:
        config = DrakoConfig.load(config_path)
    except ConfigError as exc:
        click.echo(click.style("  [error]  ", fg="red") + str(exc))
        raise SystemExit(1)

    # ---- Resolve API key ----
    try:
        api_key = config.resolve_api_key()
    except ConfigError as exc:
        click.echo(click.style("  [error]  ", fg="red") + str(exc))
        raise SystemExit(1)

    base_url = (endpoint or config.endpoint).rstrip("/")

    # ---- Read raw YAML as dict (preserves all fields) ----
    try:
        with open(config_path) as f:
            raw_config = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        click.echo(click.style("  [error]  ", fg="red") + f"Invalid YAML: {exc}")
        raise SystemExit(1)

    # Remove api_key from the pushed config (security)
    raw_config.pop("api_key", None)

    # ---- Show summary ----
    n_agents = len(raw_config.get("agents", {}))
    n_tools = len(raw_config.get("tools", {}))
    dlp_mode = "off"
    dlp_section = raw_config.get("dlp")
    if isinstance(dlp_section, dict):
        dlp_mode = dlp_section.get("mode", "off")
    cb = "enabled" if raw_config.get("circuit_breaker") else "disabled"

    click.echo(click.style("  [config] ", fg="green") + f"Reading {config_path}...")
    click.echo(click.style("  [valid]  ", fg="green") + f"YAML valid │ {n_agents} agents │ {n_tools} tools │ DLP: {dlp_mode} │ CB: {cb}")

    # ---- Confirm ----
    if not yes:
        click.echo()
        if not click.confirm("  Push this config to Drako?", default=True):
            click.echo("  Aborted.")
            return

    # ---- Push ----
    click.echo(click.style("  [push]   ", fg="green") + f"Uploading to {base_url}...")

    try:
        import httpx

        with httpx.Client(timeout=15.0) as http:
            resp = http.post(
                f"{base_url}/api/v1/config/push",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"config": raw_config},
            )

        if resp.status_code == 401:
            click.secho("  [error]  Invalid API key.", fg="red")
            raise SystemExit(1)

        if resp.status_code == 422:
            detail = resp.json().get("detail", {})
            errors = detail.get("errors", [])
            click.secho("  [error]  Config validation failed:", fg="red")
            for e in errors:
                click.echo(f"           - {e}")
            raise SystemExit(1)

        if resp.status_code >= 400:
            click.secho(f"  [error]  Push failed: HTTP {resp.status_code}", fg="red")
            raise SystemExit(1)

        data = resp.json()
    except httpx.ConnectError:
        click.secho("  [error]  Could not connect to Drako backend.", fg="red")
        click.echo("           Scan CLI works offline. Push needs connectivity.")
        raise SystemExit(1)
    except httpx.ReadTimeout:
        click.secho("  [error]  Push timed out.", fg="red")
        raise SystemExit(1)

    # ---- Display result ----
    version = data.get("snapshot_version", "?")
    message = data.get("message")

    click.echo()
    if message:
        click.echo(click.style("  ✓ ", fg="green") + message)
    else:
        click.echo(click.style("  ✓ ", fg="green") + f"Config synced to Drako platform (snapshot v{version})")

    # Active features
    active = data.get("active_features", [])
    locked = data.get("locked_features", [])

    if active:
        click.echo()
        click.echo("  Active features:")
        for f in active:
            click.echo(click.style("    ✓ ", fg="green") + f)

    if locked:
        click.echo()
        click.echo("  Locked features (upgrade to unlock):")
        for f in locked:
            click.echo(click.style("    ✗ ", fg="yellow") + f)

    click.echo()
    click.echo("  Dashboard: " + click.style("https://app.useagentmesh.com/dashboard", fg="cyan", underline=True))
    click.echo()
