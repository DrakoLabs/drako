"""`drako status` — Show project & connection status."""

from __future__ import annotations

from pathlib import Path

import click

from drako.config import DrakoConfig
from drako.exceptions import DrakoError, ConfigError


@click.command()
@click.option("--config", "config_path", default=".drako.yaml", help="Path to config file")
def status(config_path: str) -> None:
    """Show the status of your Drako integration."""

    click.echo()
    click.secho("  Drako Status", fg="cyan", bold=True)
    click.echo()

    # ---- Config file ----
    if not Path(config_path).exists():
        click.echo(click.style("  [config] ", fg="red") + f"{config_path} not found. Run 'drako init' first.")
        raise SystemExit(1)

    try:
        config = DrakoConfig.load(config_path)
    except ConfigError as exc:
        click.echo(click.style("  [config] ", fg="red") + str(exc))
        raise SystemExit(1)

    click.echo(click.style("  [config] ", fg="green") + f"Config loaded from {config_path}")
    click.echo(f"           Tenant:    {config.tenant_id}")
    click.echo(f"           Framework: {config.framework}")
    click.echo(f"           Endpoint:  {config.endpoint}")

    # ---- API key ----
    try:
        api_key = config.resolve_api_key()
        masked = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "****"
        click.echo(click.style("  [auth]   ", fg="green") + f"API key: {masked}")
    except ConfigError as exc:
        click.echo(click.style("  [auth]   ", fg="red") + str(exc))
        raise SystemExit(1)

    # ---- Connectivity ----
    click.echo(click.style("  [conn]   ", fg="green") + "Testing connection...")
    try:
        from drako.client import DrakoClient

        client = DrakoClient(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id)
        result = client.validate_key_sync()
        click.echo(click.style("  [conn]   ", fg="green") + "Connected to Drako backend")

        # Show stats if available
        if isinstance(result, dict):
            for key in ("total_agents", "active_tasks", "avg_trust_score"):
                if key in result:
                    label = key.replace("_", " ").title()
                    click.echo(f"           {label}: {result[key]}")
    except DrakoError as exc:
        click.echo(click.style("  [conn]   ", fg="red") + f"Connection failed: {exc}")
        raise SystemExit(1)
    except Exception as exc:
        click.echo(click.style("  [conn]   ", fg="red") + f"Connection failed: {exc}")
        raise SystemExit(1)

    # ---- Quota ----
    try:
        quota = client.check_quota_sync()
        if isinstance(quota, dict):
            plan = quota.get("plan", "free")
            used = quota.get("used_this_period", 0)
            limit = quota.get("monthly_quota", 10000)
            click.echo(click.style("  [quota]  ", fg="green") + f"Plan: {plan} | Usage: {used}/{limit}")
    except DrakoError:
        click.echo(click.style("  [quota]  ", fg="yellow") + "Could not fetch quota info")

    # ---- Scan info ----
    from drako.cli.scan_cache import load_scan_cache

    scan_data = load_scan_cache(".", max_age_seconds=86400)  # 24h for status display
    if scan_data:
        score = scan_data.get("score", "?")
        grade = scan_data.get("grade", "?")
        n_agents = len(scan_data.get("agents", []))
        n_tools = len(scan_data.get("tools", []))
        findings = scan_data.get("findings_summary", {})
        critical = findings.get("critical", 0)
        high = findings.get("high", 0)
        click.echo(click.style("  [scan]   ", fg="green") + f"Last scan: {score}/100 [{grade}] │ {n_agents} agents │ {n_tools} tools")
        if critical or high:
            click.echo(f"           {critical} critical │ {high} high findings")
    else:
        click.echo(click.style("  [scan]   ", fg="yellow") + "No recent scan. Run: drako scan .")

    # ---- Governance features from config ----
    _show_governance(config_path)

    # ---- Last push info ----
    try:
        import httpx
        with httpx.Client(timeout=5.0) as http:
            resp = http.get(
                f"{config.endpoint.rstrip('/')}/api/v1/config/current",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code == 200:
            data = resp.json()
            version = data.get("version")
            pushed_at = data.get("pushed_at")
            if version:
                click.echo(click.style("  [push]   ", fg="green") + f"Config v{version} (pushed {pushed_at or '?'})")

                active = data.get("active_features", [])
                locked = data.get("locked_features", [])
                if active:
                    for f in active:
                        click.echo(f"           ✓ {f}")
                if locked:
                    for f in locked:
                        click.echo(click.style(f"           ✗ {f}", fg="yellow"))
            else:
                click.echo(click.style("  [push]   ", fg="yellow") + "No config pushed yet. Run: drako push")
    except Exception:
        pass  # Non-critical

    click.echo()
    click.secho("  All checks passed.", fg="green", bold=True)
    click.echo()


def _show_governance(config_path: str) -> None:
    """Show governance feature status from the local YAML."""
    import yaml

    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    except Exception:
        return

    features = []
    dlp = raw.get("dlp")
    if isinstance(dlp, dict) and dlp.get("mode", "off") != "off":
        features.append(f"DLP: {dlp['mode']} mode")

    cb = raw.get("circuit_breaker")
    if isinstance(cb, dict):
        threshold = cb.get("agent_level", {}).get("failure_threshold", "?")
        features.append(f"Circuit Breaker: threshold {threshold}")

    audit = raw.get("audit")
    if isinstance(audit, dict) and audit.get("enabled", False):
        features.append("Audit Trail: enabled")

    if features:
        click.echo(click.style("  [gov]    ", fg="green") + " │ ".join(features))
