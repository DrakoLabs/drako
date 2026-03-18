"""`drako upgrade` — Upgrade governance level of existing config.

Adjusts the governance_level in .drako.yaml from autopilot/balanced
to a stricter enforcement posture.
"""

from __future__ import annotations

from pathlib import Path

import click
import yaml

_CONFIG_FILENAME = ".drako.yaml"


@click.command()
@click.option("--balanced", "level", flag_value="balanced",
              help="Enable enforcement with escape hatches")
@click.option("--strict", "level", flag_value="strict",
              help="Maximum governance for enterprise")
@click.option("--config", "config_path", default=_CONFIG_FILENAME,
              help="Path to config file")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def upgrade(level: str | None, config_path: str, yes: bool) -> None:
    """Upgrade governance enforcement level."""

    click.echo()
    click.secho("  Drako Upgrade", fg="cyan", bold=True)
    click.echo()

    if not level:
        click.echo("  Choose a governance level:")
        click.echo()
        click.echo("    " + click.style("--balanced", fg="yellow") + "  DLP enforce, ODD enforce, HITL reject on timeout")
        click.echo("    " + click.style("--strict", fg="red") + "    Everything enforced + intent verification + crypto audit")
        click.echo()
        click.echo("  Usage: " + click.style("drako upgrade --balanced", fg="cyan"))
        return

    # Load existing config
    path = Path(config_path)
    if not path.exists():
        click.secho(f"  [error]  {config_path} not found. Run 'drako init' first.", fg="red")
        raise SystemExit(1)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        click.secho(f"  [error]  Invalid YAML: {exc}", fg="red")
        raise SystemExit(1)

    current_level = raw.get("governance_level", "custom")
    click.echo(click.style("  [config] ", fg="green") + f"Current level: {current_level}")
    click.echo(click.style("  [config] ", fg="green") + f"Target level:  {level}")

    # Show what will change
    click.echo()
    click.secho("  Changes:", fg="white", bold=True)

    if level == "balanced":
        changes = [
            ("DLP", "audit -> enforce", "Blocks critical PII"),
            ("ODD", "audit -> enforce", "Blocks unauthorized tools"),
            ("HITL", "timeout: allow -> reject", "No-response = block"),
        ]
    else:  # strict
        changes = [
            ("DLP", "-> enforce", "Blocks all PII"),
            ("ODD", "-> enforce", "Blocks unauthorized tools"),
            ("HITL", "-> enforce + reject", "Mandatory human approval"),
            ("Intent", "-> enforce + anti-replay", "Cryptographic intent verification"),
            ("Audit", "-> cryptographic + 90-day retention", "Tamper-proof audit trail"),
            ("Magnitude", "-> enforce", "Hard spending limits"),
        ]

    for name, change, desc in changes:
        click.echo(f"    {name:12s} {change:30s} {desc}")

    # Confirm
    if not yes:
        click.echo()
        if not click.confirm(f"  Upgrade to {level}?", default=True):
            click.echo("  Aborted.")
            return

    # Apply changes
    raw["governance_level"] = level

    if level == "balanced":
        # DLP: enforce
        if "dlp" not in raw:
            raw["dlp"] = {}
        raw["dlp"]["mode"] = "enforce"

        # ODD: enforce
        if "odd" in raw and isinstance(raw["odd"], dict):
            raw["odd"]["enforcement_mode"] = "enforce"

        # HITL: reject on timeout
        if "hitl" in raw and isinstance(raw["hitl"], dict):
            raw["hitl"]["timeout_action"] = "reject"
            if raw["hitl"].get("mode") == "audit":
                raw["hitl"]["mode"] = "enforce"

    elif level == "strict":
        # DLP enforce
        if "dlp" not in raw:
            raw["dlp"] = {}
        raw["dlp"]["mode"] = "enforce"

        # ODD enforce
        if "odd" in raw and isinstance(raw["odd"], dict):
            raw["odd"]["enforcement_mode"] = "enforce"

        # HITL enforce + reject
        if "hitl" not in raw:
            raw["hitl"] = {"triggers": {"tool_types": ["write", "execute", "payment"]}}
        raw["hitl"]["mode"] = "enforce"
        raw["hitl"]["timeout_action"] = "reject"

        # Intent verification
        if "intent_verification" not in raw:
            raw["intent_verification"] = {}
        raw["intent_verification"]["mode"] = "enforce"
        raw["intent_verification"]["anti_replay"] = True

        # Audit cryptographic
        if "audit" not in raw:
            raw["audit"] = {}
        raw["audit"]["enabled"] = True
        raw["audit"]["cryptographic"] = True
        raw["audit"]["retention_days"] = 90

        # Magnitude enforce
        if "magnitude" in raw and isinstance(raw["magnitude"], dict):
            raw["magnitude"]["enforcement_mode"] = "enforce"

    # Preserve comments by reading original and replacing the YAML body
    # For simplicity, write clean YAML with a header comment
    header = f"# Drako Configuration - governance_level: {level}\n"
    header += "# Upgraded with: drako upgrade --" + level + "\n"
    header += "# Docs: https://docs.useagentmesh.com/config\n\n"

    yaml_body = yaml.dump(raw, default_flow_style=False, sort_keys=False, allow_unicode=True)
    path.write_text(header + yaml_body, encoding="utf-8")

    click.echo()
    click.echo(click.style("  [ok] ", fg="green") + f"Upgraded to {level}!")
    click.echo()

    # Offer to push
    click.echo("  Run: " + click.style("drako push", fg="cyan") + "  to sync changes to platform")
    click.echo("  Run: " + click.style("drako status", fg="cyan") + " to verify configuration")
    click.echo()
