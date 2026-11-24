"""`drako upgrade` — Upgrade .drako.yaml posture or migrate v3 configs to v4.

Supports:
  drako upgrade --v4         Idempotent migration from v3 (SaaS) to v4 (local-first)
  drako upgrade --balanced   Enforce-by-default posture with consent gates
  drako upgrade --strict     Maximum fail-closed posture
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click
import yaml

_CONFIG_FILENAME = ".drako.yaml"
_SAAS_REMOVED_KEYS = ("api_key", "api_key_env", "endpoint", "governance", "bft", "chaos", "topology")


def migrate_v3_to_v4_dict(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Idempotently migrate a v3 config mapping to v4 local-first schema."""
    migrated = dict(raw)
    notes: list[str] = []

    if str(migrated.get("version", "")) != "4.0":
        migrated["version"] = "4.0"
        notes.append("Set version: 4.0")

    if "project_id" not in migrated:
        migrated["project_id"] = str(migrated.get("tenant_id") or "default")
        notes.append(f"Set project_id: {migrated['project_id']}")

    for key in _SAAS_REMOVED_KEYS:
        if key in migrated:
            migrated.pop(key, None)
            notes.append(f"Removed deprecated v3 SaaS field: {key}")

    if "kernel" not in migrated or not isinstance(migrated.get("kernel"), dict):
        level = str(migrated.get("governance_level", "balanced"))
        migrated["kernel"] = {
            "spec_pin": "AGENT-HOOKS-0.1",
            "default_effect": "deny" if level != "autopilot" else "permit",
            "receipt_store": ".drako/receipts.jsonl",
            "tiers": {
                "read": "auto",
                "write": "audit",
                "external_comms": "audit",
                "irreversible": "consent",
            },
        }
        notes.append("Added kernel block (spec_pin: AGENT-HOOKS-0.1, fail-closed)")
    elif "spec_pin" not in migrated["kernel"]:
        migrated["kernel"]["spec_pin"] = "AGENT-HOOKS-0.1"
        notes.append("Pinned kernel.spec_pin: AGENT-HOOKS-0.1")

    if "loop_breaker" not in migrated:
        migrated["loop_breaker"] = {
            "enabled": True,
            "trip_threshold": 10,
            "window_seconds": 300.0,
        }
        notes.append("Added loop_breaker defaults (10 calls / 300s)")

    if "egress" not in migrated:
        migrated["egress"] = {"allowed_domains": []}
        notes.append("Added egress block (public-IP SSRF guard)")

    mcp = migrated.setdefault("mcp", {})
    if isinstance(mcp, dict):
        if "protocol_version" not in mcp:
            mcp["protocol_version"] = "2026-07-28"
            notes.append("Pinned mcp.protocol_version: 2026-07-28")
        if "enforce_pin" not in mcp:
            mcp["enforce_pin"] = True
            notes.append("Enabled mcp.enforce_pin: true")

    return migrated, notes


@click.command()
@click.option("--v4", "to_v4", is_flag=True, help="Idempotently migrate v3 .drako.yaml to v4 local-first schema")
@click.option("--balanced", "level", flag_value="balanced", help="Enable fail-closed enforcement with consent gates")
@click.option("--strict", "level", flag_value="strict", help="Maximum fail-closed governance posture")
@click.option("--config", "config_path", default=_CONFIG_FILENAME, help="Path to config file")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def upgrade(to_v4: bool, level: str | None, config_path: str, yes: bool) -> None:
    """Upgrade governance posture or migrate .drako.yaml from v3 to v4."""
    click.echo()
    click.secho("  Drako Upgrade", fg="cyan", bold=True)
    click.echo()

    if not to_v4 and not level:
        click.echo("  Choose an upgrade target:")
        click.echo()
        click.echo("    " + click.style("--v4", fg="cyan") + "        Migrate v3 SaaS config to v4 local-first schema (idempotent)")
        click.echo("    " + click.style("--balanced", fg="yellow") + "  Fail-closed default + consent gates for irreversible tools")
        click.echo("    " + click.style("--strict", fg="red") + "    Strict fail-closed + signed A2A + cryptographic receipts")
        click.echo()
        click.echo("  Usage: " + click.style("drako upgrade --v4", fg="cyan"))
        return

    path = Path(config_path)
    if not path.exists():
        click.secho(f"  [error]  {config_path} not found. Run 'drako init' first.", fg="red")
        raise SystemExit(1)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        click.secho(f"  [error]  Invalid YAML: {exc}", fg="red")
        raise SystemExit(1)

    if not isinstance(raw, dict):
        click.secho("  [error]  Expected a YAML mapping.", fg="red")
        raise SystemExit(1)

    notes: list[str] = []
    if to_v4:
        raw, v4_notes = migrate_v3_to_v4_dict(raw)
        notes.extend(v4_notes)

    if level:
        raw["governance_level"] = level
        raw.setdefault("kernel", {})["default_effect"] = "deny"
        raw["kernel"].setdefault("spec_pin", "AGENT-HOOKS-0.1")
        raw.setdefault("dlp", {})["mode"] = "enforce"
        raw.setdefault("hitl", {})["timeout_action"] = "reject"
        raw["hitl"]["mode"] = "enforce"
        if level == "strict":
            raw.setdefault("intent_verification", {})["mode"] = "enforce"
            raw["intent_verification"]["anti_replay"] = True
            raw.setdefault("a2a", {})["mode"] = "enforce"
            raw["a2a"]["require_signed_cards"] = True
            raw.setdefault("audit", {})["cryptographic"] = True
        notes.append(f"Set governance_level: {level}")

    if not notes:
        click.echo(click.style("  [ok] ", fg="green") + f"{config_path} is already up to date.")
        return

    for n in notes:
        click.echo(f"    • {n}")

    if not yes:
        click.echo()
        if not click.confirm(f"  Apply {len(notes)} change(s) to {config_path}?", default=True):
            click.echo("  Aborted.")
            return

    header = (
        f"# Drako v4 Configuration — governance_level: {raw.get('governance_level', 'balanced')}\n"
        "# Validate with: drako validate .drako.yaml\n\n"
    )
    path.write_text(
        header + yaml.dump(raw, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    click.echo()
    click.echo(click.style("  [ok] ", fg="green") + f"Updated {config_path}!")
    click.echo("  Run: " + click.style(f"drako validate {config_path}", fg="cyan"))
    click.echo()
