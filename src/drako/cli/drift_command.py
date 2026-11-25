"""`drako drift` — MITRE ATLAS v2026.08 Scope Drift Detection (offline).

Compares the baseline tools recorded in `.drako/.last_scan.json` (or an
automatic offline live scan when no cache is present) against the effective
ACS policy profile (`drako-policy.yaml`). Exits non-zero when blocking drift
(`uncovered`, `widened`, `flipped`) occurs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import yaml

_DEFAULT_BASELINE = ".drako/.last_scan.json"


def _detect_governance_level(profile_path: Path) -> str:
    """Read local .drako.yaml governance_level if present alongside the profile."""
    cfg_path = profile_path.parent / ".drako.yaml"
    if cfg_path.exists():
        try:
            raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("governance_level"):
                return str(raw["governance_level"]).lower()
        except (yaml.YAMLError, OSError):
            pass
    return "balanced"


def _entries_from_profile(profile: dict[str, Any]):
    from drako.kernel.drift import AuthorityEntry

    entries = []
    for name, rule in (profile.get("tools") or {}).items():
        if isinstance(rule, dict):
            entries.append(
                AuthorityEntry(id=str(name), kind="tool", detail=str(rule.get("effect", "deny")))
            )
    return entries


def _entries_from_baseline(baseline_path: Path, governance_level: str = "balanced"):
    from drako.cli.init_command import classify_tool_type, expected_effect_for_tool
    from drako.kernel.drift import AuthorityEntry

    raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    entries = []
    for t in raw.get("tools", []):
        if isinstance(t, dict) and t.get("name"):
            if "expected_effect" in t:
                effect = t["expected_effect"]
            else:
                effect = expected_effect_for_tool(classify_tool_type(t), governance_level)
            entries.append(AuthorityEntry(id=str(t["name"]), kind="tool", detail=str(effect)))
    issued_at = raw.get("scanned_at") or raw.get("timestamp") or raw.get("generated_at")
    return entries, issued_at


def _entries_from_live_scan(directory: Path, governance_level: str = "balanced"):
    from drako.cli.init_command import classify_tool_type, expected_effect_for_tool
    from drako.cli.scanner import run_scan
    from drako.kernel.drift import AuthorityEntry

    result = run_scan(str(directory))
    entries = []
    for tool in result.bom.tools:
        if tool.name:
            effect = expected_effect_for_tool(classify_tool_type(tool), governance_level)
            entries.append(AuthorityEntry(id=str(tool.name), kind="tool", detail=effect))
    return entries, datetime.now(timezone.utc).isoformat()


@click.command()
@click.option("--profile", "profile_path", default="drako-policy.yaml", help="ACS policy profile YAML")
@click.option(
    "--baseline",
    "baseline_path",
    default=None,
    help="Baseline scan cache JSON (default: .drako/.last_scan.json, or live offline scan)",
)
@click.option("--max-age-days", default=30, type=int, help="Mark baseline stale after N days")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def drift(
    profile_path: str,
    baseline_path: str | None,
    max_age_days: int,
    output_format: str,
) -> None:
    """Detect scope drift between baseline authority and effective ACS profile."""
    from drako.kernel.drift import detect_drift
    from drako.kernel.policies import compile_profile

    p_file = Path(profile_path)
    if not p_file.exists():
        raise click.ClickException(f"ACS policy profile not found: {profile_path} (run `drako init`)")

    governance_level = _detect_governance_level(p_file)
    used_live_scan = False

    if baseline_path is not None:
        b_file = Path(baseline_path)
        if not b_file.exists():
            raise click.ClickException(
                f"Scan baseline not found: {baseline_path} (run `drako scan . --save-cache`)"
            )
        base_entries, issued_at = _entries_from_baseline(b_file, governance_level=governance_level)
    else:
        default_cache = Path(_DEFAULT_BASELINE)
        if default_cache.exists():
            base_entries, issued_at = _entries_from_baseline(
                default_cache, governance_level=governance_level
            )
        else:
            used_live_scan = True
            base_entries, issued_at = _entries_from_live_scan(
                p_file.parent, governance_level=governance_level
            )

    profile = compile_profile(yaml.safe_load(p_file.read_text(encoding="utf-8")))
    eff_entries = _entries_from_profile(profile)
    report = detect_drift(
        base_entries,
        eff_entries,
        baseline_issued_at=issued_at,
        max_age_days=max_age_days,
    )

    if output_format == "json":
        click.echo(
            json.dumps(
                {
                    "clean": report.clean,
                    "source": "live" if used_live_scan else "cache",
                    "blocking_count": len(report.blocking),
                    "items": [
                        {"kind": i.kind, "id": i.id, "message": i.message}
                        for i in report.items
                    ],
                },
                indent=2,
            )
        )
    else:
        click.echo()
        click.secho("  Drako Scope Drift (ATLAS v2026.08)", fg="cyan", bold=True)
        click.echo()
        if used_live_scan:
            click.echo(
                click.style("  [live]   ", fg="cyan")
                + "No scan cache found; comparing against live offline scan."
            )
        if not report.items:
            click.secho("  [clean]  No scope drift detected.", fg="green")
        for item in report.items:
            color = "yellow" if item.kind == "stale" else "red"
            click.echo(click.style(f"  [{item.kind.upper():9s}] ", fg=color) + item.message)
        click.echo()

    if not report.clean:
        raise SystemExit(1)
