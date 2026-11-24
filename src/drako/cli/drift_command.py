"""`drako drift` — MITRE ATLAS v2026.08 Scope Drift Detection (offline).

Compares the baseline tools recorded in `.drako/.last_scan.json` (or a live
scan) against the effective ACS policy profile (`drako-policy.yaml`).
Exits non-zero when blocking drift (`uncovered`, `widened`, `flipped`) occurs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import yaml


def _entries_from_profile(profile: dict[str, Any]):
    from drako.kernel.drift import AuthorityEntry

    entries = []
    for name, rule in (profile.get("tools") or {}).items():
        if isinstance(rule, dict):
            entries.append(
                AuthorityEntry(id=str(name), kind="tool", detail=str(rule.get("effect", "deny")))
            )
    return entries


def _entries_from_baseline(baseline_path: Path):
    from drako.kernel.drift import AuthorityEntry

    raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    entries = []
    for t in raw.get("tools", []):
        if isinstance(t, dict) and t.get("name"):
            effect = t.get("expected_effect", "allow")
            entries.append(AuthorityEntry(id=str(t["name"]), kind="tool", detail=str(effect)))
    return entries, raw.get("timestamp") or raw.get("generated_at")


@click.command()
@click.option("--profile", "profile_path", default="drako-policy.yaml", help="ACS policy profile YAML")
@click.option("--baseline", "baseline_path", default=".drako/.last_scan.json", help="Baseline scan cache JSON")
@click.option("--max-age-days", default=30, type=int, help="Mark baseline stale after N days")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def drift(
    profile_path: str,
    baseline_path: str,
    max_age_days: int,
    output_format: str,
) -> None:
    """Detect scope drift between baseline authority and effective ACS profile."""
    from drako.kernel.drift import detect_drift
    from drako.kernel.policies import compile_profile

    p_file = Path(profile_path)
    b_file = Path(baseline_path)
    if not p_file.exists():
        raise click.ClickException(f"ACS policy profile not found: {profile_path} (run `drako init`)")
    if not b_file.exists():
        raise click.ClickException(f"Scan baseline not found: {baseline_path} (run `drako scan .`)")

    profile = compile_profile(yaml.safe_load(p_file.read_text(encoding="utf-8")))
    base_entries, issued_at = _entries_from_baseline(b_file)
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
        if not report.items:
            click.secho("  [clean]  No scope drift detected.", fg="green")
        for item in report.items:
            color = "yellow" if item.kind == "stale" else "red"
            click.echo(click.style(f"  [{item.kind.upper():9s}] ", fg=color) + item.message)
        click.echo()

    if not report.clean:
        raise SystemExit(1)
