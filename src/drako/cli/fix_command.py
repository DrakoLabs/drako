"""`drako fix` — Auto-fix governance and compliance findings.

Runs the offline scanner, then applies fix_snippet patches for each
finding that has an available fix.  Use --dry-run to preview the diffs
without modifying any files.
"""

from __future__ import annotations

import ast
import difflib
import sys
from pathlib import Path

import click


@click.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show diffs without applying changes",
)
@click.option(
    "--framework",
    default=None,
    help="Comma-separated frameworks to detect (e.g. crewai,langgraph)",
)
def fix(directory: str, dry_run: bool, framework: str | None) -> None:
    """Auto-fix governance findings in your AI agent project.

    Scans DIRECTORY (defaults to current directory), then applies
    available fixes.  Use --dry-run to preview what would change.
    """
    from drako.cli.scanner import run_scan

    framework_filter = None
    if framework:
        framework_filter = [f.strip() for f in framework.split(",") if f.strip()]

    result = run_scan(directory, framework_filter=framework_filter)

    fixable = [f for f in result.findings if f.fix_snippet and f.file_path]

    if not fixable:
        click.echo("No auto-fixable findings detected.")
        sys.exit(0)

    applied = 0
    skipped = 0

    for finding in fixable:
        file_path = Path(finding.file_path)
        if not file_path.is_absolute():
            file_path = Path(directory) / file_path

        if not file_path.exists():
            click.secho(f"  [skip] {finding.policy_id}: file not found: {file_path}", fg="yellow")
            skipped += 1
            continue

        if not finding.code_snippet:
            click.secho(f"  [skip] {finding.policy_id}: no code_snippet to replace", fg="yellow")
            skipped += 1
            continue

        try:
            original = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            click.secho(f"  [skip] {finding.policy_id}: cannot read {file_path}: {exc}", fg="yellow")
            skipped += 1
            continue

        if finding.code_snippet not in original:
            click.secho(
                f"  [skip] {finding.policy_id}: code_snippet not found in {file_path.name}",
                fg="yellow",
            )
            skipped += 1
            continue

        patched = original.replace(finding.code_snippet, finding.fix_snippet, 1)

        if file_path.suffix == ".py":
            try:
                ast.parse(patched, filename=str(file_path))
            except SyntaxError as exc:
                click.secho(
                    f"  [skip] {finding.policy_id}: patch would produce invalid Python syntax ({exc.msg})",
                    fg="yellow",
                )
                skipped += 1
                continue

        # Generate unified diff
        rel_path = str(file_path)
        diff_lines = list(difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"--- {rel_path}",
            tofile=f"+++ {rel_path}",
        ))

        if not diff_lines:
            skipped += 1
            continue

        if dry_run:
            click.echo()
            click.secho(f"  [{finding.policy_id}] {finding.title}", fg="cyan", bold=True)
            for line in diff_lines:
                line_s = line.rstrip("\n")
                if line_s.startswith("---") or line_s.startswith("+++"):
                    click.secho(line_s, fg="white", bold=True)
                elif line_s.startswith("-"):
                    click.secho(line_s, fg="red")
                elif line_s.startswith("+"):
                    click.secho(line_s, fg="green")
                else:
                    click.echo(line_s)
        else:
            file_path.write_text(patched, encoding="utf-8")
            click.secho(
                f"  [fixed] {finding.policy_id}: {finding.title} ({file_path.name})",
                fg="green",
            )

        applied += 1

    click.echo()
    if dry_run:
        click.secho(
            f"Dry run: {applied} fix(es) available, {skipped} skipped. "
            f"Run without --dry-run to apply.",
            fg="cyan",
        )
    else:
        click.secho(f"Applied {applied} fix(es), {skipped} skipped.", fg="green")
