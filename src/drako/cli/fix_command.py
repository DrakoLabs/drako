"""`drako fix` — Show proposed fixes for scan findings.

Dry-run only: displays unified diffs without modifying any files.
"""

from __future__ import annotations

import click


@click.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "--dry-run",
    is_flag=True,
    required=True,
    help="Show proposed changes without modifying files (required).",
)
@click.option(
    "--policy",
    default=None,
    help="Only show fixes for a specific policy ID (e.g. SEC-001).",
)
@click.option(
    "--include-tests",
    is_flag=True,
    help="Include tests/ directories in the scan.",
)
def fix(directory: str, dry_run: bool, policy: str | None, include_tests: bool) -> None:
    """Show proposed fixes for governance findings (dry-run only).

    Scans DIRECTORY and displays unified diffs for auto-fixable findings.
    No files are modified.

    \b
    Examples:
        drako fix --dry-run              # Preview all auto-fixes
        drako fix --dry-run --policy SEC-001   # Only hardcoded-key fixes
    """
    # Lazy imports
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text

    from drako.cli.scanner import run_scan
    from drako.cli.autofix import AutoFixer, format_unified_diff

    console = Console(stderr=True)

    console.print()
    console.print(Panel(
        "[bold]Drako Fix[/bold] \u2014 Dry Run",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    # Run scan first
    with console.status("[cyan]Scanning project...[/cyan]"):
        result = run_scan(directory, include_tests=include_tests)

    if result.score is None:
        console.print("  [yellow]No agent frameworks detected. Nothing to fix.[/yellow]")
        console.print()
        return

    # Generate fixes
    fixer = AutoFixer(result)
    fixes = fixer.generate_all_fixes(policy_filter=policy)

    if not fixes:
        if policy:
            console.print(f"  [yellow]No auto-fixes available for {policy.upper()}.[/yellow]")
        else:
            console.print("  [green]No auto-fixable findings detected.[/green]")
        console.print()
        return

    console.print(
        f"  Found [bold]{len(fixes)}[/bold] auto-fixable issue{'s' if len(fixes) != 1 else ''}:\n"
    )

    for i, fix_item in enumerate(fixes, 1):
        diff_text = format_unified_diff(fix_item)
        if not diff_text:
            continue

        # Fix header
        sev = fix_item.finding.severity
        color = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "white")

        header = Text()
        header.append(f"  {i}. ", style="bold")
        header.append(f"{fix_item.finding.policy_id}", style=f"bold {color}")
        header.append(f" [{sev}]", style=color)
        header.append(f"  {fix_item.description}")
        console.print(header)

        if fix_item.file_path:
            action = "create" if fix_item.new_file else "modify"
            console.print(f"     [dim]{action}: {fix_item.file_path}[/dim]")

        console.print(Syntax(
            diff_text,
            "diff",
            theme="monokai",
            line_numbers=False,
            padding=1,
        ))

        if fix_item.imports_needed:
            console.print(
                f"     [dim]Requires: {', '.join(fix_item.imports_needed)}[/dim]"
            )

        console.print()

    # Footer
    console.print(
        "  [dim]\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500[/dim]"
    )
    console.print("  [bold]This is a dry run \u2014 no files were modified.[/bold]")
    console.print(
        "  [dim]Actual file modification coming in a future release.[/dim]"
    )
    console.print()
