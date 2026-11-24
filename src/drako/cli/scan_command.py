"""`drako scan` — Scan a project for governance and agent security gaps.

100% offline-first: all analysis runs locally using AST. Zero network calls,
no signup, and no API key required.
"""

from __future__ import annotations

import sys

import click


@click.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help="Output format (default: terminal with Rich)",
)
@click.option(
    "--framework",
    default=None,
    help="Comma-separated frameworks to detect (e.g. langgraph,openai-agents,maf)",
)
@click.option(
    "--save-cache",
    is_flag=True,
    default=False,
    help="Persist scan cache to .drako/.last_scan.json (read-only by default)",
)
@click.option(
    "--details",
    is_flag=True,
    help="Show impact analysis and attack scenarios for each finding",
)
@click.option(
    "--compact",
    is_flag=True,
    help="Plain-text compact output with concise one-line fixes",
)
@click.option(
    "--baseline",
    "save_baseline",
    is_flag=True,
    help="Save current findings as the baseline for future scans",
)
@click.option(
    "--show-all",
    is_flag=True,
    help="Show all findings, ignoring the baseline",
)
@click.option(
    "--benchmark",
    is_flag=True,
    help="Compare your score against bundled anonymized benchmark data",
)
@click.option(
    "--determinism",
    is_flag=True,
    help="Show only determinism findings (DET-* rules)",
)
@click.option(
    "--threshold-det",
    type=int,
    default=0,
    help="Minimum determinism score (exit 1 if below). For CI gating.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Exit code 1 if any finding at this severity or above (for CI gating)",
)
@click.option(
    "--diff", "diff_ref",
    default=None,
    help="Only scan files changed since a git ref (e.g., HEAD~1, origin/main)",
)
def scan(
    directory: str,
    output_format: str,
    framework: str | None,
    save_cache: bool,
    details: bool,
    compact: bool,
    save_baseline: bool,
    show_all: bool,
    benchmark: bool,
    determinism: bool,
    threshold_det: int,
    fail_on: str | None,
    diff_ref: str | None,
) -> None:
    """Scan your AI agent project for governance and security gaps.

    Analyzes the project at DIRECTORY (defaults to current directory)
    and generates a governance score, Agent BOM, and actionable findings.

    All analysis runs 100% offline — zero network calls, zero API keys.
    """
    if compact and output_format != "terminal":
        raise click.UsageError("--compact is only compatible with --format terminal")
    if compact and details:
        raise click.UsageError("--compact is incompatible with --details")

    from drako.cli.scanner import run_scan

    framework_filter = None
    if framework:
        framework_filter = [f.strip() for f in framework.split(",") if f.strip()]

    result = run_scan(directory, framework_filter=framework_filter)

    if (
        output_format == "terminal"
        and not result.bom.agents
        and not result.bom.tools
        and not result.bom.frameworks
    ):
        click.echo()
        click.secho("  No AI agent components detected in this project.", fg="yellow")
        click.echo()
        click.echo("  Drako scans Python & TypeScript projects using: LangGraph, OpenAI Agents SDK,")
        click.echo("  Microsoft Agent Framework, Claude Agent SDK, Google ADK, CrewAI, PydanticAI.")
        click.echo()
        click.echo("  If your agents are in a subdirectory, try:")
        click.echo("     " + click.style("drako scan path/to/agent-module/", fg="cyan"))
        click.echo()
        sys.exit(0)

    if diff_ref:
        import subprocess

        try:
            git_result = subprocess.run(
                ["git", "diff", "--name-only", diff_ref],
                capture_output=True, text=True, cwd=directory, timeout=10,
            )
            if git_result.returncode != 0:
                click.secho(
                    f"  [error]  git diff failed: {git_result.stderr.strip()}",
                    fg="red", err=True,
                )
                sys.exit(1)
            changed_files = {
                f.strip().replace("\\", "/")
                for f in git_result.stdout.splitlines()
                if f.strip()
            }
            if not changed_files:
                click.echo("  No files changed since " + diff_ref + ". Nothing to scan.")
                sys.exit(0)
            result.findings = [
                f for f in result.findings
                if not f.file_path or f.file_path.replace("\\", "/") in changed_files
            ]
            if output_format == "terminal":
                click.echo(
                    click.style("  [diff]   ", fg="green")
                    + f"Filtered to {len(changed_files)} changed file(s) since {diff_ref}"
                )
        except FileNotFoundError:
            click.secho("  [error]  git not found. --diff requires git.", fg="red", err=True)
            sys.exit(1)
        except subprocess.TimeoutExpired:
            click.secho("  [error]  git diff timed out.", fg="red", err=True)
            sys.exit(1)

    if determinism:
        result.findings = [f for f in result.findings if f.category == "Determinism"]

    from drako.cli.baseline import Baseline

    bl = Baseline(directory)
    all_findings = result.findings
    display_findings = all_findings
    baselined_count = 0
    resolved_count = 0

    if save_baseline:
        path = bl.save(all_findings)
        if output_format == "terminal":
            click.echo(
                click.style("  [baseline] ", fg="green")
                + f"Saved {len(all_findings)} findings as baseline to {path}"
            )
        else:
            click.echo(f"  [baseline] Saved {len(all_findings)} findings to {path}", err=True)
    elif bl.exists() and not show_all:
        new_findings, baselined_findings, resolved_fps = bl.filter_findings(all_findings)
        display_findings = new_findings
        baselined_count = len(baselined_findings)
        resolved_count = len(resolved_fps)

    if save_cache:
        from drako.cli.scan_cache import save_scan_cache

        try:
            save_scan_cache(result, directory)
            if output_format == "terminal":
                click.echo(click.style("  [cache]  ", fg="green") + "Scan results saved to .drako/.last_scan.json")
            else:
                click.echo("  [cache]  Scan results saved to .drako/.last_scan.json", err=True)
        except OSError:
            pass

    benchmark_result = None
    if benchmark:
        from drako.benchmark import compute_benchmark, load_dataset

        dataset = load_dataset()
        fw_name = result.bom.frameworks[0].name if result.bom.frameworks else None
        benchmark_result = compute_benchmark(result.score, fw_name, dataset)

    if output_format == "json":
        from drako.cli.formats.json_fmt import format_json

        click.echo(format_json(result, benchmark=benchmark_result))
    elif output_format == "sarif":
        from drako.cli.formats.sarif import format_sarif

        baseline_fps: set[str] | None = None
        if bl.exists() and not show_all:
            data = bl.load()
            if data:
                baseline_fps = set(data["fingerprints"].keys())
        click.echo(format_sarif(result, baseline_fingerprints=baseline_fps))
    elif compact:
        click.echo(f"Drako Scan: Governance {result.score}/100 [{result.grade}] | Determinism {result.determinism_score}/100 [{result.determinism_grade}]")
        if not display_findings:
            click.echo("  0 findings.")
        for f in display_findings:
            loc = f" ({f.file_path})" if f.file_path else ""
            fix_line = (f.fix_snippet or "").strip().splitlines()[0] if f.fix_snippet else ""
            click.echo(f"  [{f.severity}] {f.policy_id} {f.title}{loc}")
            if fix_line:
                click.echo(f"      fix: {fix_line}")
    else:
        from drako.cli.report import render_report

        render_report(
            bom=result.bom,
            findings=display_findings,
            score=result.score,
            grade=result.grade,
            metadata=result.metadata,
            scan_duration_ms=result.scan_duration_ms,
            details=details,
            baselined_count=baselined_count,
            resolved_count=resolved_count,
            determinism_score=result.determinism_score,
            determinism_grade=result.determinism_grade,
            matched_advisories=result.matched_advisories,
            reachability=result.reachability,
            skipped_files=result.skipped_files,
        )
        if benchmark_result:
            from drako.cli.report import render_benchmark_panel

            render_benchmark_panel(benchmark_result, result.score, result.grade)

    _SEVERITY_ORDER = ["low", "medium", "high", "critical"]

    if fail_on:
        threshold_idx = _SEVERITY_ORDER.index(fail_on.lower())
        failing = [
            f for f in result.findings
            if f.severity.lower() in _SEVERITY_ORDER
            and _SEVERITY_ORDER.index(f.severity.lower()) >= threshold_idx
            and getattr(f, "finding_type", "vulnerability") == "vulnerability"
        ]
        if failing:
            click.secho(
                f"\n  [gate]  {len(failing)} finding(s) at {fail_on.upper()} or above",
                fg="red", err=True,
            )
            for f in failing[:5]:
                click.secho(f"          {f.policy_id}: {f.title}", fg="red", err=True)
            if len(failing) > 5:
                click.secho(f"          ... and {len(failing) - 5} more", fg="red", err=True)
            sys.exit(1)

    if threshold_det > 0 and result.determinism_score < threshold_det:
        click.secho(
            f"  [gate]  Determinism score {result.determinism_score} below threshold {threshold_det}",
            fg="red", err=True,
        )
        sys.exit(1)

    critical_count = sum(
        1 for f in result.findings
        if f.severity == "CRITICAL"
        and getattr(f, "finding_type", "vulnerability") == "vulnerability"
    )
    if critical_count > 0:
        click.secho(
            f"  [gate]  {critical_count} CRITICAL finding(s) detected",
            fg="red", err=True,
        )
        sys.exit(1)
