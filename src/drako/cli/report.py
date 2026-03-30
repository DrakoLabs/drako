"""Rich terminal report for `drako scan`.

Generates a marketing-grade terminal output using the Rich library.
Developers take screenshots of this and share on Twitter/X.
"""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich import box

if TYPE_CHECKING:
    from drako.benchmark import BenchmarkResult
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata
    from drako.cli.policies.base import Finding


# ---------------------------------------------------------------------------
# Color mapping
# ---------------------------------------------------------------------------

_GRADE_COLORS = {
    "A": "green",
    "B": "bright_green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "red",
}

_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",   # red circle
    "HIGH": "\U0001f7e0",       # orange circle
    "MEDIUM": "\U0001f7e1",     # yellow circle
    "LOW": "\U0001f535",        # blue circle
}


# ---------------------------------------------------------------------------
# Score bar rendering
# ---------------------------------------------------------------------------

def _render_score_bar(score: int) -> str:
    """Render a progress bar for the score."""
    filled = score // 5
    empty = 20 - filled
    return "\u2588" * filled + "\u2591" * empty


# ---------------------------------------------------------------------------
# Main render function
# ---------------------------------------------------------------------------

def _render_findings_section(
    console: Console,
    findings: list[Finding],
    details: bool = False,
) -> None:
    """Render a group of findings organized by severity."""
    findings_by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_severity.setdefault(f.severity, []).append(f)

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        items = findings_by_severity.get(severity, [])
        if not items:
            continue

        color = _SEVERITY_COLORS.get(severity, "white")
        emoji = _SEVERITY_EMOJI.get(severity, "\u2022")

        console.print(
            f"{emoji} [bold {color}]{severity}[/bold {color}] ({len(items)} finding{'s' if len(items) != 1 else ''})",
        )
        console.print()

        for f in items:
            location = ""
            if f.file_path:
                location = f"  File: {f.file_path}"
                if f.line_number:
                    location += f":{f.line_number}"

            finding_text = Text()
            finding_text.append(f"{f.policy_id}", style=f"bold {color}")
            finding_text.append(f" \u2502 {f.title}\n", style="bold")
            finding_text.append(f"  {f.message}\n", style="white")
            if location:
                finding_text.append(f"{location}\n", style="dim")

            if f.code_snippet:
                finding_text.append(f"  Found: ", style="dim")
                finding_text.append(f"{f.code_snippet}\n", style="dim italic")

            console.print(finding_text, end="")

            if details:
                if f.impact:
                    console.print(f"  [bold]Impact:[/bold] {f.impact}")
                if f.attack_scenario:
                    console.print(f"  [dim italic]Attack: {f.attack_scenario}[/dim italic]")
                effort_str = f.remediation_effort or "unknown"
                refs_str = ", ".join(f.references) if f.references else "none"
                console.print(f"  [dim]Fix effort: {effort_str} \u2502 Refs: {refs_str}[/dim]")
                console.print()

            if f.fix_snippet:
                console.print(f"  [bold green]Fix:[/bold green]")
                console.print(Syntax(
                    f.fix_snippet,
                    "python",
                    theme="monokai",
                    line_numbers=False,
                    padding=1,
                ))

            console.print()


_DEFAULT_MAX_FINDINGS = 10
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def render_report(
    bom: AgentBOM,
    findings: list[Finding],
    score: int,
    grade: str,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    console: Console | None = None,
    details: bool = False,
    verbose: bool = False,
    baselined_count: int = 0,
    resolved_count: int = 0,
    determinism_score: int | None = None,
    determinism_grade: str | None = None,
    matched_advisories: dict | None = None,
    reachability: list | None = None,
) -> None:
    """Render the full scan report to the terminal.

    If *console* is None a new Console writing to stderr is created.
    Pass a ``Console(file=StringIO())`` for testing.
    """
    if console is None:
        console = Console(stderr=True)

    console.print()

    # ---- Header Panel ----
    framework_str = ", ".join(
        f"{fw.name} {fw.version or ''}" for fw in bom.frameworks
    ) if bom.frameworks else "No framework detected"

    header = Text()
    header.append("\U0001f4c1 Project: ", style="bold")
    header.append(str(metadata.root.name) + "\n")
    header.append("\U0001f50d Framework: ", style="bold")
    header.append(framework_str + "\n")
    header.append("\u23f1\ufe0f  Scan completed in ", style="bold")
    header.append(f"{scan_duration_ms / 1000:.1f}s")

    console.print(Panel(
        header,
        title="[bold cyan]Drako Scan Report[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    console.print()

    # ---- Agent BOM Table ----
    bom_table = Table(
        title="\U0001f3d7\ufe0f  AGENT BOM (Bill of Materials)",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        title_style="bold",
    )
    bom_table.add_column("Component", style="cyan", width=14)
    bom_table.add_column("Details", style="white")

    agent_names = ", ".join(a.name for a in bom.agents[:8]) or "None detected"
    if len(bom.agents) > 8:
        agent_names += f" (+{len(bom.agents) - 8} more)"
    bom_table.add_row("Agents", f"{len(bom.agents)} ({agent_names})")

    tool_names = ", ".join(t.name for t in bom.tools[:8]) or "None detected"
    if len(bom.tools) > 8:
        tool_names += f" (+{len(bom.tools) - 8} more)"
    bom_table.add_row("Tools", f"{len(bom.tools)} ({tool_names})")

    model_names = ", ".join(m.name for m in bom.models[:5]) or "None detected"
    bom_table.add_row("Models", f"{len(bom.models)} ({model_names})")

    bom_table.add_row("MCP Servers", str(len(bom.mcp_servers)))
    bom_table.add_row("Prompts", f"{len(bom.prompts)} system prompts detected")
    bom_table.add_row("Framework", framework_str)

    console.print(bom_table)
    console.print()

    # ---- Governance Score ----
    grade_color = _GRADE_COLORS.get(grade, "white")
    bar = _render_score_bar(score)

    score_text = Text()
    score_text.append("\U0001f4ca GOVERNANCE SCORE: ", style="bold")
    score_text.append(f"{score}/100 ", style=f"bold {grade_color}")
    score_text.append(f"[{grade}] ", style=f"bold {grade_color}")
    score_text.append(bar, style=grade_color)
    score_text.append(f" {score}%", style=f"dim {grade_color}")

    # ---- Determinism Score (if available) ----
    if determinism_score is not None and determinism_grade is not None:
        det_color = _GRADE_COLORS.get(determinism_grade, "white")
        det_bar = _render_score_bar(determinism_score)

        score_text.append("\n")
        score_text.append("\U0001f3af DETERMINISM SCORE: ", style="bold")
        score_text.append(f"{determinism_score}/100 ", style=f"bold {det_color}")
        score_text.append(f"[{determinism_grade}] ", style=f"bold {det_color}")
        score_text.append(det_bar, style=det_color)
        score_text.append(f" {determinism_score}%", style=f"dim {det_color}")

    console.print(Panel(score_text, border_style=grade_color))
    console.print()

    # ---- Reachability summary ----
    if reachability:
        from drako.reachability import ReachabilityStatus
        r_counts = {"reachable": 0, "potentially_reachable": 0, "unreachable": 0}
        for tr in reachability:
            r_counts[tr.status.value] += 1
        if any(v > 0 for v in r_counts.values()):
            r_parts = []
            if r_counts["reachable"]:
                r_parts.append(f"[red]{r_counts['reachable']} reachable[/red]")
            if r_counts["potentially_reachable"]:
                r_parts.append(f"[yellow]{r_counts['potentially_reachable']} potentially reachable[/yellow]")
            if r_counts["unreachable"]:
                r_parts.append(f"[dim]{r_counts['unreachable']} unreachable[/dim]")
            console.print(f"\U0001f517 Tool Reachability: " + " \u2502 ".join(r_parts))
            console.print()

    # ---- Split findings into vulnerabilities and recommendations ----
    vuln_findings = [f for f in findings if getattr(f, "finding_type", "vulnerability") == "vulnerability"]
    rec_findings = [f for f in findings if getattr(f, "finding_type", "vulnerability") == "recommendation"]

    # ---- Vulnerabilities by Severity ----
    show_all_findings = details or verbose
    if vuln_findings:
        console.print(f"[bold]\u26a0\ufe0f  FINDINGS ({len(vuln_findings)}):[/bold]")
        console.print()
        if show_all_findings:
            _render_findings_section(console, vuln_findings, details)
        else:
            # Default: show top N sorted by severity
            sorted_vulns = sorted(
                vuln_findings,
                key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
            )
            top_findings = sorted_vulns[:_DEFAULT_MAX_FINDINGS]
            _render_findings_section(console, top_findings, details)
            remaining = len(vuln_findings) - _DEFAULT_MAX_FINDINGS
            if remaining > 0:
                console.print(
                    f"  [dim]... and {remaining} more finding{'s' if remaining != 1 else ''}[/dim]"
                )
                console.print(
                    "  [dim]Run: [cyan]drako scan --details[/cyan] to see all[/dim]"
                )
                console.print()

    # ---- Recommendations by Severity ----
    if rec_findings:
        console.print(f"[bold]\U0001f4a1 RECOMMENDATIONS ({len(rec_findings)}):[/bold]")
        console.print()
        if show_all_findings:
            _render_findings_section(console, rec_findings, details)
        else:
            sorted_recs = sorted(
                rec_findings,
                key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
            )
            top_recs = sorted_recs[:_DEFAULT_MAX_FINDINGS]
            _render_findings_section(console, top_recs, details)
            remaining_recs = len(rec_findings) - _DEFAULT_MAX_FINDINGS
            if remaining_recs > 0:
                console.print(
                    f"  [dim]... and {remaining_recs} more recommendation{'s' if remaining_recs != 1 else ''}[/dim]"
                )
                console.print()

    # ---- Summary ----
    vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in vuln_findings:
        if f.severity in vuln_counts:
            vuln_counts[f.severity] += 1

    summary_parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if vuln_counts[sev] > 0:
            color = _SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{vuln_counts[sev]} {sev.lower()}[/{color}]")

    if summary_parts:
        console.print(f"\U0001f4c8 Summary: " + " \u2502 ".join(summary_parts))
        if rec_findings:
            console.print(f"   [dim]{len(rec_findings)} recommendation{'s' if len(rec_findings) != 1 else ''} (do not affect score)[/dim]")
    elif not rec_findings:
        console.print("\u2705 [green]No findings! Your project has excellent governance.[/green]")
    else:
        console.print(f"\u2705 [green]No vulnerabilities found![/green] {len(rec_findings)} recommendation{'s' if len(rec_findings) != 1 else ''} available.")

    if baselined_count > 0 or resolved_count > 0:
        parts = []
        if baselined_count > 0:
            parts.append(f"{baselined_count} baselined")
        if resolved_count > 0:
            parts.append(f"[green]{resolved_count} resolved[/green]")
        sep = " \u2502 "
        console.print(f"   Baseline: {sep.join(parts)} (use --show-all to see all)")

    # Improvement hint
    if score < 80 and vuln_counts["CRITICAL"] > 0:
        potential = min(100, score + vuln_counts["CRITICAL"] * 15)
        console.print(f"   Fix the {vuln_counts['CRITICAL']} critical issue{'s' if vuln_counts['CRITICAL'] != 1 else ''} to reach score {potential}+")

    console.print()

    # ---- Related Advisories ----
    if matched_advisories:
        adv_table = Table(
            title="\U0001f6e1\ufe0f  RELATED ADVISORIES (DRAKO-ABSS)",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
            title_style="bold",
        )
        adv_table.add_column("Advisory", style="cyan", width=24)
        adv_table.add_column("Title", style="white")
        adv_table.add_column("Rules", style="dim", width=20)

        shown: set[str] = set()
        for _rule_id, advs in matched_advisories.items():
            for adv in advs:
                if adv.id in shown:
                    continue
                shown.add(adv.id)
                rules_str = ", ".join(adv.drako_rules[:4])
                if len(adv.drako_rules) > 4:
                    rules_str += f" +{len(adv.drako_rules) - 4}"
                adv_table.add_row(adv.id, adv.title, rules_str)

        console.print(adv_table)
        console.print()

    # ---- CTA ----
    console.print("[bold]Next steps:[/bold]")
    console.print("   [cyan]drako init[/cyan]            Set up governance for this project")
    console.print("   [cyan]drako scan --details[/cyan]  See impact and fix suggestions")
    console.print("   [cyan]drako scan --baseline[/cyan] Acknowledge existing issues")
    console.print()


def render_report_to_string(
    bom: AgentBOM,
    findings: list[Finding],
    score: int,
    grade: str,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    details: bool = False,
    verbose: bool = False,
    baselined_count: int = 0,
    resolved_count: int = 0,
    determinism_score: int | None = None,
    determinism_grade: str | None = None,
    matched_advisories: dict | None = None,
    reachability: list | None = None,
) -> str:
    """Render the report to a string (for testing)."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100)
    render_report(
        bom, findings, score, grade, metadata, scan_duration_ms,
        console=console, details=details, verbose=verbose,
        baselined_count=baselined_count, resolved_count=resolved_count,
        determinism_score=determinism_score, determinism_grade=determinism_grade,
        matched_advisories=matched_advisories, reachability=reachability,
    )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Benchmark panel
# ---------------------------------------------------------------------------

def render_benchmark_panel(
    benchmark: BenchmarkResult,
    score: int,
    grade: str,
    console: Console | None = None,
) -> None:
    """Render a benchmark comparison panel after the scan report.

    Shows how the project's score compares to the benchmark dataset.
    """
    if console is None:
        console = Console(stderr=True)

    if not benchmark.score_distribution:
        console.print("[dim]Benchmark data unavailable.[/dim]")
        return

    grade_color = _GRADE_COLORS.get(grade, "white")

    lines = Text()

    # ---- Score line ----
    lines.append("Your score: ", style="bold")
    lines.append(f"{score}/100 ", style=f"bold {grade_color}")
    lines.append(f"[{grade}]\n", style=f"bold {grade_color}")

    # ---- Percentile ----
    lines.append(
        f"Better than {benchmark.percentile}% of scanned projects (benchmark dataset)\n",
    )

    # ---- Framework comparison ----
    if benchmark.framework and benchmark.framework_percentile is not None:
        fw_display = benchmark.framework.replace("_", " ").title()
        fw_count = benchmark.framework_count or "?"
        top_pct = 100 - benchmark.framework_percentile
        lines.append(f"\nvs. {fw_display} projects ({fw_count} scanned): ", style="dim")
        lines.append(f" Top {top_pct}%\n", style="bold")

    top_all = 100 - benchmark.percentile
    lines.append("vs. all projects: ", style="dim")
    lines.append(f"                  Top {top_all}%\n", style="bold")

    # ---- Score distribution histogram ----
    lines.append("\n")
    buckets = [0] * 10  # 0-9, 10-19, ..., 90-100
    for s in benchmark.score_distribution:
        idx = min(s // 10, 9)
        buckets[idx] += 1

    user_bucket = min(score // 10, 9)
    bar_chars = []
    for i, count in enumerate(buckets):
        width = max(1, count // 2)  # scale down for display
        if i == user_bucket:
            bar_chars.append("\u2588" * width)  # filled block = user's bucket
        else:
            bar_chars.append("\u2591" * width)  # light shade = other buckets

    bar_line = "".join(bar_chars)
    lines.append(bar_line)
    lines.append(" \u2190 you are here\n", style="dim italic")

    # ---- Grade distribution ----
    lines.append("\nGrade distribution:\n", style="bold")
    total = sum(benchmark.grade_distribution.values()) or 1
    for g in ("F", "D", "C", "B", "A"):
        count = benchmark.grade_distribution.get(g, 0)
        pct = round(count / total * 100)
        bar_width = max(1, pct // 2)
        bar = "\u2588" * bar_width
        g_color = _GRADE_COLORS.get(g, "white")
        style = f"bold {g_color}" if g == grade else g_color
        lines.append(f"{g}: ", style=style)
        lines.append(f"{bar} {pct}%\n", style=style)

    lines.append("\n")
    lines.append(
        "Note: Benchmark uses an aggregate dataset. Contribute: drako scan . --share",
        style="dim italic",
    )

    console.print(Panel(
        lines,
        title="[bold cyan]Benchmark Comparison[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))
    console.print()


def render_benchmark_panel_to_string(
    benchmark: BenchmarkResult,
    score: int,
    grade: str,
) -> str:
    """Render the benchmark panel to a string (for testing)."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100)
    render_benchmark_panel(benchmark, score, grade, console=console)
    return buf.getvalue()
