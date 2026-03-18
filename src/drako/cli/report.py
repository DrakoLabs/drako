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
# Risk tagline mapping (Item 7)
# ---------------------------------------------------------------------------

_RISK_TAGLINES: dict[str, str] = {
    "SEC-005": "Your agents can execute arbitrary code.",
    "SEC-001": "API keys are exposed in source code.",
    "GOV-006": "Agents can rewrite their own instructions.",
    "SEC-007": "Agents are vulnerable to prompt injection.",
    "SEC-003": "Tools have unrestricted filesystem access.",
    "SEC-004": "Tools have unrestricted network access.",
    "MAG-001": "No spend caps \u2014 agents can consume unlimited resources.",
    "ODD-001": "Agents operate without defined boundaries.",
}

_SEVERITY_RISK = {
    "CRITICAL": ("\U0001f6a8", "CRITICAL", "red"),
    "HIGH": ("\U0001f6a8", "HIGH", "dark_orange"),
    "MEDIUM": ("\u26a0\ufe0f", "MODERATE", "yellow"),
    "LOW": ("\u2139\ufe0f", "LOW", "blue"),
}

_CATEGORY_ORDER = [
    ("Security", "\U0001f6e1\ufe0f"),
    ("Governance", "\U0001f3db\ufe0f"),
    ("Compliance", "\U0001f4dc"),
    ("Operational", "\u2699\ufe0f"),
    ("Magnitude", "\U0001f4cf"),
    ("Identity", "\U0001f511"),
    ("Best Practices", "\u2728"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_score_bar(score: int) -> str:
    """Render a progress bar for the score."""
    filled = score // 5
    empty = 20 - filled
    return "\u2588" * filled + "\u2591" * empty


def _generate_risk_tagline(findings: list[Finding]) -> tuple[str, str, str, str] | None:
    """Return (emoji, risk_level, color, tagline) for the most critical finding."""
    if not findings:
        return None

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top = min(findings, key=lambda f: severity_order.get(f.severity, 99))

    tagline = _RISK_TAGLINES.get(top.policy_id)
    if not tagline:
        tagline = {
            "CRITICAL": "Critical governance gaps detected.",
            "HIGH": "Significant governance gaps need attention.",
            "MEDIUM": "Moderate improvements recommended.",
            "LOW": "Minor improvements suggested.",
        }.get(top.severity, "Review findings above.")

    info = _SEVERITY_RISK.get(top.severity, ("\u2022", "UNKNOWN", "white"))
    return info[0], info[1], info[2], tagline


def _render_score_section(
    score: int | None,
    grade: str | None,
    findings: list[Finding],
    console: Console,
) -> None:
    """Render governance score + risk tagline (shared by compact & detailed)."""
    if score is None:
        console.print("  \u26a0  [bold yellow]No agent frameworks detected \u2014 score: N/A[/bold yellow]")
        console.print("     [dim]Try scanning a Python project that uses CrewAI, LangGraph, or AutoGen.[/dim]")
    else:
        grade_color = _GRADE_COLORS.get(grade, "white")
        bar = _render_score_bar(score)

        score_text = Text()
        score_text.append("\U0001f4ca GOVERNANCE SCORE: ", style="bold")
        score_text.append(f"{score}/100 ", style=f"bold {grade_color}")
        score_text.append(f"[{grade}] ", style=f"bold {grade_color}")
        score_text.append(bar, style=grade_color)
        score_text.append(f" {score}%", style=f"dim {grade_color}")

        console.print(Panel(score_text, border_style=grade_color))

    console.print()

    # Risk tagline
    if score is not None and findings:
        risk = _generate_risk_tagline(findings)
        if risk:
            emoji, level, color, tagline = risk
            console.print(
                f"  {emoji} [bold {color}]Risk Level: {level}[/bold {color}]"
                f" \u2014 {tagline}"
            )
            console.print()


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


# ---------------------------------------------------------------------------
# Compact report (default)
# ---------------------------------------------------------------------------

def _render_compact_report(
    bom: AgentBOM,
    findings: list[Finding],
    score: int | None,
    grade: str | None,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    console: Console,
) -> None:
    """Render a compact summary report (default mode)."""
    console.print()

    # ---- Header (condensed) ----
    framework_str = ", ".join(
        f"{fw.name} {fw.version or ''}".strip() for fw in bom.frameworks
    ) if bom.frameworks else "No framework detected"

    header = Text()
    header.append("\U0001f4c1 ", style="bold")
    header.append(str(metadata.root.name), style="bold cyan")
    header.append(f"  \u2502  {framework_str}", style="dim")
    header.append(f"  \u2502  {scan_duration_ms / 1000:.1f}s", style="dim")

    console.print(Panel(
        header,
        title="[bold cyan]Drako Scan[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    # ---- BOM one-liner ----
    console.print(
        f"  \U0001f3d7\ufe0f  Agent BOM: "
        f"[cyan]{len(bom.agents)}[/cyan] agents \u2502 "
        f"[cyan]{len(bom.tools)}[/cyan] tools \u2502 "
        f"[cyan]{len(bom.models)}[/cyan] models \u2502 "
        f"[cyan]{len(bom.prompts)}[/cyan] prompts"
    )
    console.print()

    # ---- Governance Score + Risk Tagline ----
    _render_score_section(score, grade, findings, console)

    # ---- Findings ----
    if score is not None:
        counts = _severity_counts(findings)

        if any(counts.values()):
            # Severity count table
            parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if counts[sev] > 0:
                    color = _SEVERITY_COLORS[sev]
                    emoji = _SEVERITY_EMOJI[sev]
                    parts.append(f"  {emoji} [{color}]{sev}[/{color}]  [bold]{counts[sev]}[/bold]")
            console.print("\n".join(parts))
            console.print()

            # Top 3 issues
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            top = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))[:3]
            console.print("  [bold]Top Issues[/bold]")
            for f in top:
                color = _SEVERITY_COLORS.get(f.severity, "white")
                file_hint = ""
                if f.file_path:
                    file_hint = f" [dim]({f.file_path})[/dim]"
                console.print(
                    f"  \u2022 [{color}]{f.policy_id}[/{color}]  {f.title}{file_hint}"
                )
            console.print()
        else:
            console.print("  \u2705 [green]No findings! Excellent governance.[/green]")
            console.print()

    # ---- CTA ----
    console.print(
        "\U0001f449 [bold cyan]drako scan --details[/bold cyan]"
        "    Full findings with code snippets and fix suggestions"
    )
    console.print(
        "\U0001f449 [bold cyan]drako fix --dry-run[/bold cyan]"
        "     Preview auto-fixes without modifying files"
    )
    console.print()
    console.print(
        "   [cyan]drako init[/cyan]              "
        "Connect to Drako for runtime governance"
    )
    console.print(
        "   [dim]https://useagentmesh.com[/dim]"
    )
    console.print()


# ---------------------------------------------------------------------------
# Detailed report (--details)
# ---------------------------------------------------------------------------

def _render_detailed_report(
    bom: AgentBOM,
    findings: list[Finding],
    score: int | None,
    grade: str | None,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    console: Console,
) -> None:
    """Render the full detailed report (--details mode)."""
    console.print()

    # ---- Header Panel ----
    framework_str = ", ".join(
        f"{fw.name} {fw.version or ''}".strip() for fw in bom.frameworks
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

    # ---- Governance Score + Risk Tagline ----
    _render_score_section(score, grade, findings, console)

    # ---- Findings by Category, then Severity (Item 6) ----
    if score is not None:
        findings_by_cat: dict[str, list[Finding]] = {}
        for f in findings:
            findings_by_cat.setdefault(f.category, []).append(f)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        for cat_name, cat_emoji in _CATEGORY_ORDER:
            cat_findings = findings_by_cat.get(cat_name, [])
            if not cat_findings:
                continue

            cat_findings.sort(key=lambda f: severity_order.get(f.severity, 99))
            cat_count = len(cat_findings)

            console.print(
                f"\n{cat_emoji} [bold underline]{cat_name.upper()}[/bold underline]"
                f" ({cat_count} finding{'s' if cat_count != 1 else ''})"
            )
            console.print()

            for f in cat_findings:
                color = _SEVERITY_COLORS.get(f.severity, "white")
                emoji = _SEVERITY_EMOJI.get(f.severity, "\u2022")

                location = ""
                if f.file_path:
                    location = f"  File: {f.file_path}"
                    if f.line_number:
                        location += f":{f.line_number}"

                finding_text = Text()
                finding_text.append(f"  {emoji} ", style=f"bold {color}")
                finding_text.append(f"{f.policy_id}", style=f"bold {color}")
                finding_text.append(f" [{f.severity}]", style=f"{color}")
                finding_text.append(f" \u2502 {f.title}\n", style="bold")
                finding_text.append(f"    {f.message}\n", style="white")
                if location:
                    finding_text.append(f"  {location}\n", style="dim")
                if f.code_snippet:
                    finding_text.append(f"    Found: ", style="dim")
                    finding_text.append(f"{f.code_snippet}\n", style="dim italic")

                console.print(finding_text, end="")

                if f.fix_snippet:
                    console.print(f"    [bold green]Fix:[/bold green]")
                    console.print(Syntax(
                        f.fix_snippet,
                        "python",
                        theme="monokai",
                        line_numbers=False,
                        padding=1,
                    ))

                console.print()

        # ---- Summary ----
        counts = _severity_counts(findings)

        summary_parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts[sev] > 0:
                color = _SEVERITY_COLORS[sev]
                summary_parts.append(f"[{color}]{counts[sev]} {sev.lower()}[/{color}]")

        if summary_parts:
            console.print(f"\U0001f4c8 Summary: " + " \u2502 ".join(summary_parts))
        else:
            console.print("\u2705 [green]No findings! Your project has excellent governance.[/green]")

        # Improvement hint
        if score < 80 and counts["CRITICAL"] > 0:
            potential = min(100, score + counts["CRITICAL"] * 15)
            console.print(
                f"   Fix the {counts['CRITICAL']} critical issue"
                f"{'s' if counts['CRITICAL'] != 1 else ''}"
                f" to improve your score to ~{potential}"
            )

    console.print()

    # ---- CTA ----
    console.print(
        "\U0001f4a1 [bold]Next steps:[/bold]"
    )
    console.print(
        "   [cyan]drako fix --dry-run[/cyan]  "
        "# Preview auto-fixes for your findings"
    )
    console.print(
        "   [cyan]drako init[/cyan]           "
        "# Connect to Drako for runtime governance"
    )
    console.print()
    console.print(
        "   [dim]Unlock runtime DLP, Trust Score, Circuit Breaker, and cryptographic audit trails.[/dim]"
    )
    console.print(
        "   [dim]\u2192 [bold white]https://useagentmesh.com/upgrade[/bold white][/dim]"
    )
    console.print()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_report(
    bom: AgentBOM,
    findings: list[Finding],
    score: int,
    grade: str,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    console: Console | None = None,
    details: bool = False,
) -> None:
    """Render the scan report to the terminal.

    If *console* is None a new Console writing to stderr is created.
    Pass a ``Console(file=StringIO())`` for testing.

    When *details* is False (default), renders a compact summary.
    When *details* is True, renders the full report with code snippets.
    """
    if console is None:
        console = Console(stderr=True)

    if details:
        _render_detailed_report(bom, findings, score, grade, metadata, scan_duration_ms, console)
    else:
        _render_compact_report(bom, findings, score, grade, metadata, scan_duration_ms, console)


def render_report_to_string(
    bom: AgentBOM,
    findings: list[Finding],
    score: int,
    grade: str,
    metadata: ProjectMetadata,
    scan_duration_ms: int,
    details: bool = False,
) -> str:
    """Render the report to a string (for testing)."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=100)
    render_report(bom, findings, score, grade, metadata, scan_duration_ms, console=console, details=details)
    return buf.getvalue()
