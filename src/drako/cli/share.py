"""Share Your Score — viral sharing for `drako scan --share`.

Generates:
- A Rich terminal score card
- Pre-redacted social texts (Twitter/Reddit/LinkedIn) with rotation
- Optional clipboard copy (pyperclip, graceful fallback)

Privacy: no file paths, no code snippets, no sensitive data in share texts.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

if TYPE_CHECKING:
    from drako.cli.scanner import ScanResult


# ---------------------------------------------------------------------------
# Score band classification
# ---------------------------------------------------------------------------

def _score_band(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Text rotation variants by score band
# ---------------------------------------------------------------------------

_TWITTER_VARIANTS: dict[str, list[str]] = {
    "low": [
        "Just discovered my AI agents have {findings_critical} critical governance gaps. "
        "This is what shipping without governance looks like. "
        "pip install drako && drako scan .\n#AIGovernance #Drako",

        "Ran a governance scanner on my {framework} project. Score: {score}/100. "
        "Found {findings_total} issues I didn't know about. "
        "pip install drako && drako scan .\n#Drako",

        "My AI agents scored {score}/100 on governance. Not great. "
        "Found {findings_critical} critical issues hiding in plain sight. "
        "pip install drako\n#AIGovernance",
    ],
    "medium": [
        "My AI agents scored {score}/100 on governance. Found {findings_total} issues "
        "including {findings_critical} critical. Fixing them now. "
        "pip install drako && drako scan .",

        "Ran a governance scan on my {framework} project — {score}/100. "
        "Not bad, but {findings_high} high-severity issues to fix. "
        "pip install drako && drako scan .",

        "Governance audit on my AI agents: {score}/100. Room to improve. "
        "{findings_total} findings, {findings_critical} critical. "
        "pip install drako",
    ],
    "high": [
        "AI agent governance score: {score}/100. {agents} agents, {tools} tools, "
        "{findings_critical} critical findings. If you're deploying agents to production, "
        "scan first: pip install drako",

        "Scored {score}/100 on AI agent governance with {agents} agents and {tools} tools. "
        "Zero critical findings. Scan yours: pip install drako && drako scan .",

        "Clean governance audit: {score}/100 on my {framework} project. "
        "{findings_total} total findings, none critical. "
        "pip install drako",
    ],
    "improvement": [
        "{old_score} -> {new_score} on AI agent governance. Fixed {findings_critical} "
        "critical issues. @drako",

        "Improved my AI agent governance score from {old_score} to {new_score}. "
        "Free scan: pip install drako",

        "Governance score went from {old_score} to {new_score} after fixing "
        "{findings_critical} critical issues. pip install drako",
    ],
}

_REDDIT_VARIANTS: dict[str, list[str]] = {
    "low": [
        "Ran a governance scanner on my {framework} project — scored {score}/100. "
        "Found {findings_critical} critical issues I missed in code review. "
        "Free CLI, no account needed: pip install drako && drako scan .",

        "Just scored {score}/100 on AI agent governance. Ouch. Found hardcoded keys "
        "and unrestricted tool access. Free scanner: pip install drako",
    ],
    "medium": [
        "Governance scan on my {framework} project: {score}/100. Found {findings_total} "
        "issues, {findings_critical} critical. Working through the fixes. "
        "Free CLI: pip install drako && drako scan .",

        "Ran Drako scan on my AI agents — {score}/100. Decent but found "
        "{findings_high} high-severity issues. Anyone else checking their agents? "
        "pip install drako",
    ],
    "high": [
        "Governance scan on my {framework} project: {score}/100. {agents} agents, "
        "{tools} tools, {findings_critical} critical findings. Pretty clean. "
        "Free scanner: pip install drako && drako scan .",

        "Scored {score}/100 on AI agent governance. {findings_total} minor findings, "
        "zero critical. If you deploy agents, try: pip install drako",
    ],
    "improvement": [
        "Improved my AI agent governance from {old_score} to {new_score}. Fixed "
        "{findings_critical} critical issues in about 30 minutes. "
        "Free scan: pip install drako && drako scan .",
    ],
}

_LINKEDIN_VARIANTS: dict[str, list[str]] = {
    "low": [
        "TIL my AI agent project had {findings_critical} critical governance gaps. "
        "Ran Drako scan (30 seconds, no account) and found issues that would've "
        "been a production incident.\npip install drako",

        "Just discovered {findings_critical} critical governance issues in my AI agents. "
        "If you're deploying agents to production without scanning, you might have the "
        "same gaps.\npip install drako",
    ],
    "medium": [
        "Ran a governance audit on my {framework} AI agents — scored {score}/100. "
        "Found {findings_total} issues including {findings_critical} critical. "
        "30-second scan, no account needed.\npip install drako",

        "My AI agents scored {score}/100 on governance. Not bad, but room to improve. "
        "{findings_total} findings across security, compliance, and best practices.\n"
        "pip install drako",
    ],
    "high": [
        "AI agent governance score: {score}/100. {agents} agents, {tools} tools, "
        "zero critical findings. Governance matters when you deploy AI to production.\n"
        "pip install drako",

        "Clean governance audit on my {framework} project. {score}/100 with {agents} "
        "agents and {tools} tools. Scan yours in 30 seconds:\npip install drako",
    ],
    "improvement": [
        "Improved my AI agent governance score from {old_score} to {new_score}. "
        "Fixed {findings_critical} critical issues in 30 minutes.\n"
        "pip install drako",
    ],
}


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class ShareTexts:
    """Pre-redacted texts for each platform."""
    twitter: str
    reddit: str
    linkedin: str


# ---------------------------------------------------------------------------
# Generate share texts with rotation
# ---------------------------------------------------------------------------

def generate_share_texts(
    score: int,
    grade: str,
    agents: int,
    tools: int,
    framework: str,
    findings_critical: int,
    findings_high: int,
    findings_total: int,
    *,
    old_score: int | None = None,
    new_score: int | None = None,
) -> ShareTexts:
    """Generate rotated social share texts based on score band.

    Uses random.choice to pick one variant per platform so not all
    posts are identical.
    """
    band = _score_band(score)

    # Use improvement band if we have old/new scores and score improved
    if old_score is not None and new_score is not None and new_score > old_score:
        band = "improvement"

    fill = {
        "score": score,
        "grade": grade,
        "agents": agents,
        "tools": tools,
        "framework": framework or "AI agent",
        "findings_critical": findings_critical,
        "findings_high": findings_high,
        "findings_total": findings_total,
        "old_score": old_score or 0,
        "new_score": new_score or score,
    }

    twitter = random.choice(_TWITTER_VARIANTS[band]).format(**fill)
    reddit = random.choice(_REDDIT_VARIANTS[band]).format(**fill)
    linkedin = random.choice(_LINKEDIN_VARIANTS[band]).format(**fill)

    return ShareTexts(twitter=twitter, reddit=reddit, linkedin=linkedin)


# ---------------------------------------------------------------------------
# Terminal score card
# ---------------------------------------------------------------------------

def render_share_card(
    score: int,
    grade: str,
    agents: int,
    tools: int,
    models: int,
    framework: str,
    findings_critical: int,
    findings_high: int,
    console: Console | None = None,
) -> None:
    """Render a visual score card in the terminal."""
    if console is None:
        console = Console(stderr=True)

    # Build the score bar
    filled = score // 5
    empty = 20 - filled
    bar = "\u2588" * filled + "\u2591" * empty

    grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "dark_orange", "F": "red"}
    color = grade_colors.get(grade, "white")

    card = Text()
    card.append("\n")
    card.append(f"     {bar}  ", style=color)
    card.append(f"{score}/100 ", style=f"bold {color}")
    card.append(f"[{grade}]", style=f"bold {color}")
    card.append("\n\n")
    card.append(f"  \u2713 {agents} agents  \u2502  {tools} tools  \u2502  {models} models\n", style="white")

    if findings_critical > 0:
        card.append(f"  \u2717 {findings_critical} critical findings\n", style="red")
    else:
        card.append("  \u2713 0 critical findings\n", style="green")

    if findings_high > 0:
        card.append(f"  \u2717 {findings_high} high findings\n", style="dark_orange")

    card.append(f"\n  Framework: {framework or 'Unknown'}\n", style="dim")
    card.append("  Scanned with Drako \u2014 useagentmesh.com\n", style="dim")

    console.print(Panel(
        card,
        title="[bold cyan]Drako Governance Report[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

def copy_to_clipboard(text: str) -> bool:
    """Copy text to clipboard. Returns True on success."""
    try:
        import pyperclip  # type: ignore[import-untyped]
        pyperclip.copy(text)
        return True
    except (ImportError, Exception):
        return False


# ---------------------------------------------------------------------------
# Interactive share prompt
# ---------------------------------------------------------------------------

def run_share_flow(result: "ScanResult", console: Console | None = None) -> None:
    """Complete --share flow: card + texts + clipboard."""
    import click
    from drako.cli.scoring import findings_summary

    if console is None:
        console = Console(stderr=True)

    counts = findings_summary(result.findings)
    findings_total = sum(counts.values())

    framework = "Unknown"
    if result.bom.frameworks:
        fw = result.bom.frameworks[0]
        framework = f"{fw.name} {fw.version or ''}".strip()

    # Render terminal score card
    render_share_card(
        score=result.score,
        grade=result.grade,
        agents=len(result.bom.agents),
        tools=len(result.bom.tools),
        models=len(result.bom.models),
        framework=framework,
        findings_critical=counts.get("CRITICAL", 0),
        findings_high=counts.get("HIGH", 0),
        console=console,
    )

    # Generate share texts
    texts = generate_share_texts(
        score=result.score,
        grade=result.grade,
        agents=len(result.bom.agents),
        tools=len(result.bom.tools),
        framework=framework,
        findings_critical=counts.get("CRITICAL", 0),
        findings_high=counts.get("HIGH", 0),
        findings_total=findings_total,
    )

    console.print()
    console.print("[bold]\U0001f4cb Share your score:[/bold]")
    console.print()
    console.print("[bold]\U0001d54f (Twitter):[/bold]")
    console.print(f"  {texts.twitter}")
    console.print()
    console.print("[bold]Reddit:[/bold]")
    console.print(f"  {texts.reddit}")
    console.print()
    console.print("[bold]LinkedIn:[/bold]")
    console.print(f"  {texts.linkedin}")
    console.print()

    choice = click.prompt(
        "\U0001f4cb Copy to clipboard? [twitter/reddit/linkedin/all/skip]",
        default="skip",
        show_default=False,
    )
    choice = choice.strip().lower()

    if choice == "skip":
        return

    clipboard_map = {
        "twitter": texts.twitter,
        "reddit": texts.reddit,
        "linkedin": texts.linkedin,
        "all": f"Twitter:\n{texts.twitter}\n\nReddit:\n{texts.reddit}\n\nLinkedIn:\n{texts.linkedin}",
    }

    text_to_copy = clipboard_map.get(choice)
    if not text_to_copy:
        console.print("[dim]Invalid choice, skipping.[/dim]")
        return

    if copy_to_clipboard(text_to_copy):
        console.print("[green]\u2713 Copied to clipboard![/green]")
    else:
        console.print("[dim]Could not copy to clipboard. Copy the text above manually.[/dim]")
