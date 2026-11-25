"""`drako comply` Click command group."""

from __future__ import annotations

from pathlib import Path

import click

from drako.comply.mapping import build_context
from drako.comply.questionnaire import run as run_questionnaire
from drako.comply.status import collect, render
from drako.comply.storage import load as load_answers
from drako.comply.storage import save as save_answers


@click.group()
def comply() -> None:
    """Generate EU AI Act documentation (Articles 9, 11, 12, 14)."""


@comply.command("init")
@click.option(
    "--directory", "-C",
    default=".",
    type=click.Path(file_okay=False),
    help="Project directory (default: current).",
)
def init_cmd(directory: str) -> None:
    """Run the questionnaire and persist answers to .drako/comply.yaml."""
    existing = load_answers(directory)
    answers = run_questionnaire(existing)
    path = save_answers(answers, directory)
    click.echo(f"Saved {len(answers)} answers to {path}")


_ARTICLE_CHOICE = click.Choice(["9", "11", "12", "14"])


@comply.command("generate")
@click.option("--article", type=_ARTICLE_CHOICE, default=None,
              help="Generate a single article (9 / 11 / 12 / 14).")
@click.option("--all", "all_articles", is_flag=True, help="Generate every article.")
@click.option("--output", "-o", default="comply-output",
              type=click.Path(file_okay=False),
              help="Output directory for DOCX + PDF files.")
@click.option("--directory", "-C", default=".",
              type=click.Path(file_okay=False),
              help="Project directory whose .drako/ holds scan + answers.")
@click.option("--format", "fmt",
              type=click.Choice(["both", "docx", "pdf"]), default="both",
              show_default=True,
              help="Which output formats to generate.")
def generate_cmd(article: str | None, all_articles: bool, output: str,
                 directory: str, fmt: str) -> None:
    """Generate one or more EU AI Act article documents."""
    if not article and not all_articles:
        raise click.UsageError("Pass --article N or --all.")

    try:
        from drako.comply.generators import ARTICLES, generate_docx, generate_pdf
    except ImportError as exc:
        raise click.UsageError(
            "drako[comply] extras are required. Install with: pip install drako[comply]"
        ) from exc

    ctx = build_context(directory)
    output_dir = Path(directory) / output
    targets = list(ARTICLES) if all_articles else [int(article)]

    written: list[Path] = []
    for art in targets:
        try:
            if fmt in ("docx", "both"):
                written.append(generate_docx(art, ctx, output_dir))
            if fmt in ("pdf", "both"):
                written.append(generate_pdf(art, ctx, output_dir))
        except ImportError as exc:
            raise click.UsageError(str(exc)) from exc

    for path in written:
        click.echo(f"Wrote {path}")


@comply.command("status")
@click.option("--directory", "-C", default=".",
              type=click.Path(file_okay=False),
              help="Project directory.")
@click.option("--output", "-o", default="comply-output",
              type=click.Path(file_okay=False),
              help="Output directory checked for generated artifacts.")
def status_cmd(directory: str, output: str) -> None:
    """Show which articles have been generated and their freshness."""
    rows = collect(directory, output)
    click.echo(render(rows))
