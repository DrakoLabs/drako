"""`drako scan` — Scan a project for governance/compliance gaps.

Offline-first: all analysis runs locally using AST. No network calls
unless --upload is passed. No signup or API key required for basic use.
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
    "--upload",
    is_flag=True,
    help="Upload results to Drako for shareable URL and badge",
)
@click.option(
    "--api-key",
    envvar="DRAKO_API_KEY",
    default=None,
    help="API key for authenticated upload (env: DRAKO_API_KEY)",
)
@click.option(
    "--endpoint",
    default="https://api.useagentmesh.com",
    envvar="DRAKO_ENDPOINT",
    help="Backend endpoint for --upload",
)
@click.option(
    "--framework",
    default=None,
    help="Comma-separated frameworks to detect (e.g. crewai,langgraph)",
)
@click.option(
    "--share",
    is_flag=True,
    help="Show shareable score card and pre-redacted social posts",
)
def scan(
    directory: str,
    output_format: str,
    upload: bool,
    api_key: str | None,
    endpoint: str,
    framework: str | None,
    share: bool,
) -> None:
    """Scan your AI agent project for governance and compliance gaps.

    Analyzes the project at DIRECTORY (defaults to current directory)
    and generates a governance score, Agent BOM, and actionable findings.

    All analysis runs offline — no network calls, no signup required.
    """
    # Lazy imports keep CLI startup fast
    from drako.cli.scanner import run_scan

    # Parse framework filter
    framework_filter = None
    if framework:
        framework_filter = [f.strip() for f in framework.split(",") if f.strip()]

    # ---- Run offline scan ----
    result = run_scan(directory, framework_filter=framework_filter)

    # ---- Cache scan results for `drako init` ----
    from drako.cli.scan_cache import save_scan_cache, ensure_gitignore_cache
    try:
        save_scan_cache(result, directory)
        ensure_gitignore_cache(directory)
        click.echo(click.style("  [cache]  ", fg="green") + "Scan results saved to .drako/.last_scan.json")
    except OSError:
        pass  # Non-critical — don't fail the scan if cache write fails

    # ---- Output based on format ----
    if output_format == "json":
        from drako.cli.formats.json_fmt import format_json
        click.echo(format_json(result))

    elif output_format == "sarif":
        from drako.cli.formats.sarif import format_sarif
        click.echo(format_sarif(result))

    else:
        # Terminal output with Rich
        from drako.cli.report import render_report
        render_report(
            bom=result.bom,
            findings=result.findings,
            score=result.score,
            grade=result.grade,
            metadata=result.metadata,
            scan_duration_ms=result.scan_duration_ms,
        )

    # ---- Share if requested ----
    if share:
        from drako.cli.share import run_share_flow
        run_share_flow(result)

    # ---- Upload if requested ----
    if upload:
        from drako.cli.upload import upload_results
        import httpx

        click.echo()
        if api_key:
            click.echo(click.style("  [upload] ", fg="green") + "Uploading results (authenticated)...")
        else:
            click.echo(click.style("  [upload] ", fg="green") + "Uploading results (anonymous, expires in 7 days)...")

        try:
            resp = upload_results(result, api_key=api_key, endpoint=endpoint)
            scan_id = resp.get("scan_id", "?")
            scan_url = resp.get("url", "")
            click.echo(click.style("  [upload] ", fg="green") + f"Scan ID: {scan_id}")
            if scan_url:
                click.echo(
                    click.style("  [upload] ", fg="green")
                    + "Report: "
                    + click.style(scan_url, fg="cyan", underline=True)
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                click.secho("  [error]  Rate limit exceeded. Try again later or use an API key.", fg="red")
            elif e.response.status_code == 401:
                click.secho("  [error]  Invalid API key.", fg="red")
            else:
                click.secho(f"  [error]  Upload failed: HTTP {e.response.status_code}", fg="red")
        except httpx.ConnectError:
            click.secho("  [error]  Could not connect to Drako backend.", fg="red")
            click.echo("           Try: --endpoint http://localhost:8000")
        except httpx.ReadTimeout:
            click.secho("  [error]  Upload timed out.", fg="red")

    # ---- Exit code based on findings ----
    critical_count = sum(1 for f in result.findings if f.severity == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
