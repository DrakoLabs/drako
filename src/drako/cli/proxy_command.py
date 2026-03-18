"""`drako proxy` — Manage the Drako enforcement proxy."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import click

_PID_FILE = ".drako/.proxy.pid"


@click.group()
def proxy() -> None:
    """Manage the out-of-process governance proxy."""


@proxy.command("start")
@click.option("--port", default=8990, type=int, help="Port to listen on")
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--config", "config_path", default=".drako.yaml", help="Config file path")
@click.option("--daemon", "-d", is_flag=True, help="Run as background daemon")
def start(port: int, host: str, config_path: str, daemon: bool) -> None:
    """Start the enforcement proxy server."""
    click.echo()
    click.secho("  Drako Proxy", fg="cyan", bold=True)
    click.echo()

    # Check config exists
    if not Path(config_path).exists():
        click.secho(f"  [error]  {config_path} not found. Run 'drako init' first.", fg="red")
        raise SystemExit(1)

    # Check dependencies
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        import httpx  # noqa: F401
    except ImportError as exc:
        click.secho(f"  [error]  Missing dependency: {exc.name}", fg="red")
        click.echo("           Install with: " + click.style("pip install 'drako[proxy]'", fg="cyan"))
        raise SystemExit(1)

    click.echo(click.style("  [config] ", fg="green") + f"Using {config_path}")
    click.echo(click.style("  [proxy]  ", fg="green") + f"Starting on {host}:{port}")
    click.echo()
    click.echo("  Configure your agents with these env vars:")
    click.echo(click.style(f"    OPENAI_BASE_URL=http://localhost:{port}/openai/v1", fg="white"))
    click.echo(click.style(f"    ANTHROPIC_BASE_URL=http://localhost:{port}/anthropic/v1", fg="white"))
    click.echo()

    if daemon:
        # Fork to background (Unix only)
        if os.name == "nt":
            click.secho("  [warn]   Daemon mode not supported on Windows. Running in foreground.", fg="yellow")
        else:
            pid = os.fork()
            if pid > 0:
                # Parent - save PID and exit
                pid_path = Path(_PID_FILE)
                pid_path.parent.mkdir(exist_ok=True)
                pid_path.write_text(str(pid))
                click.echo(click.style("  [proxy]  ", fg="green") + f"Proxy started in background (PID: {pid})")
                click.echo("           Stop with: " + click.style("drako proxy stop", fg="cyan"))
                return
            # Child continues to run server

    from drako.proxy.proxy_server import run_server
    run_server(port=port, host=host, config_path=config_path)


@proxy.command("stop")
def stop() -> None:
    """Stop the background proxy daemon."""
    pid_path = Path(_PID_FILE)
    if not pid_path.exists():
        click.secho("  [info]   No proxy PID file found. Proxy may not be running.", fg="yellow")
        return

    try:
        pid = int(pid_path.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        pid_path.unlink(missing_ok=True)
        click.echo(click.style("  [ok] ", fg="green") + f"Proxy stopped (PID: {pid})")
    except ProcessLookupError:
        pid_path.unlink(missing_ok=True)
        click.echo(click.style("  [info]   ", fg="yellow") + "Proxy was not running.")
    except (ValueError, OSError) as exc:
        click.secho(f"  [error]  Could not stop proxy: {exc}", fg="red")


@proxy.command("status")
@click.option("--port", default=8990, type=int, help="Proxy port to check")
def status(port: int) -> None:
    """Check proxy status."""
    import httpx

    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"http://localhost:{port}/health")
        if resp.status_code == 200:
            data = resp.json()
            click.echo()
            click.echo(click.style("  [proxy]  ", fg="green") + "Proxy is running")
            click.echo(f"           Governance: {data.get('governance_level', '?')}")
            click.echo(f"           Targets:    {', '.join(data.get('targets', []))}")
            click.echo(f"           Audit logs: {data.get('audit_entries', 0)}")
            click.echo()
        else:
            click.secho(f"  [warn]   Proxy responded with HTTP {resp.status_code}", fg="yellow")
    except (httpx.ConnectError, httpx.ReadTimeout):
        click.echo()
        click.secho(f"  [info]   Proxy is not running on port {port}", fg="yellow")
        click.echo("           Start with: " + click.style("drako proxy start", fg="cyan"))
        click.echo()
