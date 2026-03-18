"""`drako serve` — Start a local MCP compliance server."""

from __future__ import annotations

import click

from drako.config import DrakoConfig
from drako.exceptions import ConfigError


@click.command()
@click.option("--config", "config_path", default=".drako.yaml", help="Path to config file")
@click.option("--port", default=3100, type=int, help="Port for the local MCP server")
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio", help="MCP transport")
def serve(config_path: str, port: int, transport: str) -> None:
    """Start a local MCP compliance server that proxies to Drako."""

    try:
        config = DrakoConfig.load(config_path)
        api_key = config.resolve_api_key()
    except ConfigError as exc:
        click.echo(click.style("  [error]  ", fg="red") + str(exc))
        raise SystemExit(1)

    click.echo()
    click.secho("  Drako MCP Server", fg="cyan", bold=True)
    click.echo()
    click.echo(click.style("  [server] ", fg="green") + f"Transport: {transport}")

    if transport == "stdio":
        click.echo(click.style("  [server] ", fg="green") + "Starting STDIO transport (reading from stdin)...")
        from drako.mcp.local_server import run_stdio
        run_stdio(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id)
    else:
        click.echo(click.style("  [server] ", fg="green") + f"Starting SSE transport on port {port}...")
        from drako.mcp.local_server import run_sse
        run_sse(api_key=api_key, endpoint=config.endpoint, tenant_id=config.tenant_id, port=port)
