"""Drako CLI — entry point (v4.0 local-first Authority Kernel)."""

from __future__ import annotations

from drako.cli.encoding import configure_output

configure_output()

import click  # noqa: E402

from drako import __version__  # noqa: E402


class _OrderedGroup(click.Group):
    """Click group that preserves command registration order."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


@click.group(
    cls=_OrderedGroup,
    invoke_without_command=True,
    epilog="Docs & ADRs: https://github.com/DrakoLabs/drako",
)
@click.version_option(version=__version__, prog_name="drako")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Drako — The Portable Authority Kernel for AI Agents.

    \b
    Getting started (100% offline, zero API keys):
      drako scan .            Scan codebase & bootstrap authority map
      drako init              Create local .drako.yaml + ACS profile
      drako drift             Detect scope drift vs baseline (ATLAS)
      drako mcp audit         Audit MCP server configs & mcp.lock pins
      drako a2a verify        Verify A2A v1.0 JWS Signed Agent Cards
      drako why <receipt_id>  Inspect provenance subgraph of a decision
      drako verify            Verify Ed25519 receipt chains offline

    \b
    Run drako COMMAND --help for details on any command.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit(0)


def _register_commands() -> None:
    from drako.cli.a2a_command import a2a
    from drako.cli.baseline_command import baseline
    from drako.cli.bom_command import bom
    from drako.cli.comply_command import comply
    from drako.cli.desktop_command import desktop
    from drako.cli.drift_command import drift
    from drako.cli.fix_command import fix
    from drako.cli.init_command import init
    from drako.cli.kernel_command import kernel
    from drako.cli.pin_command import mcp
    from drako.cli.proxy_command import proxy
    from drako.cli.scan_command import scan
    from drako.cli.templates_command import templates
    from drako.cli.upgrade_command import upgrade
    from drako.cli.validate_command import validate
    from drako.cli.verify_command import verify
    from drako.cli.why_command import why

    for cmd in (
        scan,
        init,
        bom,
        baseline,
        fix,
        validate,
        templates,
        upgrade,
        why,
        verify,
        drift,
        mcp,
        a2a,
        desktop,
        proxy,
        kernel,
        comply,
    ):
        cli.add_command(cmd)


_register_commands()

if __name__ == "__main__":
    cli()
