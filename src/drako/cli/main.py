"""Drako CLI — entry point."""

from __future__ import annotations

import click

from drako import __version__


class _OrderedGroup(click.Group):
    """Click group that preserves command registration order."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


@click.group(
    cls=_OrderedGroup,
    invoke_without_command=True,
    epilog="Full docs: https://docs.getdrako.com",
)
@click.version_option(version=__version__, prog_name="drako")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Drako — The Trust Layer for AI Agents.

    \b
    Getting started:
      drako scan .     Scan your project for governance issues
      drako init       Set up governance config
      drako push       Sync config to the platform

    \b
    Run drako COMMAND --help for details on any command.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit(0)


# Register sub-commands (lazy imports keep startup fast)
def _register_commands() -> None:
    from drako.cli.scan_command import scan
    from drako.cli.init_command import init
    from drako.cli.push_command import push
    from drako.cli.status_command import status
    from drako.cli.bom_command import bom
    from drako.cli.baseline_command import baseline
    from drako.cli.upgrade_command import upgrade
    from drako.cli.fix_command import fix
    from drako.cli.validate_command import validate
    from drako.cli.templates_command import templates
    from drako.cli.simulate_command import simulate
    from drako.cli.history_command import history
    from drako.cli.diff_command import diff
    from drako.cli.rollback_command import rollback
    from drako.cli.proxy_command import proxy
    from drako.cli.serve_command import serve
    from drako.cli.verify_command import verify

    # Ordered by user journey: scan → configure → connect → manage
    cli.add_command(scan)
    cli.add_command(init)
    cli.add_command(push)
    cli.add_command(status)
    cli.add_command(bom)
    cli.add_command(baseline)
    cli.add_command(upgrade)
    cli.add_command(fix)
    cli.add_command(validate)
    cli.add_command(templates)
    cli.add_command(simulate)
    cli.add_command(history)
    cli.add_command(diff)
    cli.add_command(rollback)
    cli.add_command(proxy)
    cli.add_command(serve)
    cli.add_command(verify)


_register_commands()

if __name__ == "__main__":
    cli()
