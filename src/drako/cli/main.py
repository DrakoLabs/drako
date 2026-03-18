"""Drako CLI — entry point."""

from __future__ import annotations

import click

from drako import __version__


@click.group()
@click.version_option(version=__version__, prog_name="drako")
def cli() -> None:
    """Drako — The Trust Layer for AI Agents."""


# Register sub-commands (lazy imports keep startup fast)
def _register_commands() -> None:
    from drako.cli.init_command import init
    from drako.cli.scan_command import scan
    from drako.cli.serve_command import serve
    from drako.cli.status_command import status
    from drako.cli.verify_command import verify
    from drako.cli.push_command import push
    from drako.cli.history_command import history
    from drako.cli.diff_command import diff
    from drako.cli.rollback_command import rollback
    from drako.cli.upgrade_command import upgrade
    from drako.cli.templates_command import templates
    from drako.cli.proxy_command import proxy

    cli.add_command(init)
    cli.add_command(scan)
    cli.add_command(serve)
    cli.add_command(status)
    cli.add_command(verify)
    cli.add_command(push)
    cli.add_command(history)
    cli.add_command(diff)
    cli.add_command(rollback)
    cli.add_command(upgrade)
    cli.add_command(templates)
    cli.add_command(proxy)


_register_commands()

if __name__ == "__main__":
    cli()
