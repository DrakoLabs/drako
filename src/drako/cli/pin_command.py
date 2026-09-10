"""`drako mcp pin` — record a hash-pin for an MCP server (Sprint 2 #1).

Reads the package's exact version + npm dist.integrity from the registry
(operator/CI step, network expected) and writes it into mcp.lock, the
file the backend enforces at spawn (pinned argv + integrity match,
fail-closed). The operator running this command IS the trust decision —
pinned_by records who/what approved these bytes.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import click

_LOCK_VERSION = 1


def _split_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        head, sep, tail = spec[1:].partition("@")
        return ("@" + head, tail or None) if sep else (spec, None)
    head, sep, tail = spec.partition("@")
    return (head, tail or None) if sep else (spec, None)


def _npm_field(spec: str, field: str) -> str:
    try:
        proc = subprocess.run(
            ["npm", "view", spec, field, "--json"],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        raise click.ClickException("npm not found — install Node.js first")
    except subprocess.TimeoutExpired:
        raise click.ClickException(f"npm view timed out for {spec}")
    if proc.returncode != 0:
        raise click.ClickException(
            f"npm view failed for {spec}: {proc.stderr.strip()[:200]}"
        )
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise click.ClickException(f"npm view returned non-JSON for {spec}")
    if not isinstance(value, str) or not value:
        raise click.ClickException(f"no {field} for {spec}")
    return value


@click.group(name="mcp")
def mcp() -> None:
    """Pin and inspect MCP server supply-chain locks."""


@mcp.command(name="pin")
@click.argument("package")
@click.option("--lock", "lock_path", default="mcp.lock",
              help="Lock file to write (default: ./mcp.lock)")
@click.option("--by", "pinned_by", default="",
              help="Who approves these bytes (recorded in the lock)")
def pin(package: str, lock_path: str, pinned_by: str) -> None:
    """Pin PACKAGE[@version] into mcp.lock (version + sha512 integrity).

    Example: drako mcp pin @anthropic/mcp-server-github --by angel
    """
    name, requested = _split_spec(package.strip())
    if not name:
        raise click.ClickException(f"refusing empty package spec {package!r}")
    version = requested or _npm_field(name, "version")
    if requested:
        # Confirm the requested version exists before pinning it.
        _npm_field(f"{name}@{requested}", "version")
    integrity = _npm_field(f"{name}@{version}", "dist.integrity")
    if not integrity.startswith("sha512-"):
        raise click.ClickException(
            f"no usable dist.integrity for {name}@{version} — not pinning"
        )
    lock_file = Path(lock_path)
    if lock_file.exists():
        try:
            data = json.loads(lock_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise click.ClickException(f"existing lock unreadable: {e}")
        if data.get("version") != _LOCK_VERSION:
            raise click.ClickException(
                f"existing lock version {data.get('version')} != {_LOCK_VERSION}"
            )
    else:
        data = {"version": _LOCK_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "servers": {}}
    data.setdefault("servers", {})[name] = {
        "version": version,
        "integrity": integrity,
        "pinned_at": datetime.now(timezone.utc).isoformat(),
        "pinned_by": pinned_by,
    }
    lock_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    click.echo(f"pinned {name}@{version} → {lock_file}")
    click.echo(f"  integrity: {integrity[:32]}… (full hash in lock)")
