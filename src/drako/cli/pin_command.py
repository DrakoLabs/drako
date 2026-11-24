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


from drako.cli.audit_command import audit as _audit  # noqa: E402
mcp.add_command(_audit)


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
    if not requested:
        # P0-hunt (2026-09-10): pinning a mutable tag is TOFU on
        # whatever the registry serves RIGHT NOW. Loud, not silent.
        click.secho(
            "  [warn]   no @version given — resolving 'latest' and pinning "
            "whatever the registry serves now (TOFU). Prefer an explicit "
            "@x.y.z you have verified.",
            fg="yellow",
        )
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
    click.echo(f"pinned {name}@{version} -> {lock_file}")
    click.echo(f"  integrity: {integrity[:32]}... (full hash in lock)")


@mcp.command(name="agbom")
@click.option("--lock", "lock_path", default="mcp.lock", help="Input mcp.lock path")
@click.option(
    "--format", "output_format",
    type=click.Choice(["snapshot", "cyclonedx", "cyclonedx-1.6"]),
    default="cyclonedx",
    help="Output format (default: CycloneDX 1.7 ECMA-424)",
)
@click.option("--output", "-o", default=None, help="Write AgBOM to file")
def agbom_cmd(lock_path: str, output_format: str, output: str | None) -> None:
    """Generate a canonical AgBOM or CycloneDX 1.7 SBOM from mcp.lock."""
    from drako.mcp_guard.agbom import agbom_to_cyclonedx, canonical_snapshot, lock_hash
    from drako.mcp_guard.lock import LockError, load_lock

    p = Path(lock_path)
    if not p.exists():
        raise click.ClickException(f"mcp.lock not found at {lock_path} (run `drako mcp pin` first)")
    try:
        locked = load_lock(p)
    except LockError as exc:
        raise click.ClickException(str(exc)) from exc

    admitted = [
        {
            "package": srv.package,
            "version": srv.version,
            "integrity": srv.integrity,
            "admitted_spec": srv.spec,
        }
        for srv in locked.values()
    ]
    snap = canonical_snapshot(admitted, lock_hash=lock_hash(p.read_text(encoding="utf-8")))
    if output_format == "snapshot":
        doc = snap
    elif output_format == "cyclonedx-1.6":
        doc = agbom_to_cyclonedx(snap, spec_version="1.6")
    else:
        doc = agbom_to_cyclonedx(snap, spec_version="1.7")

    rendered = json.dumps(doc, indent=2) + "\n"
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        click.echo(f"AgBOM written to {output}")
    else:
        click.echo(rendered)


@mcp.command(name="check-drift")
@click.argument("endpoint")
@click.option("--baseline-hash", default=None, help="Expected sha256:... tools/list fingerprint")
@click.option("--allow-private", is_flag=True, help="Allow private/loopback URLs (local dev only)")
def check_drift_cmd(endpoint: str, baseline_hash: str | None, allow_private: bool) -> None:
    """Query a stateless MCP 2026-07-28 server's tools/list and verify against a baseline hash."""
    from drako.kernel.egress import EgressViolation
    from drako.mcp_guard.client import MCPClientError, MCPGAClient
    from drako.mcp_guard.drift import ToolsDriftError, check_tools_drift

    try:
        client = MCPGAClient(endpoint, allow_private=allow_private)
        tools = client.list_tools()
        fp = check_tools_drift(baseline_hash, tools, endpoint)
    except (EgressViolation, MCPClientError, ToolsDriftError) as exc:
        click.secho(f"  [FAIL] {exc}", fg="red", err=True)
        raise SystemExit(1)
    click.echo(json.dumps({"endpoint": endpoint, "tool_count": len(tools), "fingerprint": fp, "drift": False}, indent=2))
