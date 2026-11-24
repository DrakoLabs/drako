"""
mcp.lock — hash-pin for NPX MCP servers (Sprint 2 #1, 2026-09-04).

Closes the U-6 unnamed risk: `npx -y <pkg>` auto-installs from the npm
registry WITHOUT A PIN — the bytes installed today are not provably the
bytes approved yesterday (postmark-mcp class). This module is the fix
that legitimizes `-y`:

- `mcp.lock` (JSON, server-side, path via DRAKO_MCP_LOCK or default
  ./mcp.lock) maps package name → {version, integrity, pinned_at, pinned_by}.
- Enforcement (in NPXMCPExecutor.start): the argv uses the PINNED
  `name@version` (never a floating spec), and the registry integrity for
  that exact version (`npm view name@version dist.integrity --json`) must
  match the lock — mismatch or missing entry fails CLOSED.
- No lock file at all = interim posture (warning, install floating):
  allowed ONLY until this Sprint 2 item lands; after that, server boot
  with DRAKO_MCP_ENFORCE_PIN=1 (default) refuses to start pool entries
  for unpinned packages.

`integrity` is the npm `dist.integrity` string (`sha512-<base64>`), the
same field npm itself verifies on install. Generation is an operator/CI
step: `drako mcp pin <package[@version]>` (SDK side) or hand-editing the
JSON — both record WHO pinned and WHEN (auditability of the trust
decision: the name remains the trust decision, now with a hash).

Deliberately OUT of scope for v1: transitive dependency pinning
(use npm's own lockfile inside prebuilt server images for that),
Sigstore provenance verification, and a server registry/admission UI.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

LOCK_VERSION = 1
DEFAULT_LOCK_PATH = Path("mcp.lock")
NPM_VIEW_TIMEOUT_SECONDS = 15.0

# P0-hunt (2026-09-10): the lock file is operator-trust, but a malformed
# or hostile entry must not become argv confusion. Versions are exact
# pins (no ranges); names must already have passed _PACKAGE_RE at the
# executor layer — re-checked here for defense in depth.
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._~+\-]*$")
_NAME_RE = re.compile(
    r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$"
)


@dataclass(frozen=True)
class PinnedServer:
    """One pinned MCP server: exact version + registry integrity hash."""

    package: str          # bare name, no version (@scope/pkg, never a URL)
    version: str          # exact, e.g. 1.2.3 (no ranges/caret)
    integrity: str        # npm dist.integrity, e.g. sha512-<base64>
    pinned_at: str = ""   # ISO-8601 UTC
    pinned_by: str = ""   # who/what approved these bytes (audit trail)

    @property
    def spec(self) -> str:
        """Pinned argv spec: name@version, never floating."""
        return f"{self.package}@{self.version}"


class LockError(ValueError):
    """Malformed lock file or pin violation. Fail-closed."""


def load_lock(path: str | Path | None = None) -> dict[str, PinnedServer]:
    """Load mcp.lock → {package: PinnedServer}. Missing file = {} (interim).

    Raises LockError on malformed JSON, wrong version, or entries missing
    package/version/integrity. A lock that cannot be read strictly is
    worse than no lock (false assurance), so strictness is the default.
    """
    p = Path(path or os.environ.get("DRAKO_MCP_LOCK", DEFAULT_LOCK_PATH))
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise LockError(f"mcp.lock unreadable at {p}: {e}") from e
    if not isinstance(raw, dict) or raw.get("version") != LOCK_VERSION:
        raise LockError(
            f"mcp.lock at {p}: expected {{'version': {LOCK_VERSION}, ...}}"
        )
    servers = raw.get("servers", {})
    if not isinstance(servers, dict):
        raise LockError(f"mcp.lock at {p}: 'servers' must be an object")
    out: dict[str, PinnedServer] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            raise LockError(f"mcp.lock entry {name!r}: must be an object")
        if not _NAME_RE.match(name):
            raise LockError(f"mcp.lock entry {name!r}: invalid package name")
        for field in ("version", "integrity"):
            if not entry.get(field) or not isinstance(entry[field], str):
                raise LockError(
                    f"mcp.lock entry {name!r}: missing/invalid {field!r}"
                )
        if not _VERSION_RE.match(entry["version"]):
            raise LockError(
                f"mcp.lock entry {name!r}: version must be an exact pin "
                f"(no ranges), got {entry['version']!r}"
            )
        if not entry["integrity"].startswith("sha512-"):
            raise LockError(
                f"mcp.lock entry {name!r}: integrity must be npm "
                "dist.integrity (sha512-…)"
            )
        out[name] = PinnedServer(
            package=name,
            version=entry["version"],
            integrity=entry["integrity"],
            pinned_at=str(entry.get("pinned_at", "")),
            pinned_by=str(entry.get("pinned_by", "")),
        )
    return out


def empty_lock() -> str:
    """Template mcp.lock JSON for operators to fill (drako mcp pin)."""
    return json.dumps(
        {
            "version": LOCK_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "servers": {},
        },
        indent=2,
    ) + "\n"


async def registry_integrity(package: str, version: str) -> str:
    """Fetch npm dist.integrity for an exact version (operator/CI network).

    Returns the integrity string. Raises LockError when npm is missing,
    the version does not exist, or the field is absent — all fail-closed.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "view", f"{package}@{version}", "dist.integrity", "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(
            proc.communicate(), timeout=NPM_VIEW_TIMEOUT_SECONDS
        )
    except FileNotFoundError as e:
        raise LockError("npm not found — cannot verify pin integrity") from e
    except asyncio.TimeoutError as e:
        raise LockError(
            f"npm view timed out for {package}@{version} — fail-closed"
        ) from e
    if proc.returncode != 0:
        raise LockError(
            f"npm view failed for {package}@{version}: "
            f"{err.decode(errors='replace')[:200]}"
        )
    try:
        integrity = json.loads(out.decode())
    except json.JSONDecodeError as e:
        raise LockError(f"npm view returned non-JSON for {package}@{version}") from e
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise LockError(
            f"no usable dist.integrity for {package}@{version} — fail-closed"
        )
    return integrity


def check_pin(
    package: str,
    lock: dict[str, PinnedServer],
    registry_integrity_value: str,
) -> PinnedServer:
    """Pure pin check (testable): entry must exist and integrity must match.

    Returns the PinnedServer whose .spec builds the spawn argv.
    Raises LockError otherwise. The package NAME remains the trust
    decision (curated by the operator); the hash makes it enforceable.
    """
    pinned = lock.get(package)
    if pinned is None:
        raise LockError(
            f"no mcp.lock pin for {package!r} — refusing to auto-install "
            "an unpinned server (fail-closed). Pin it: record version + "
            "dist.integrity in mcp.lock"
        )
    if registry_integrity_value != pinned.integrity:
        raise LockError(
            f"integrity mismatch for {pinned.spec}: registry reports a "
            "different dist.integrity than mcp.lock — possible registry "
            "confusion or tampering. Refusing to start (fail-closed)"
        )
    return pinned


def enforcement_enabled() -> bool:
    """DRAKO_MCP_ENFORCE_PIN=0 opts out (emergency only, audited at use)."""
    return os.environ.get("DRAKO_MCP_ENFORCE_PIN", "1") != "0"
