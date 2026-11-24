"""MCP server admission: the package NAME is the trust decision (U-6).

Before any pin check or spawn, the operator's declared server set
answers one question: is this package ADMITTED here at all? Three
inputs, deny-closed:

1. Declaration — the package must be pinned in mcp.lock (undeclared
   servers are not admitted, even with a valid registry hash).
2. Scope allowlist (optional) — when the operator sets one, only
   listed packages admit (curated set); when unset, any PINNED package
   admits (pin-only posture).
3. Version authority — the admitted spec is ALWAYS the lock's
   name@version, never the requester's string (downgrade/confusion
   resistance at the admission layer, enforced again at spawn).

Pure function over caller-supplied lock mapping ({package: spec}) so
the kernel stays transport-agnostic; the backend executor is the
enforcement point that re-verifies integrity at spawn time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    reason: str
    admitted_spec: str | None = None  # lock's name@version, if admitted


def _bare_name(spec: str) -> str:
    """Strip an optional @version (scoped packages keep their scope)."""
    if spec.startswith("@"):
        head, _, _ = spec[1:].partition("@")
        return "@" + head
    head, _, _ = spec.partition("@")
    return head


def admit(
    package: str,
    lock: Mapping[str, str],
    allowed_packages: Sequence[str] | None = None,
) -> AdmissionDecision:
    """Admit a server package (pure, testable). Deny-closed."""
    name = _bare_name((package or "").strip())
    if not name or name == "@":
        return AdmissionDecision(False, "empty package name")
    pinned_spec = lock.get(name)
    if pinned_spec is None:
        return AdmissionDecision(
            False,
            f"{name!r} is not declared in mcp.lock — undeclared servers "
            "are not admitted",
        )
    if allowed_packages is not None and name not in allowed_packages:
        return AdmissionDecision(
            False,
            f"{name!r} is pinned but outside the operator allowlist "
            f"({len(allowed_packages)} admitted)",
        )
    return AdmissionDecision(True, f"{name!r} admitted as {pinned_spec}",
                             admitted_spec=pinned_spec)
