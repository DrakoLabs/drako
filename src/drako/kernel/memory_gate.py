"""Memory gate: writes to agent memory are a strict side-effect class.

Threat model (MPBench 2606.04329: 4 injection channels into agent memory;
MemSecBench 2607.27080; Louck origin-bound 2606.24322): tool output and
retrieved context flow INTO memory, and later reads treat memory as
trusted. A sourceless, immortal, or laundered write is a sleeper/MINJA
implant. So memory writes carry three non-negotiable requirements on
top of the lattice floor:

1. ORIGIN MANDATORY — every label in the provenance chain names where
   the bytes came from. A write nobody attributes is unattributable
   by design; deny.
2. TTL MANDATORY — every label carries ttl_seconds and is unexpired.
   Immortal memory is persistence for implants; deny. (Merge already
   takes min-TTL; the gate additionally refuses TTL-less inputs.)
3. LATTICE FLOOR — may_influence(label, AGENT, "memory_write") per
   label: trust >= AGENT and "memory_write" explicitly in scope.
   Tool-output labels (TOOL/UNTRUSTED, or scopes without memory_write)
   cannot launder themselves into memory.

"memory_write" is registered in authority.REQUIRED_TRUST on import so
the envelope treats it as a known class; unknown classes still deny
at the schema gate. Profiles must grant the scope explicitly — empty
scope keeps meaning deny-all (T-1.3 invariant, unchanged).

Deliberately OUT: content inspection of the bytes (that's the injection
scanner's job), cross-session isolation policy (consumer-side scoping
of memory_id), and persistence (consumers store gated writes; the gate
is pure). 100% offline, no network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Sequence

from drako.kernel.authority import (
    REQUIRED_TRUST,
    Label,
    TrustLevel,
    may_influence,
)

MEMORY_WRITE_CLASS = "memory_write"

# Registered on import: known class with AGENT floor. The extra
# origin/TTL rules below are what make it STRICTER than plain "write".
REQUIRED_TRUST.setdefault(MEMORY_WRITE_CLASS, TrustLevel.AGENT)


@dataclass(frozen=True)
class MemoryDecision:
    """Gate verdict for one memory write. permit carries the merged TTL."""

    verdict: str  # "permit" | "deny"
    reason: str
    effective_ttl_seconds: Optional[int] = None


def authorize_memory_write(
    labels: Sequence[Label],
    memory_id: str,
    now: Optional[datetime] = None,
) -> MemoryDecision:
    """Authorize a write of derived bytes into memory_id (pure, testable).

    Deny-closed: any missing origin, missing/expired TTL, insufficient
    trust, or missing scope denies the whole write. Permit returns the
    effective TTL (min over labels) for the consumer to store alongside
    the bytes — storage without the TTL is a gate bypass.
    """
    now = now or datetime.now(timezone.utc)
    if not memory_id or not memory_id.strip():
        return MemoryDecision("deny", "memory write without memory_id")
    if not labels:
        return MemoryDecision(
            "deny",
            f"memory write to {memory_id!r} without provenance "
            "(sourceless writes are unattributable by design)",
        )
    for label in labels:
        if not isinstance(label, Label):
            return MemoryDecision(
                "deny",
                f"memory write to {memory_id!r} carries a non-Label "
                "provenance entry",
            )
        if not label.origin or not label.origin.strip():
            return MemoryDecision(
                "deny",
                f"memory write to {memory_id!r} has a label without origin "
                "(MPBench channel: unattributed context → memory)",
            )
        if label.ttl_seconds is None:
            return MemoryDecision(
                "deny",
                f"memory write to {memory_id!r} from {label.origin!r} has no "
                "TTL (immortal memory is implant persistence)",
            )
        if label.expired(now):
            return MemoryDecision(
                "deny",
                f"memory write to {memory_id!r} from {label.origin!r} is "
                "expired (stale-context replay)",
            )
        if not may_influence(label, TrustLevel.AGENT, MEMORY_WRITE_CLASS):
            return MemoryDecision(
                "deny",
                f"memory write to {memory_id!r} from {label.origin!r} "
                f"fails lattice floor (trust={label.trust.name}, "
                "need >= AGENT with 'memory_write' in scope)",
            )
    ttls = [l.ttl_seconds for l in labels if l.ttl_seconds is not None]
    return MemoryDecision(
        "permit",
        f"memory write to {memory_id!r} authorized "
        f"({len(labels)} label(s), ttl={min(ttls)}s)",
        effective_ttl_seconds=min(ttls) if ttls else None,
    )
