"""
tools/list runtime drift detection.

Deadbugz (Pillar/CSA 02-sep-2026, Omnafy 09-sep-2026) proved the gap:
a server benign for the first 3 calls, then mutating tools/list (and
prompts/get) into credential-seeking instructions. Pins, signatures,
SBOMs and code review all inspect ARTIFACTS; the payload is a dynamic
RESPONSE. So every tools/list refresh is a security event: hash the
normalized definitions, compare against the session baseline, and
treat ANY mutation as compromise until re-approved.

Baseline scope is deliberately per-connection (in-memory): a fresh
process re-baselines because the server-side counter also resets per
client — the attack replays benign-first every session, and each
session catches the mutation on call 4+. Operator-pinned baselines
(AgBOM snapshot compare) are the follow-up, not the substitute.

Pure functions (testable); clients own the baseline slot and the
kill action.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def fingerprint_tools(tools: list[dict[str, Any]] | list[Any]) -> str:
    """Canonical hash of tool definitions (name+description+schema).

    Order-independent (servers may reorder); descriptions included
    because THAT is what Deadbugz mutates. Returns 'sha256:<hex>'.
    """
    normalized = []
    for t in tools or []:
        if isinstance(t, dict):
            normalized.append({
                "name": str(t.get("name", "")),
                "description": str(t.get("description", "")),
                "inputSchema": t.get("inputSchema", t.get("input_schema", {})),
            })
        else:
            normalized.append({
                "name": str(getattr(t, "name", "")),
                "description": str(getattr(t, "description", "")),
                "inputSchema": getattr(t, "input_schema",
                                       getattr(t, "inputSchema", {})),
            })
    blob = json.dumps(sorted(normalized, key=lambda e: e["name"]),
                      sort_keys=True, separators=(",", ":"),
                      default=str).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


class ToolsDriftError(RuntimeError):
    """tools/list mutated mid-session. Fail-closed."""


def check_tools_drift(baseline_fp: str | None,
                      tools: list[dict[str, Any]] | list[Any],
                      server_id: str) -> str:
    """Compare current definitions against the session baseline.

    Returns the fingerprint to store (baseline on first call). Raises
    ToolsDriftError on mutation. First call never raises — baselining
    is normal; MUTATION is the signal.
    """
    current = fingerprint_tools(tools)
    if baseline_fp is None:
        return current
    if current != baseline_fp:
        raise ToolsDriftError(
            f"mcp tools/list DRIFT on {server_id}: definitions mutated "
            f"mid-session ({baseline_fp[:19]}… → {current[:19]}…) — "
            "possible Deadbugz-class metadata poisoning. Refusing to "
            "use the mutated set (fail-closed)"
        )
    return current
