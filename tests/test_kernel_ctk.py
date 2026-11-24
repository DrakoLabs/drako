"""AGENT-HOOKS-0.1 CTK conformance (Sprint 1, route A).

Runs all 47 vectors against DrakoHarness. Asserts ZERO failures; capability-
gated skips (int64_json/bigint_json transports) are reported, not hidden.
Requires the `guardian` extra (agent-hooks-sdk==0.1.0a5, SPEC agent-hooks/0.1).
"""

from __future__ import annotations

import pytest

agent_hooks = pytest.importorskip("agent_hooks", reason="drako[guardian] not installed")

from agent_hooks.ctk.runner import load_vectors, run_vectors

from drako.kernel.ctk_host import DrakoDomainGuard, DrakoHarness


def test_conformance_no_failures():
    vectors = load_vectors(None)
    assert len(vectors) == 47
    results = run_vectors(DrakoHarness, vectors)
    by_status: dict[str, list] = {}
    for r in results:
        by_status.setdefault(r.status, []).append(r)
    fails = by_status.get("fail", [])
    for r in fails:
        print(f"\nFAIL {r.id}: {r.title}")
        for f in (r.failures or [])[:5]:
            print(f"  - {str(f)[:300]}")
    assert not fails, f"{len(fails)} CTK vectors failed"
    skips = by_status.get("skip", [])
    print(f"\nCTK: {len(by_status.get('pass', []))}/{len(vectors)} pass, "
          f"{len(skips)} capability-gated skips: {[r.id for r in skips]}")


def test_domain_guard_standalone():
    """DrakoDomainGuard denies out-of-domain data WITHOUT framework help.

    Kept out of the harness (would defeat Â§7 zero-interceptor vectors);
    lives in the Guardian admission pipeline instead.
    """
    g = DrakoDomainGuard()
    assert g.intercept({"tool_call": {"args": {"expr": "2+2"}}})["decision"] == "allow"
    bad = g.intercept({"tool_call": {"args": {"id": 2**53}}})
    assert bad["decision"] == "deny" and bad["reason"] == "host_error:context_invalid"
    assert g.intercept({"x": float("nan")})["decision"] == "deny"

