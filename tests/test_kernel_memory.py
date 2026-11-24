"""Sprint 2 #2: memory-gate suites (2026-09-04). Hermetic, CI-runnable.

Six attack classes mapped to the memory-threat literature (MPBench
2606.04329: injection channels into agent memory; MemSecBench 2607.27080;
MINJA/sleeper persistence): each must DENY except the legitimate write.
Plus: effective-TTL=min property, receipt TTL carriage, and registration
of the memory_write class in the lattice.
"""

from datetime import datetime, timedelta, timezone

import pytest

from drako.kernel.authority import (
    REQUIRED_TRUST,
    Label,
    TrustLevel,
    merge,
)
from drako.kernel.memory_gate import (
    MEMORY_WRITE_CLASS,
    MemoryDecision,
    authorize_memory_write,
)

SCOPE_MEM = frozenset({"read", "write", "memory_write"})


def _label(origin="user:task", trust=TrustLevel.USER, ttl=3600, scope=SCOPE_MEM):
    return Label(origin=origin, trust=trust, ttl_seconds=ttl, scope=scope)


# --- MPBench class 1: unattributed context â†’ memory --------------------------
def test_sourceless_write_denied():
    d = authorize_memory_write([_label(origin="  ")], "mem:session-1")
    assert d.verdict == "deny" and "origin" in d.reason


def test_empty_provenance_denied():
    d = authorize_memory_write([], "mem:session-1")
    assert d.verdict == "deny" and "without provenance" in d.reason


# --- MPBench class 2: immortal write (implant persistence) -------------------
def test_immortal_write_denied():
    d = authorize_memory_write([_label(ttl=None)], "mem:session-1")
    assert d.verdict == "deny" and "no TTL" in d.reason


# --- MPBench class 3: stale-context replay ----------------------------------
def test_expired_write_denied():
    old = Label(origin="user:task", trust=TrustLevel.USER, ttl_seconds=60,
                scope=SCOPE_MEM,
                issued_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat())
    d = authorize_memory_write([old], "mem:session-1")
    assert d.verdict == "deny" and "expired" in d.reason


# --- MPBench class 4: tool-output launder (trust floor) ----------------------
def test_untrusted_tool_output_cannot_write_memory():
    laundered = Label(origin="tool:web_search", trust=TrustLevel.UNTRUSTED,
                      ttl_seconds=3600, scope=SCOPE_MEM)
    d = authorize_memory_write([laundered], "mem:session-1")
    assert d.verdict == "deny" and "lattice floor" in d.reason


# --- MPBench class 5: scope escape (no memory_write grant) -------------------
def test_scope_without_memory_write_denied():
    narrow = _label(scope=frozenset({"read", "write"}))  # legit write scope, no memory
    d = authorize_memory_write([narrow], "mem:session-1")
    assert d.verdict == "deny" and "lattice floor" in d.reason


# --- Legitimate write + merged TTL ------------------------------------------
def test_legit_write_permits_with_min_ttl():
    labels = [_label(ttl=3600), _label(origin="tool:summarizer",
                                       trust=TrustLevel.TOOL, ttl=600)]
    d = authorize_memory_write(labels, "mem:session-1")
    assert d.verdict == "permit"
    assert d.effective_ttl_seconds == 600  # min wins; store WITH the bytes


def test_weakest_link_one_bad_label_denies_all():
    labels = [_label(), _label(origin="")]
    d = authorize_memory_write(labels, "mem:session-1")
    assert d.verdict == "deny"


def test_memory_id_required():
    d = authorize_memory_write([_label()], "  ")
    assert d.verdict == "deny" and "memory_id" in d.reason


def test_non_label_entry_denied():
    d = authorize_memory_write(["user:task"], "mem:session-1")  # type: ignore
    assert d.verdict == "deny" and "non-Label" in d.reason


def test_class_registered_with_agent_floor():
    assert REQUIRED_TRUST[MEMORY_WRITE_CLASS] is TrustLevel.AGENT


def test_merge_ttl_min_property():
    """Merge takes min-TTL: memory reads of merged context expire early."""
    a = _label(ttl=3600)
    b = _label(origin="tool:x", trust=TrustLevel.TOOL, ttl=60)
    m = merge(a, b)
    assert m.ttl_seconds == 60
    assert m.trust is TrustLevel.TOOL


def test_receipt_carries_ttl():
    """Host receipts preserve TTL so stored memory writes stay auditable."""
    from drako.kernel.host import Host, HostConfig
    from drako.kernel.policies import guardian_from_yaml
    from drako.kernel.receipts import generate_keypair

    profile = guardian_from_yaml(
        "spec_pin: AGENT-HOOKS-0.1\ndefault_effect: deny\n"
    )
    host = Host(profile, HostConfig(agent_id="a"))
    _, receipt = host.govern_tool_call(
        "remember", {"fact": "x"},
        provenance=[_label()],
        side_effect_class="write",
    )
    assert receipt is None  # no keys â†’ decisions only, explicit
    # With keys, provenance entries carry ttl_seconds:
    priv_pem, pub_pem = generate_keypair()
    host2 = Host(profile, HostConfig(agent_id="a", private_pem=priv_pem,
                                     public_pem=pub_pem))
    _, r2 = host2.govern_tool_call(
        "remember", {"fact": "x"},
        provenance=[_label(ttl=600)],
        side_effect_class="write",
    )
    prov = r2["provenance"]
    assert prov[0]["ttl_seconds"] == 600
    assert prov[0]["origin"] == "user:task"


def test_decision_dataclass_shape():
    d = MemoryDecision("deny", "r")
    assert d.effective_ttl_seconds is None


def test_origin_ceiling_tool_cannot_claim_user():
    """P1-04: tool-originated labels cap at TOOL (fail-closed build)."""
    from drako.kernel.authority import ceiling_for_origin

    assert ceiling_for_origin("tool:web_search") is TrustLevel.TOOL
    assert ceiling_for_origin("memory:session-9") is TrustLevel.AGENT
    assert ceiling_for_origin("ctk:scripted") is TrustLevel.UNTRUSTED
    assert ceiling_for_origin("user:task") is TrustLevel.USER
    assert ceiling_for_origin("merge(a+b)") is TrustLevel.USER
    with pytest.raises(ValueError, match="cannot assert trust"):
        Label(origin="tool:evil", trust=TrustLevel.USER)
    with pytest.raises(ValueError, match="cannot assert trust"):
        Label(origin="memory:x", trust=TrustLevel.USER)
    # At-ceiling builds fine.
    assert Label(origin="tool:x", trust=TrustLevel.TOOL).trust is TrustLevel.TOOL

