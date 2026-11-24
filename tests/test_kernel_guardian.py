"""Kernel tests: envelope + receipts + authority + policies (Sprint 1, route A).

DOD: deterministic, no network, no backend imports. CTK conformance runs
separately (see test_kernel_ctk.py, requires guardian extra).
"""

from __future__ import annotations

import pytest

from drako.kernel import authority as auth
from drako.kernel.authority import Label, TrustLevel, merge, may_influence
from drako.kernel.envelope import Guardian, Proposal, args_hash
from drako.kernel.eval import UnsafeExpressionError, evaluate_condition
from drako.kernel.policies import ProfileError, compile_profile, guardian_from_yaml
from drako.kernel.receipts import (
    generate_keypair,
    mint_receipt,
    to_slsa_provenance,
    verify_chain,
    verify_receipt,
)


PROFILE_YAML = """
spec_pin: AGENT-HOOKS-0.1
default_effect: deny
tools:
  web_search:
    id: allow-search
    effect: allow
    reason: read-only research tool
  file_delete:
    id: deny-delete
    effect: deny
    reason: destructive op
  db_query:
    id: guard-sql
    effect: deny
    reason: default deny, conditional allow
    conditions:
      - id: readonly-select
        when: "query_type == 'select'"
        effect: allow
  send_email:
    id: email-approval
    effect: deny
    reason: external comms needs consent
    approval_liftable: true
"""


def _label(origin="user:task", trust=TrustLevel.USER, scope=("read", "write", "external_comms", "irreversible")):
    return Label(origin=origin, trust=trust, scope=frozenset(scope))


def _guardian():
    return guardian_from_yaml(PROFILE_YAML)


# -- eval --------------------------------------------------------------------

ADVERSARIAL = [
    "().__class__",
    "__import__('os')",
    "(lambda: 1)()",
    "[x for x in [1]]",
    "task_type.__class__",
    "open('/etc/passwd').read()",
    "eval('1')",
    "1 if True else 2",
    "(((((",
]


@pytest.mark.parametrize("cond", ADVERSARIAL)
def test_eval_rejects_adversarial(cond):
    with pytest.raises(UnsafeExpressionError):
        evaluate_condition(cond, {"task_type": "x"})


def test_eval_legit():
    assert evaluate_condition("a == 1 and b < 5", {"a": 1, "b": 2}) is True
    assert evaluate_condition("not a == 2", {"a": 1}) is True


# -- authority ---------------------------------------------------------------

def test_merge_takes_minimum_trust():
    m = merge(Label("u", TrustLevel.UNTRUSTED), Label("t", TrustLevel.USER))
    assert m.trust == TrustLevel.UNTRUSTED


def test_scope_intersection_deny_by_default():
    m = merge(Label("a", TrustLevel.USER, frozenset({"read"})),
              Label("b", TrustLevel.USER, frozenset({"write"})))
    assert m.scope == frozenset()
    assert may_influence(m, TrustLevel.USER, "read") is False


def test_may_influence_lattice():
    lab = _label(trust=TrustLevel.TOOL, scope=("read",))
    assert may_influence(lab, TrustLevel.AGENT, "read") is True
    assert may_influence(lab, TrustLevel.USER, "read") is False
    assert may_influence(lab, TrustLevel.AGENT, "write") is False


# -- envelope -----------------------------------------------------------------

def test_permit_read():
    d = _guardian().evaluate(Proposal(action="web_search", side_effect_class="read",
                                      args={}, provenance_chain=(_label(trust=TrustLevel.UNTRUSTED),)))
    assert d.verdict == "permit"


def test_default_deny_unknown_tool():
    d = _guardian().evaluate(Proposal(action="nuke", side_effect_class="write",
                                      args={}, provenance_chain=(_label(),)))
    assert d.verdict == "deny" and d.policy_id == "kernel:default-deny"


def test_conditional_allow():
    g = _guardian()
    lab = (_label(),)
    assert g.evaluate(Proposal(action="db_query", side_effect_class="read",
                               args={"query_type": "select"}, provenance_chain=lab)).verdict == "permit"
    assert g.evaluate(Proposal(action="db_query", side_effect_class="read",
                               args={"query_type": "drop"}, provenance_chain=lab)).verdict == "deny"


def test_weak_provenance_blocks():
    d = _guardian().evaluate(Proposal(action="web_search", side_effect_class="write",
                                      args={}, provenance_chain=(_label(trust=TrustLevel.UNTRUSTED),)))
    assert d.verdict == "deny" and "provenance" in d.reason


def test_irreversible_requires_consent():
    d = _guardian().evaluate(Proposal(action="web_search", side_effect_class="irreversible",
                                      args={}, provenance_chain=(_label(),)))
    assert d.verdict == "deny" and d.approval is not None
    assert d.approval["binds"] == args_hash({})


def test_approval_seam_liftable():
    d = _guardian().evaluate(Proposal(action="send_email", side_effect_class="external_comms",
                                      args={"to": "x"}, provenance_chain=(_label(),)))
    assert d.verdict == "deny" and d.approval is not None


def test_fail_closed_synthesis():
    g = _guardian()
    bad = Proposal(action="web_search", side_effect_class="read", args={},
                   provenance_chain=("not-a-label",))  # type: ignore
    d = g.evaluate(bad)
    assert d.verdict == "deny" and d.reason.startswith("host_error:")


def test_unknown_side_effect_class_denied():
    d = _guardian().evaluate(Proposal(action="web_search", side_effect_class="teleport",
                                      args={}, provenance_chain=(_label(),)))
    assert d.verdict == "deny"


def test_hooks_verdict_mapping():
    assert Guardian.to_hooks_verdict(
        type("D", (), {"verdict": "permit", "reason": "r", "modifications": None, "approval": None})()
    ) == {"verdict": "allow", "reason": "r"}


# -- policies ------------------------------------------------------------------

def test_profile_rejects_bad_pin():
    with pytest.raises(ProfileError):
        compile_profile({"spec_pin": "NOPE", "tools": {}})


def test_profile_rejects_unsafe_condition_grammar():
    with pytest.raises(ProfileError):
        compile_profile({"spec_pin": "AGENT-HOOKS-0.1",
                         "tools": {"t": {"effect": "allow",
                                         "conditions": [{"id": "x", "when": "f()"}]}}})


# -- receipts -------------------------------------------------------------------

def test_receipt_sign_verify_chain():
    priv, pub = generate_keypair()
    r1 = mint_receipt(decision="permit", policy_id="p", reason="ok", tool_name="web_search",
                      agent_id="a", args_hash="h", private_pem=priv, public_pem=pub)
    r2 = mint_receipt(decision="deny", policy_id="p", reason="no", tool_name="x",
                      agent_id="a", args_hash="h2", prev_hash=r1["payload_hash"],
                      private_pem=priv, public_pem=pub)
    assert verify_receipt(r1, pub) is True
    ok, idx = verify_chain([r1, r2], pub)
    assert (ok, idx) == (True, None)
    # Tamper â†’ exact failing index
    r2b = dict(r2, reason="forged")
    ok, idx = verify_chain([r1, r2b], pub)
    assert (ok, idx) == (False, 1)
    # Wrong key â†’ False, never raise
    _, pub2 = generate_keypair()
    assert verify_receipt(r1, pub2) is False


def test_receipt_never_unsigned():
    with pytest.raises(Exception):
        mint_receipt(decision="maybe", policy_id="p", reason="x", tool_name="t",
                     agent_id="a", args_hash="h", private_pem="x", public_pem="y")


def test_slsa_shape():
    priv, pub = generate_keypair()
    r = mint_receipt(decision="permit", policy_id="p", reason="ok", tool_name="t",
                     agent_id="a", args_hash="h", private_pem=priv, public_pem=pub)
    s = to_slsa_provenance(r)
    assert s["_type"] == "https://in-toto.io/Statement/v1"
    assert s["subject"][0]["digest"]["sha256"] == r["payload_hash"]

