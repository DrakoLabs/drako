"""Tests for zero-friction `drako.guard()` and `drako.build_host()` facade."""

from __future__ import annotations

from pathlib import Path

import pytest

import drako
from drako import PolicyViolationError, build_host, guard
from drako.kernel.authority import Label, TrustLevel, sign_consent_token
from drako.kernel.envelope import args_hash
from drako.kernel.receipts import generate_keypair, verify_chain


def test_version_is_alpha_prerelease():
    assert drako.__version__ == "4.0.0a1"


def test_guard_plain_callable_allow_and_deny(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def search_docs(q: str) -> str:
        return f"hits:{q}"

    def delete_volume(vol: str) -> str:
        return f"deleted:{vol}"

    safe_search = guard(search_docs, allow=["search_*"], deny=["delete_*"])
    blocked_delete = guard(delete_volume, allow=["search_*"], deny=["delete_*"])

    assert safe_search(q="owasp") == "hits:owasp"
    with pytest.raises(PolicyViolationError):
        blocked_delete(vol="prod-db")

    # Zero files written to disk by default
    assert list(tmp_path.iterdir()) == []
    assert hasattr(safe_search, "drako_host")


def test_guard_fail_closed_default_deny():
    def unnamed_tool(x: int) -> int:
        return x + 1

    wrapped = guard(unnamed_tool, allow=["other_*"])
    with pytest.raises(PolicyViolationError) as exc_info:
        wrapped(x=1)
    assert exc_info.value.policy_id == "kernel:default-deny"


def test_guard_deny_overrides_allow_on_overlap():
    def delete_tmp(path: str) -> str:
        return path

    wrapped = guard(delete_tmp, allow=["*"], deny=["delete_*"])
    with pytest.raises(PolicyViolationError):
        wrapped(path="/tmp/x")


def test_guard_langgraph_tool_node_wrapper():
    called: list[str] = []

    def fake_tool_node(state: dict) -> dict:
        for tc in state.get("tool_calls", []):
            called.append(tc["name"])
        return {"ran": list(called), "drako_denials": state.get("drako_denials", [])}

    wrapped = guard(
        fake_tool_node,
        framework="langgraph",
        allow=["search_*"],
        deny=["delete_*"],
    )
    out = wrapped(
        {
            "tool_calls": [
                {"id": "1", "name": "search_docs", "args": {"q": "a"}},
                {"id": "2", "name": "delete_volume", "args": {"id": "v1"}},
            ]
        }
    )
    assert called == ["search_docs"]
    assert len(out.get("drako_denials", [])) == 1
    assert out["drako_denials"][0]["name"] == "delete_volume"


def test_build_host_approval_required_and_signed_receipts(tmp_path: Path):
    op_priv, op_pub = generate_keypair()
    r_priv, r_pub = generate_keypair()
    store = tmp_path / "receipts.jsonl"

    host = build_host(
        allow=["search_*"],
        approval_required=["transfer_*"],
        agent_id="payments-bot",
        receipts=store,
        private_pem=r_priv,
        public_pem=r_pub,
        operator_public_pem=op_pub,
    )
    user_prov = [Label("user:cli", TrustLevel.USER, frozenset({"read", "write", "irreversible"}))]

    # Without ConsentToken -> denied with approval seam
    d1, r1 = host.govern_tool_call(
        "transfer_funds",
        {"amount": 500},
        provenance=user_prov,
        side_effect_class="irreversible",
    )
    assert d1.verdict == "deny"
    assert d1.approval is not None

    # With operator-signed ConsentToken bound to args_hash -> permitted
    tok = sign_consent_token(
        token_id="tok-001",
        issuer="human:operator",
        action_hash=args_hash({"amount": 500}),
        expires_at="2099-01-01T00:00:00Z",
        operator_private_pem=op_priv,
    )
    d2, r2 = host.govern_tool_call(
        "transfer_funds",
        {"amount": 500},
        provenance=user_prov,
        side_effect_class="irreversible",
        consent_token=tok,
    )
    assert d2.verdict == "permit"
    assert store.exists()
    ok, bad_idx = verify_chain([r1, r2], r_pub)
    assert ok is True and bad_idx is None
