"""Tests for Drako v4 kernel extensions: signed ConsentTokens, OriginAttester, Q1 HMAC grader, LoopBreaker, Egress, Proxy."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pytest

from drako.kernel import ACS_SPEC_PIN
from drako.kernel.authority import (
    Label,
    OriginAttester,
    TrustLevel,
    sign_consent_token,
    verify_consent_token,
)
from drako.kernel.egress import EgressViolation, assert_public_url, resolve_redirect
from drako.kernel.envelope import Guardian, Proposal, args_hash
from drako.kernel.host import Host, HostConfig
from drako.kernel.loop_breaker import LoopBreaker, call_fingerprint
from drako.kernel.receipts import (
    _canonical,
    generate_keypair,
    mint_receipt,
    provenance_subgraph,
    verify_chain,
    verify_receipt,
    verify_receipt_hmac,
)


def test_operator_signed_consent_token_lifts_irreversible_action():
    op_priv, op_pub = generate_keypair()
    host_priv, host_pub = generate_keypair()

    profile = {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": "deny",
        "tools": {
            "delete_volume": {
                "id": "rule:delete-vol",
                "effect": "deny",
                "reason": "Destructive action requires operator signature",
                "approval_liftable": True,
            }
        },
    }
    host = Host(
        Guardian(profile),
        HostConfig(
            agent_id="ops-agent",
            private_pem=host_priv,
            public_pem=host_pub,
            operator_public_pem=op_pub,
        ),
    )

    user_label = Label("user:task", TrustLevel.USER, frozenset({"irreversible"}))
    args = {"volume_id": "vol-prod-1"}

    # 1. Without consent -> deny + approval seam
    d1, r1 = host.govern_tool_call("delete_volume", args, [user_label], side_effect_class="irreversible")
    assert d1.verdict == "deny"
    assert d1.approval is not None
    assert r1 is not None and verify_receipt(r1, host_pub)

    # 2. Operator signs ConsentToken bound to exact args_hash (operator key never touches Host)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    token = sign_consent_token(
        token_id="ct-1",
        issuer="human:alice",
        action_hash=d1.approval["binds"],
        expires_at=expires,
        operator_private_pem=op_priv,
    )
    assert verify_consent_token(token, op_pub, expected_action_hash=args_hash(args))

    # 3. Same args with signed token -> permit!
    d2, r2 = host.govern_tool_call(
        "delete_volume", args, [user_label], side_effect_class="irreversible", consent_token=token
    )
    assert d2.verdict == "permit"
    assert "consent-verified" in d2.trace
    assert r2 is not None and verify_chain([r1, r2], host_pub) == (True, None)

    # 4. Anti-TOCTOU: swapping args with same token -> DENY!
    d3, _ = host.govern_tool_call(
        "delete_volume",
        {"volume_id": "vol-prod-ALL"},
        [user_label],
        side_effect_class="irreversible",
        consent_token=token,
    )
    assert d3.verdict == "deny"


def test_origin_attester_detects_forged_label():
    attester = OriginAttester()
    good = attester.issue(origin="tool:search", trust=TrustLevel.TOOL, scope=frozenset({"read"}))
    assert attester.verify(good) is True

    forged = Label(origin="tool:search", trust=TrustLevel.TOOL, scope=frozenset({"read"}))
    assert attester.verify(forged) is False


def test_q1_hmac_grader_always_telemetry_never_evidence():
    secret = b"shared-secret-key"
    body = {"decision": "permit", "tool_name": "read", "agent_id": "a1"}
    canonical = _canonical(body)
    receipt = {
        **body,
        "payload_hash": hashlib.sha256(canonical).hexdigest(),
        "hmac": hmac.new(secret, canonical, hashlib.sha256).hexdigest(),
    }
    ok, grade = verify_receipt_hmac(receipt, secret)
    assert ok is True
    assert grade == "telemetry"  # NEVER "evidence"

    ok_bad, grade_bad = verify_receipt_hmac(receipt, b"wrong-secret")
    assert ok_bad is False
    assert grade_bad == "invalid"


def test_provenance_subgraph_structure():
    priv, pub = generate_keypair()
    r = mint_receipt(
        decision="permit",
        policy_id="rule:search",
        reason="ok",
        tool_name="search",
        agent_id="a1",
        args_hash="abc",
        provenance=[{"origin": "user:prompt", "trust": "USER", "ttl_seconds": 60}],
        prev_hash="0" * 64,
        private_pem=priv,
        public_pem=pub,
    )
    graph = provenance_subgraph(r)
    assert graph["receipt_id"] == r["receipt_id"]
    kinds = {n["kind"] for n in graph["nodes"]}
    assert kinds == {"decision", "chain_parent", "provenance"}
    assert len(graph["edges"]) == 2


def test_host_loop_breaker_trips_and_mints_receipt():
    priv, pub = generate_keypair()
    profile = {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": "permit",
        "tools": {"ping": {"id": "rule:ping", "effect": "allow"}},
    }
    host = Host(
        Guardian(profile),
        HostConfig(
            agent_id="looper",
            private_pem=priv,
            public_pem=pub,
            enable_loop_breaker=True,
            loop_threshold=3,
            loop_window_seconds=60.0,
        ),
    )
    receipts = []
    for _ in range(2):
        d, r = host.govern_tool_call("ping", {"x": 1}, side_effect_class="read")
        assert d.verdict == "permit"
        receipts.append(r)

    # 3rd identical call trips the circuit breaker
    d3, r3 = host.govern_tool_call("ping", {"x": 1}, side_effect_class="read")
    assert d3.verdict == "deny"
    assert d3.policy_id == "kernel:loop-breaker"
    receipts.append(r3)
    assert verify_chain(receipts, pub) == (True, None)


def test_host_govern_memory_write_chains_receipts():
    priv, pub = generate_keypair()
    host = Host(
        Guardian({"spec_pin": ACS_SPEC_PIN, "default_effect": "deny", "tools": {}}),
        HostConfig(agent_id="mem-agent", private_pem=priv, public_pem=pub),
    )
    bad_label = Label("tool:web", TrustLevel.TOOL, frozenset({"read"}))
    m1, r1 = host.govern_memory_write("session-mem", [bad_label])
    assert m1.verdict == "deny"
    assert r1 is not None

    good_label = Label("memory:verified", TrustLevel.AGENT, frozenset({"memory_write"}), ttl_seconds=600)
    m2, r2 = host.govern_memory_write("session-mem", [good_label])
    assert m2.verdict == "permit"
    assert m2.effective_ttl_seconds == 600
    assert r2 is not None
    assert verify_chain([r1, r2], pub) == (True, None)


def test_egress_blocks_ssrf_and_redirects():
    with pytest.raises(EgressViolation):
        assert_public_url("http://example.com")
    with pytest.raises(EgressViolation):
        assert_public_url("https://169.254.169.254/latest")
    with pytest.raises(EgressViolation):
        assert_public_url("https://10.0.0.1/internal")
    with pytest.raises(EgressViolation):
        assert_public_url("https://127.0.0.1/admin")
    with pytest.raises(EgressViolation):
        resolve_redirect("https://example.com", "https://127.0.0.1/x", hop=0)
    with pytest.raises(EgressViolation, match="too many redirects"):
        resolve_redirect("https://example.com", "https://example.org", hop=3)


def test_proxy_v4_auth_and_loop_breaker(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from drako.proxy.proxy_server import create_app

    cfg = tmp_path / ".drako.yaml"
    cfg.write_text(
        "version: '4.0'\nloop_breaker:\n  enabled: true\n  trip_threshold: 2\n  window_seconds: 60\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DRAKO_PROXY_TOKEN", "test-secret-token")
    monkeypatch.delenv("DRAKO_DEV_UNSAFE", raising=False)

    app = create_app(str(cfg))
    client = TestClient(app)

    # /health public
    assert client.get("/health").status_code == 200
    # /status requires bearer token (no 422 regression!)
    assert client.get("/status").status_code == 401
    assert client.get("/status", headers={"Authorization": "Bearer test-secret-token"}).status_code == 200
    # Unknown target returns 400 (not 422!)
    assert client.post("/unknown/v1/chat", json={"model": "gpt-5"}).status_code == 400
