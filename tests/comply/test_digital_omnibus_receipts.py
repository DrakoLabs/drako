"""Tests for EU AI Act Digital Omnibus timeline & Ed25519 receipt ingestion in `drako.comply`."""

from __future__ import annotations

from pathlib import Path

from drako.comply.mapping import build_context
from drako.kernel import ACS_SPEC_PIN
from drako.kernel.authority import Label, TrustLevel
from drako.kernel.envelope import Guardian
from drako.kernel.host import Host, HostConfig
from drako.kernel.receipts import generate_keypair


def test_comply_context_ingests_v4_config_and_receipt_chain(tmp_path: Path):
    # Write local v4 .drako.yaml
    (tmp_path / ".drako.yaml").write_text(
        "version: '4.0'\n"
        "project_id: eu-demo\n"
        "kernel:\n"
        "  spec_pin: AGENT-HOOKS-0.1\n"
        "  receipt_store: .drako/receipts.jsonl\n"
        "audit:\n"
        "  enabled: true\n"
        "hitl:\n"
        "  mode: enforce\n"
        "  triggers:\n"
        "    tools: [wire_transfer]\n",
        encoding="utf-8",
    )

    # Mint 2 chained Ed25519 receipts
    priv, pub = generate_keypair()
    store_path = tmp_path / ".drako" / "receipts.jsonl"
    host = Host(
        Guardian({"spec_pin": ACS_SPEC_PIN, "default_effect": "deny", "tools": {"search": {"id": "r1", "effect": "allow"}}}),
        HostConfig(agent_id="eu-bot", store_path=str(store_path), private_pem=priv, public_pem=pub),
    )
    lbl = Label("user:eu", TrustLevel.USER, frozenset({"read"}))
    host.govern_tool_call("search", {"q": "ok"}, [lbl], side_effect_class="read")
    host.govern_tool_call("wire_transfer", {"amt": 500}, [lbl], side_effect_class="read")

    ctx = build_context(tmp_path)
    assert ctx.audit_trail_enabled is True
    assert ctx.hitl_configured is True
    assert "wire_transfer" in ctx.hitl_triggers
    assert ctx.article50_transparency_active is True
    assert ctx.eu_ai_act_timeline["article_50_2_watermarking_grace_end"] == "2026-12-02"
    assert ctx.eu_ai_act_timeline["annex_iii_high_risk"] == "2027-12-02"
    assert ctx.receipt_evidence["present"] is True
    assert ctx.receipt_evidence["count"] == 2
    assert ctx.receipt_evidence["permits"] == 1
    assert ctx.receipt_evidence["denies"] == 1
    assert ctx.receipt_evidence["chain_contiguous"] is True
