"""Tests for A2A v1.0 Signed Agent Cards (RFC 7515 Detached JWS + RFC 8785 JCS)."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from drako.a2a.cards import (
    canonicalize_agent_card,
    card_fingerprint,
    fetch_and_verify_agent_card,
    sign_agent_card,
    verify_agent_card,
)
from drako.kernel.egress import EgressViolation
from drako.kernel.receipts import generate_keypair


def _sample_card() -> dict:
    return {
        "name": "Acme Forex Agent",
        "description": "Converts currencies safely.",
        "version": "1.0.0",
        "url": "https://forex.example.com/a2a",
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {"id": "convert", "name": "Currency Converter", "tags": ["forex"]}
        ],
    }


def test_sign_and_verify_roundtrip():
    priv, pub = generate_keypair()
    signed = sign_agent_card(_sample_card(), priv, kid="did:example:acme#sig1")
    assert "signatures" in signed
    assert len(signed["signatures"]) == 1
    assert set(signed["signatures"][0].keys()) == {"protected", "signature"}
    assert verify_agent_card(signed, pub) is True
    assert verify_agent_card(signed, pub, expected_kid="did:example:acme#sig1") is True
    assert verify_agent_card(signed, pub, expected_kid="did:example:other#sig1") is False


def test_default_stripping_canonical_invariance():
    card_a = _sample_card()
    card_b = copy.deepcopy(card_a)
    card_b["optionalEmpty"] = ""
    card_b["optionalNull"] = None
    card_b["optionalList"] = []
    card_b["optionalDict"] = {}
    assert canonicalize_agent_card(card_a) == canonicalize_agent_card(card_b)
    assert card_fingerprint(card_a) == card_fingerprint(card_b)


def test_tampering_url_or_skills_fails_closed():
    priv, pub = generate_keypair()
    signed = sign_agent_card(_sample_card(), priv, kid="k1")

    tampered_url = copy.deepcopy(signed)
    tampered_url["url"] = "https://evil.example.com/a2a"
    assert verify_agent_card(tampered_url, pub) is False

    tampered_skill = copy.deepcopy(signed)
    tampered_skill["skills"][0]["id"] = "drain_wallet"
    assert verify_agent_card(tampered_skill, pub) is False


def test_wrong_key_and_unsigned_fail_closed():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    signed = sign_agent_card(_sample_card(), priv, kid="k1")
    assert verify_agent_card(signed, other_pub) is False
    assert verify_agent_card(_sample_card(), other_pub) is False
    assert verify_agent_card({"signatures": []}, other_pub) is False
    assert verify_agent_card("not-a-dict", other_pub) is False


def test_expiry_enforced_unless_ignored():
    priv, pub = generate_keypair()
    past = datetime(2025, 1, 1, tzinfo=timezone.utc)
    signed = sign_agent_card(_sample_card(), priv, kid="k1", ttl_days=1, now=past)
    now = past + timedelta(days=5)
    assert verify_agent_card(signed, pub, now=now) is False
    assert verify_agent_card(signed, pub, now=now, ignore_expiry=True) is True


def test_fetch_blocks_private_ssrf():
    _, pub = generate_keypair()
    with pytest.raises(EgressViolation):
        fetch_and_verify_agent_card("http://169.254.169.254/latest/meta-data/", pub)
    with pytest.raises(EgressViolation):
        fetch_and_verify_agent_card("https://127.0.0.1/.well-known/agent-card.json", pub)
