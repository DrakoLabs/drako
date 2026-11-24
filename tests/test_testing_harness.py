"""Tests for Drako v4 local-first testing harness (`test_mode` and `MockConsentResolver`)."""

from drako.kernel.authority import Label, TrustLevel, verify_consent_token
from drako.kernel.receipts import generate_keypair, verify_receipt
from drako.testing import MockConsentResolver, MockHITLResolver, test_mode as drako_test_mode


def test_mock_consent_resolver_signs_only_approved_tools():
    priv, pub = generate_keypair()
    resolver = MockConsentResolver(default_action="deny", rules={"deploy": "approve"})

    tok_ok = resolver.issue_signed_consent(
        tool_name="deploy", action_hash="hash123", operator_private_pem=priv
    )
    assert tok_ok is not None
    assert verify_consent_token(tok_ok, pub, expected_action_hash="hash123")

    tok_denied = resolver.issue_signed_consent(
        tool_name="delete_db", action_hash="hash999", operator_private_pem=priv
    )
    assert tok_denied is None
    assert len(resolver.call_log) == 2
    assert MockHITLResolver is MockConsentResolver


def test_test_mode_yields_signed_ephemeral_host():
    with drako_test_mode(agent_id="ci-bot") as host:
        d, r = host.govern_tool_call(
            "unknown_tool",
            {},
            [Label("user:u", TrustLevel.USER, frozenset({"read"}))],
            side_effect_class="read",
        )
        assert d.verdict == "deny"
        assert r is not None
        assert verify_receipt(r, host.config.public_pem)
