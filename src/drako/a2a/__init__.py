"""Drako A2A v1.0 cryptographic identity — Signed Agent Cards (RFC 7515 JWS + RFC 8785 JCS)."""

from drako.a2a.cards import (
    AgentCardError,
    canonicalize_agent_card,
    card_fingerprint,
    fetch_and_verify_agent_card,
    sign_agent_card,
    verify_agent_card,
)

__all__ = [
    "AgentCardError",
    "canonicalize_agent_card",
    "card_fingerprint",
    "fetch_and_verify_agent_card",
    "sign_agent_card",
    "verify_agent_card",
]
