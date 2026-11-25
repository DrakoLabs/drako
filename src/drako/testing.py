"""Local-first test harness for Drako v4 Authority Kernel workflows."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any


class MockConsentResolver:
    """Deterministic operator consent resolver for unit and CI tests.

    Simulates the "AI proposes, human signs" pattern offline without prompting
    interactively.
    """

    def __init__(
        self,
        default_action: str = "deny",
        rules: dict[str, str] | None = None,
    ) -> None:
        if default_action not in ("approve", "deny"):
            raise ValueError(f"default_action must be 'approve' or 'deny', got {default_action!r}")
        self.default_action = default_action
        self.rules: dict[str, str] = dict(rules or {})
        self.call_log: list[dict[str, Any]] = []

    def resolve(self, tool_name: str, action_hash: str) -> bool:
        decision = self.rules.get(tool_name, self.default_action)
        approved = decision == "approve"
        self.call_log.append(
            {
                "tool_name": tool_name,
                "action_hash": action_hash,
                "approved": approved,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        return approved

    def issue_signed_consent(
        self,
        *,
        tool_name: str,
        action_hash: str,
        operator_private_pem: str,
        issuer: str = "human:test-operator",
        ttl_seconds: int = 300,
    ):
        """Sign an Ed25519 ConsentToken if approved by rules; return None if denied."""
        if not self.resolve(tool_name, action_hash):
            return None
        from drako.kernel.authority import sign_consent_token

        expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        return sign_consent_token(
            token_id=f"test-{len(self.call_log)}",
            issuer=issuer,
            action_hash=action_hash,
            expires_at=expires,
            operator_private_pem=operator_private_pem,
        )


# Backward-compatible alias for v3 test suites migrating to v4
MockHITLResolver = MockConsentResolver


@contextmanager
def test_mode(
    *,
    profile: dict[str, Any] | None = None,
    agent_id: str = "test-agent",
    signed: bool = True,
) -> Iterator[Any]:
    """Yield an ephemeral in-memory `drako.kernel.Host` with fresh Ed25519 keys."""
    from drako.kernel import ACS_SPEC_PIN
    from drako.kernel.envelope import Guardian
    from drako.kernel.host import Host, HostConfig
    from drako.kernel.receipts import generate_keypair

    effective_profile = profile or {
        "spec_pin": ACS_SPEC_PIN,
        "default_effect": "deny",
        "tools": {},
    }
    priv, pub = generate_keypair() if signed else (None, None)
    host = Host(
        Guardian(effective_profile),
        HostConfig(agent_id=agent_id, private_pem=priv, public_pem=pub),
    )
    yield host
