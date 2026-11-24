"""Authority lattice: origin-bound, non-malleable (Louck TMA-NM, T1–T3).

Trust levels are totally ordered; labels only narrow (⊑), never widen.
Elevation requires an independent ConsentToken (operator-signed Ed25519 or
policy-issued), never self-assertion by untrusted data.

Operator-Signing vs Target-Verification (ADR-0002 / ADR-0003):
  - Operators sign `ConsentToken`s offline (`drako kernel sign-consent`) with
    their private Ed25519 key; private keys NEVER need to live in the agent's
    runtime process.
  - The target `Guardian`/`Host` verifies `ConsentToken`s against a sealed
    operator public key, bound to `action_hash` (anti-TOCTOU).

Scope: bounded-model property tests in CI (Hypothesis); always claim
"property-tested non-malleability", never "proven".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Optional


class TrustLevel(IntEnum):
    UNTRUSTED = 0
    AGENT = 1
    TOOL = 2
    USER = 3


_ORIGIN_CEILINGS: tuple[tuple[str, TrustLevel], ...] = (
    ("tool:", TrustLevel.TOOL),
    ("memory:", TrustLevel.AGENT),
    ("ctk:", TrustLevel.UNTRUSTED),
)


def ceiling_for_origin(origin: str) -> TrustLevel:
    """Max trust an origin class may assert (P1-04, pure, testable)."""
    for prefix, ceiling in _ORIGIN_CEILINGS:
        if origin.startswith(prefix):
            return ceiling
    return TrustLevel.USER


@dataclass(frozen=True)
class Label:
    """Provenance label bound at write time (M1).

    Trust is CAPPED by origin class at construction — a tool-originated label
    can never assert USER trust no matter what the caller claims (TMA-NM
    laundering: self-summarization, trusted-tool echo, fabricated corroboration).

    Ceilings:
    - ``tool:*``   -> TOOL (tool outputs are never user-direct)
    - ``memory:*`` -> AGENT (derived data is never user-direct)
    - ``ctk:*``    -> UNTRUSTED (scripted fixtures prove nothing)
    - anything else (``user:*``, ``merge(*)``, ...) -> USER

    Residual limit, stated honestly: within a ceiling, arbitrary in-process
    code could still fabricate a ``tool:*`` label unless bound via
    ``OriginAttester`` (host-scoped HMAC call-site tag).
    """

    origin: str
    trust: TrustLevel = TrustLevel.UNTRUSTED
    scope: frozenset = field(default_factory=frozenset)
    ttl_seconds: Optional[int] = None
    issued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attestation: Optional[str] = None  # optional call-site HMAC from OriginAttester

    def __post_init__(self) -> None:
        ceiling = ceiling_for_origin(self.origin)
        if self.trust > ceiling:
            raise ValueError(
                f"origin {self.origin!r} cannot assert trust "
                f"{self.trust.name} (ceiling {ceiling.name})"
            )

    def expired(self, now: Optional[datetime] = None) -> bool:
        if self.ttl_seconds is None:
            return False
        now = now or datetime.now(timezone.utc)
        issued = datetime.fromisoformat(self.issued_at)
        return (now - issued).total_seconds() > self.ttl_seconds


class OriginAttester:
    """Host-scoped call-site attester for Labels created by trusted adapters.

    Raises the bar against accidental or buggy origin spoofing within a
    ceiling by binding (origin, trust, scope, issued_at) to an ephemeral
    per-Host secret. Honest residual limit: an in-process RCE with memory read
    access to the Host instance could read the secret.
    """

    def __init__(self, secret: Optional[bytes] = None) -> None:
        import os

        self._secret = secret or os.urandom(32)

    def _mac(self, label: Label) -> str:
        msg = (
            f"{label.origin}|{int(label.trust)}|"
            f"{','.join(sorted(label.scope))}|{label.issued_at}|{label.ttl_seconds}"
        ).encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def issue(
        self,
        *,
        origin: str,
        trust: TrustLevel,
        scope: frozenset,
        ttl_seconds: Optional[int] = None,
    ) -> Label:
        base = Label(origin=origin, trust=trust, scope=scope, ttl_seconds=ttl_seconds)
        return Label(
            origin=base.origin,
            trust=base.trust,
            scope=base.scope,
            ttl_seconds=base.ttl_seconds,
            issued_at=base.issued_at,
            attestation=self._mac(base),
        )

    def verify(self, label: Label) -> bool:
        if not label.attestation:
            return False
        return hmac.compare_digest(label.attestation, self._mac(label))


def merge(a: Label, b: Label) -> Label:
    """Conservative propagation (M2): trust(result) <= min(trust(inputs)).

    SCOPE SEMANTICS: frozenset() means DENY-ALL (empty scope authorizes
    nothing). Intersection when both constrained; empty otherwise.
    """
    trust = a.trust if a.trust <= b.trust else b.trust
    scope = a.scope.intersection(b.scope) if a.scope and b.scope else frozenset()
    ttl = None
    if a.ttl_seconds is not None and b.ttl_seconds is not None:
        ttl = min(a.ttl_seconds, b.ttl_seconds)
    elif a.ttl_seconds is not None:
        ttl = a.ttl_seconds
    elif b.ttl_seconds is not None:
        ttl = b.ttl_seconds
    return Label(origin=f"merge({a.origin}+{b.origin})", trust=trust, scope=scope, ttl_seconds=ttl)


@dataclass(frozen=True)
class ConsentToken:
    """Independent elevation (M3): operator or signed-policy approval bound to an action.

    Follows the Operator-Signing vs Target-Verification pattern: the operator
    signs the canonical token body offline with an Ed25519 private key, and
    the target Guardian verifies `signature` against its sealed public key.
    """

    token_id: str
    issuer: str  # "human:<id>" or "policy:<id>"
    action_hash: str  # binds approval to exact JCS args hash (anti-TOCTOU)
    expires_at: str
    signature: Optional[str] = None  # base64 Ed25519 signature over canonical body

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "issuer": self.issuer,
            "action_hash": self.action_hash,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        out = self.canonical_dict()
        if self.signature is not None:
            out["signature"] = self.signature
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConsentToken:
        return cls(
            token_id=str(data["token_id"]),
            issuer=str(data["issuer"]),
            action_hash=str(data["action_hash"]),
            expires_at=str(data["expires_at"]),
            signature=data.get("signature"),
        )


def sign_consent_token(
    *,
    token_id: str,
    issuer: str,
    action_hash: str,
    expires_at: str,
    operator_private_pem: str,
) -> ConsentToken:
    """Operator-side one-shot signing of a ConsentToken (Ed25519 + JCS)."""
    from drako.kernel.receipts import _canonical, _ed25519

    Ed25519PrivateKey, _, serialization = _ed25519()
    priv = serialization.load_pem_private_key(operator_private_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("operator private key must be Ed25519")
    unsigned = ConsentToken(
        token_id=token_id,
        issuer=issuer,
        action_hash=action_hash,
        expires_at=expires_at,
    )
    sig = priv.sign(_canonical(unsigned.canonical_dict()))
    return ConsentToken(
        token_id=token_id,
        issuer=issuer,
        action_hash=action_hash,
        expires_at=expires_at,
        signature=base64.b64encode(sig).decode("ascii"),
    )


def verify_consent_token(
    token: ConsentToken,
    operator_public_pem: str,
    *,
    expected_action_hash: Optional[str] = None,
    now: Optional[datetime] = None,
) -> bool:
    """Target-side offline verification of a ConsentToken. Fail-closed (False on any error)."""
    from drako.kernel.receipts import _canonical, _ed25519

    try:
        if not token.signature:
            return False
        if expected_action_hash is not None and token.action_hash != expected_action_hash:
            return False
        check_now = now or datetime.now(timezone.utc)
        if datetime.fromisoformat(token.expires_at) <= check_now:
            return False
        _, Ed25519PublicKey, serialization = _ed25519()
        pub = serialization.load_pem_public_key(operator_public_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            return False
        pub.verify(base64.b64decode(token.signature), _canonical(token.canonical_dict()))
        return True
    except Exception:
        return False


@dataclass(frozen=True)
class CapabilityToken:
    origin: str
    scope: frozenset
    ttl_seconds: Optional[int] = None
    consent: Optional[ConsentToken] = None


def may_influence(label: Label, required_trust: TrustLevel, side_effect: str) -> bool:
    """Lattice check d ⊑ a: data may influence an action only if its trust
    dominates the action's requirement AND the side-effect is in scope."""
    if label.expired():
        return False
    if label.trust < required_trust:
        return False
    if side_effect not in label.scope:
        return False
    return True


REQUIRED_TRUST = {
    "read": TrustLevel.UNTRUSTED,
    "write": TrustLevel.AGENT,
    "external_comms": TrustLevel.TOOL,
    "irreversible": TrustLevel.USER,  # consent token mandatory (checked by envelope)
}
