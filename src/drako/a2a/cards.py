"""A2A v1.0 Signed Agent Cards — RFC 7515 Detached JWS (EdDSA) + RFC 8785 JCS (ADR-0008).

Implements the Linux Foundation / AAIF A2A v1.0 AgentCardSignature workflow:
  1. Strip empty/default fields recursively (None, "", [], {}) for deterministic
     cross-framework serialization.
  2. Exclude the top-level `signatures` array from the signed payload.
  3. Canonicalize via RFC 8785 JCS (`drako.kernel.receipts._canonical`).
  4. Sign detached JWS signing input `ASCII(b64url(protected) || '.' || b64url(payload))`
     using Ed25519 (`alg: "EdDSA"`, RFC 8037) and attach an `AgentCardSignature`
     entry `{"protected": ..., "signature": ...}` under `card["signatures"]`.

Operator-Signing vs Target-Verification:
  - Operators / CI sign `agent-card.json` offline with their Ed25519 private key.
  - Target peer agents verify cards offline with only the trusted public key
    (or fetch `/.well-known/agent-card.json` strictly through `drako.kernel.egress`).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from drako.kernel.receipts import _canonical, _ed25519

CARD_DEFAULT_TTL_DAYS = 90
_ACCEPTED_ALGS = ("EdDSA", "Ed25519")


class AgentCardError(ValueError):
    """Malformed or invalid A2A Agent Card."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _strip_defaults(obj: Any) -> Any:
    """Recursively strip empty/default values per A2A v1.0 signing rules."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            sub = _strip_defaults(v)
            if sub is None or sub == "" or sub == [] or sub == {}:
                continue
            cleaned[k] = sub
        return cleaned
    if isinstance(obj, list):
        return [_strip_defaults(item) for item in obj if item is not None]
    return obj


def canonicalize_agent_card(card: dict[str, Any]) -> bytes:
    """Return RFC 8785 JCS canonical bytes of an AgentCard excluding `signatures`."""
    if not isinstance(card, dict):
        raise AgentCardError("Agent Card must be a JSON object")
    body = {k: v for k, v in card.items() if k != "signatures"}
    stripped = _strip_defaults(body)
    return _canonical(stripped)


def card_fingerprint(card: dict[str, Any]) -> str:
    """Stable short SHA-256 fingerprint of the canonical card payload."""
    return "sha256:" + hashlib.sha256(canonicalize_agent_card(card)).hexdigest()[:16]


def sign_agent_card(
    card: dict[str, Any],
    private_pem: str,
    *,
    kid: str,
    ttl_days: int = CARD_DEFAULT_TTL_DAYS,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Sign an A2A v1.0 Agent Card with RFC 7515 Detached JWS (EdDSA) + JCS.

    Returns a new dict with an appended `signatures` entry; never mutates input.
    """
    Ed25519PrivateKey, _, serialization = _ed25519()
    priv = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise AgentCardError("signing key must be Ed25519")

    ts = now or datetime.now(timezone.utc)
    protected_obj = {
        "alg": "EdDSA",
        "typ": "a2a-agent-card+jws",
        "kid": kid,
        "iat": int(ts.timestamp()),
        "exp": int((ts + timedelta(days=ttl_days)).timestamp()),
    }
    protected_b64 = _b64url_encode(_canonical(protected_obj))
    payload_b64 = _b64url_encode(canonicalize_agent_card(card))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    sig_b64 = _b64url_encode(priv.sign(signing_input))

    out = dict(card)
    existing = list(card.get("signatures") or [])
    existing.append({"protected": protected_b64, "signature": sig_b64})
    out["signatures"] = existing
    return out


def verify_agent_card(
    card: Any,
    public_pem: str,
    *,
    expected_kid: Optional[str] = None,
    now: Optional[datetime] = None,
    ignore_expiry: bool = False,
) -> bool:
    """Verify at least one valid RFC 7515 Detached JWS signature on an A2A Agent Card.

    Fail-closed: returns False on ANY malformed shape, missing `signatures`,
    unsupported alg, expired `exp`, kid mismatch, or cryptographic failure.
    """
    try:
        if not isinstance(card, dict):
            return False
        signatures = card.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            return False

        _, Ed25519PublicKey, serialization = _ed25519()
        pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            return False

        payload_b64 = _b64url_encode(canonicalize_agent_card(card))
        check_ts = int((now or datetime.now(timezone.utc)).timestamp())

        for entry in signatures:
            if not isinstance(entry, dict):
                continue
            protected_b64 = entry.get("protected")
            sig_b64 = entry.get("signature")
            if not isinstance(protected_b64, str) or not isinstance(sig_b64, str):
                continue
            try:
                header = json.loads(_b64url_decode(protected_b64).decode("utf-8"))
            except Exception:
                continue
            if not isinstance(header, dict):
                continue
            if header.get("alg") not in _ACCEPTED_ALGS:
                continue
            if expected_kid is not None and header.get("kid") != expected_kid:
                continue
            if not ignore_expiry and "exp" in header:
                if not isinstance(header["exp"], (int, float)) or header["exp"] <= check_ts:
                    continue

            signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
            try:
                pub.verify(_b64url_decode(sig_b64), signing_input)
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def fetch_and_verify_agent_card(
    url: str,
    public_pem: str,
    *,
    allowlist: Optional[list[str]] = None,
    allow_private: bool = False,
    expected_kid: Optional[str] = None,
    timeout: float = 10.0,
) -> tuple[dict[str, Any], bool]:
    """Fetch a remote Agent Card via SSRF-guarded egress and verify its JWS signature."""
    import httpx

    from drako.kernel.egress import assert_public_url, resolve_redirect

    target = assert_public_url(url, allow_private=allow_private, allowlist=allowlist)
    with httpx.Client(timeout=timeout, follow_redirects=False) as http:
        for hop in range(4):
            resp = http.get(target, headers={"Accept": "application/json"})
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location")
                if not loc:
                    raise AgentCardError("redirect missing Location header")
                target = resolve_redirect(target, loc, hop, allowlist=allowlist)
                continue
            resp.raise_for_status()
            card = resp.json()
            if not isinstance(card, dict):
                raise AgentCardError("fetched Agent Card is not a JSON object")
            valid = verify_agent_card(card, public_pem, expected_kid=expected_kid)
            return card, valid
    raise AgentCardError("too many redirects fetching Agent Card")
