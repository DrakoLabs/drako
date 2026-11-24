"""Receipts: Ed25519-signed, hash-chained, offline-verifiable (SLSA/in-toto export).

Canonical bytes: agent_hooks.canonical_json (JCS RFC 8785, Rust core) when the
`guardian` extra is installed, else a stdlib JCS-compatible subset
(sort_keys + compact separators + allow_nan=False).

Q1 Evidence Grade Rule (RFC 8032):
  - Asymmetric Ed25519 signatures (RFC 8032) grade "evidence" (non-repudiable,
    verifiable offline with public key only).
  - Symmetric HMAC-SHA256 signatures ALWAYS grade "telemetry", NEVER "evidence":
    any verifier holding the shared secret can forge arbitrary records.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from agent_hooks import canonical_json as _ah_canonical_json

    def _canonical(obj: Any) -> bytes:
        return _ah_canonical_json(obj).encode("utf-8")

    CANONICALIZER = "agent-hooks-canonical_json"
except ImportError:  # pragma: no cover - fallback path
    def _canonical(obj: Any) -> bytes:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    CANONICALIZER = "stdlib-jcs-subset"


def _ed25519():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:
        raise ImportError(
            "cryptography is required for signed receipts (drako core dependency). "
            f"Install it: pip install cryptography. ({e})"
        ) from e
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem). Keep private_pem off target agent nodes."""
    Ed25519PrivateKey, _, serialization = _ed25519()
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def pubkey_fingerprint(public_pem: str) -> str:
    return "sha256:" + hashlib.sha256(public_pem.encode("utf-8")).hexdigest()[:32]


def mint_receipt(
    *,
    decision: str,
    policy_id: str,
    reason: str,
    tool_name: str,
    agent_id: str,
    args_hash: str,
    provenance: Optional[list[dict[str, Any]]] = None,
    intent_binding: Optional[str] = None,
    prev_hash: Optional[str] = None,
    supersedes_receipt_id: Optional[str] = None,
    private_pem: str,
    public_pem: str,
    grade: str = "evidence",
) -> dict[str, Any]:
    """Mint + Ed25519-sign a receipt. Raises on bad inputs; never mints unsigned."""
    if decision not in ("permit", "deny"):
        raise ValueError(f"bad decision: {decision}")
    Ed25519PrivateKey, _, serialization = _ed25519()
    priv = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519 (RFC 8032)")
    payload: dict[str, Any] = {
        "format": "drako-receipt/v1",
        "receipt_id": _new_id(tool_name, args_hash),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "policy_id": policy_id,
        "reason": reason,
        "tool_name": tool_name,
        "agent_id": agent_id,
        "args_hash": args_hash,
        "provenance": provenance or [],
        "intent_binding": intent_binding,
        "prev_hash": prev_hash,
        "canonicalizer": CANONICALIZER,
        "signer": pubkey_fingerprint(public_pem),
        "grade": grade,
    }
    if supersedes_receipt_id is not None:
        payload["supersedes_receipt_id"] = supersedes_receipt_id
    signed_bytes = _canonical(payload)
    payload["payload_hash"] = hashlib.sha256(signed_bytes).hexdigest()
    sig = priv.sign(signed_bytes)
    payload["signature"] = base64.b64encode(sig).decode("ascii")
    return payload


def _new_id(tool_name: str, args_hash: str) -> str:
    import uuid

    return "rcpt_" + uuid.uuid5(uuid.NAMESPACE_URL, f"{tool_name}:{args_hash}").hex[:16]


def verify_receipt(receipt: dict[str, Any], public_pem: str) -> bool:
    """Verify Ed25519 signature + payload hash. False on ANY mismatch. No exceptions."""
    try:
        _, Ed25519PublicKey, serialization = _ed25519()
        sig = base64.b64decode(receipt["signature"])
        body = {k: v for k, v in receipt.items() if k not in ("signature", "payload_hash")}
        if hashlib.sha256(_canonical(body)).hexdigest() != receipt.get("payload_hash"):
            return False
        pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            return False
        pub.verify(sig, _canonical(body))
        return True
    except Exception:
        return False


def verify_receipt_hmac(receipt: dict[str, Any], shared_secret: bytes) -> tuple[bool, str]:
    """Verify an HMAC-SHA256-tagged receipt (Q1 grading rule).

    Per RFC 8032 non-repudiation semantics, symmetric MACs NEVER grade as
    "evidence" because any verifier possessing the shared secret can forge
    valid records. Always returns grade="telemetry" (or "invalid").
    """
    try:
        presented = receipt.get("hmac") or receipt.get("signature")
        if not isinstance(presented, str) or not presented:
            return False, "invalid"
        body = {
            k: v
            for k, v in receipt.items()
            if k not in ("hmac", "signature", "payload_hash")
        }
        canonical = _canonical(body)
        if "payload_hash" in receipt:
            if hashlib.sha256(canonical).hexdigest() != receipt.get("payload_hash"):
                return False, "invalid"
        expected = hmac.new(shared_secret, canonical, hashlib.sha256).hexdigest()
        if hmac.compare_digest(presented, expected):
            return True, "telemetry"
        return False, "invalid"
    except Exception:
        return False, "invalid"


def verify_chain(receipts: list[dict[str, Any]], public_pem: str) -> tuple[bool, Optional[int]]:
    """Verify Ed25519 signatures + hash links in order. Returns (ok, failing_index)."""
    prev = None
    for i, r in enumerate(receipts):
        if not verify_receipt(r, public_pem):
            return False, i
        if r.get("prev_hash") != prev:
            return False, i
        prev = r["payload_hash"]
    return True, None


def provenance_subgraph(receipt: dict[str, Any]) -> dict[str, Any]:
    """Return a structured provenance graph (nodes + edges) for `drako why` (T7)."""
    decision_node = {
        "id": receipt.get("receipt_id", "unknown"),
        "kind": "decision",
        "decision": receipt.get("decision"),
        "tool_name": receipt.get("tool_name"),
        "agent_id": receipt.get("agent_id"),
        "policy_id": receipt.get("policy_id"),
        "reason": receipt.get("reason"),
        "grade": receipt.get("grade", "evidence"),
        "timestamp": receipt.get("timestamp"),
    }
    nodes: list[dict[str, Any]] = [decision_node]
    edges: list[dict[str, Any]] = []

    if receipt.get("prev_hash"):
        prev_id = f"hash:{str(receipt['prev_hash'])[:16]}"
        nodes.append({"id": prev_id, "kind": "chain_parent", "payload_hash": receipt["prev_hash"]})
        edges.append({"from": prev_id, "to": decision_node["id"], "relation": "chains_to"})

    for idx, p in enumerate(receipt.get("provenance") or []):
        src_id = f"prov:{idx}:{p.get('origin', 'unknown')}"
        nodes.append({
            "id": src_id,
            "kind": "provenance",
            "origin": p.get("origin"),
            "trust": p.get("trust"),
            "ttl_seconds": p.get("ttl_seconds"),
        })
        edges.append({"from": src_id, "to": decision_node["id"], "relation": "influenced"})

    return {"receipt_id": decision_node["id"], "nodes": nodes, "edges": edges}


def to_slsa_provenance(receipt: dict[str, Any]) -> dict[str, Any]:
    """Minimal in-toto Statement / SLSA v1 predicate carrying the receipt."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": f"drako:receipt:{receipt['receipt_id']}",
            "digest": {"sha256": receipt["payload_hash"]},
        }],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://drakolabs.github.io/schema/receipt/v1",
                "externalParameters": {
                    "decision": receipt["decision"],
                    "policy_id": receipt["policy_id"],
                    "tool_name": receipt["tool_name"],
                    "agent_id": receipt["agent_id"],
                    "grade": receipt.get("grade", "evidence"),
                },
            },
            "runDetails": {"builder": {"id": receipt.get("signer", "")}},
        },
    }


def _locked_append(path, line: bytes, timeout_s: float = 5.0) -> None:
    """Cross-platform exclusive append via lockfile (T-4, O_CREAT|O_EXCL)."""
    import os
    import time

    lock = str(path) + ".lock"
    deadline = time.time() + timeout_s
    attempt = 0
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except (FileExistsError, PermissionError):
            try:
                if time.time() - os.path.getmtime(lock) > timeout_s:
                    try:
                        os.unlink(lock)
                    except OSError:
                        pass
                    continue
            except OSError:
                pass
            if time.time() > deadline:
                raise TimeoutError(f"receipt store lock contention: {lock}")
            attempt += 1
            time.sleep(min(0.01 * (1 + attempt * 0.5), 0.2))
    try:
        with open(path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    finally:
        for _ in range(5):
            try:
                os.unlink(lock)
                break
            except OSError:
                time.sleep(0.02)


class ReceiptStore:
    """Append-only local JSONL receipt store with cross-process file locking."""

    def __init__(self, path: str):
        from pathlib import Path

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, receipt: dict[str, Any]) -> None:
        line = (json.dumps(receipt) + "\n").encode("utf-8")
        _locked_append(self.path, line)

    def load_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def get(self, receipt_id: str) -> Optional[dict[str, Any]]:
        for r in self.load_all():
            if r.get("receipt_id") == receipt_id:
                return r
        return None
