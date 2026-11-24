# Authority Kernel Reference

The Authority Kernel (`src/drako/kernel/`) is Drako's deterministic runtime core. It runs 100% offline with zero LLM calls and fail-closed semantics.

## 1. Origin-Bound Trust Lattice (`authority.py`)

Trust levels are totally ordered: `UNTRUSTED (0) < AGENT (1) < TOOL (2) < USER (3)`.
Labels enforce hard **origin ceilings** at construction time (Louck TMA-NM, arXiv 2606.24322):

- `tool:*` -> max trust `TOOL`
- `memory:*` -> max trust `AGENT`
- `ctk:*` -> max trust `UNTRUSTED`
- `user:*` / `merge(*)` -> max trust `USER`

Merging labels is strictly conservative: `trust(merge(a, b)) = min(a.trust, b.trust)`, `scope = a.scope ∩ b.scope` (empty scope = deny-all), and `ttl = min(a.ttl, b.ttl)`.

## 2. Operator-Signing vs Target-Verification (`ConsentToken`)

For `irreversible` side effects or `approval_liftable: true` rules:

1. The target agent `Host` denies the proposal and returns `decision.approval = {"lift": "consent-token", "binds": "<jcs_args_hash>"}`.
2. Out-of-band, a human operator signs a `ConsentToken` with their private Ed25519 key (which never touches the agent runtime):
   ```bash
   drako kernel sign-consent --action-hash <binds> --key operator.key --issuer human:alice
   ```
3. The target `Host` verifies the token offline against its sealed `operator_public_pem`, confirming signature validity, non-expiry, and exact `action_hash` match (anti-TOCTOU).

## 3. Memory Firewall (`memory_gate.py`, OWASP ASI06)

`Host.govern_memory_write(memory_id, labels)` enforces:
1. Every provenance label has a non-empty `origin`.
2. Every label carries a finite, unexpired `ttl_seconds` (no immortal implants).
3. Every label satisfies `trust >= AGENT` with `"memory_write"` explicitly in `scope`.

## 4. Receipts & Q1 Evidence Grading (`receipts.py`)

- Every `Host` decision (`permit` or `deny`) mints an Ed25519-signed, JCS-canonicalized, hash-chained `drako-receipt/v1` record (`grade = "evidence"`).
- Exportable as an **in-toto / SLSA v1 Statement** via `to_slsa_provenance(receipt)`.
- **Q1 Grading Rule (RFC 8032):** `verify_receipt_hmac()` always grades symmetric HMAC-SHA256 records as `"telemetry"`, never `"evidence"`.
- Query any receipt offline with `drako why <receipt_id> --pubkey-file <pub>` or verify full chains with `drako verify <store> --pubkey-file <pub>`.
