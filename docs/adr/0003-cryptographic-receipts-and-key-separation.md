# ADR-0003: Cryptographic Receipts & Operator/Target Key Separation

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Security teams, developers, and EU AI Act Art. 12 auditors consistently face the same gap: standard application logs record *what* happened, not verifiable proof of *why* an agent action was allowed or denied under which policy and provenance. At the same time, modern open-source security runtimes (e.g., OpenAI/Cisco Shirudo, Nov 2026) establish strict separation between **operator signing keys** and **target execution nodes**.

## Decision

1. **Receipt as First-Class Artifact (`drako.kernel.receipts`):** Every decision (`permit` or `deny`) evaluated by `Host` mints a `drako-receipt/v1` record canonicalized with JCS (RFC 8785 via `agent_hooks.canonical_json` or stdlib JCS subset), hash-chained via `prev_hash -> payload_hash`, signed with **Ed25519 (RFC 8032)**, and exportable as an **in-toto / SLSA v1 Statement** (`to_slsa_provenance`).
2. **Offline Verification & Provenance Graph:**
   - `drako verify` validates hash-chain continuity and Ed25519 signatures 100% offline using only the public key PEM.
   - `drako why <receipt_id>` renders the decision provenance subgraph (`provenance_subgraph()`, both human text and `--format json`).
3. **Q1 Asymmetric Evidence Grading Rule (RFC 8032):**
   - Only asymmetric Ed25519 receipts grade as `"evidence"`.
   - `verify_receipt_hmac()` explicitly grades symmetric HMAC-SHA256 records as `"telemetry"`, **never** `"evidence"`, because any party holding the shared secret can forge valid records.
4. **Operator-Signing vs Target-Verification:**
   - Operator keys (used for `drako kernel sign-consent` and `drako a2a sign`) never reside inside agent repositories or target runtime processes.
   - Target runtimes and verifiers accept sealed public keys only.
   - `ReceiptStore` uses cross-platform `O_CREAT | O_EXCL` lockfiles with stale-lock recovery so concurrent writers cannot corrupt chains.

## Alternatives Considered

- **Unsigned JSON logs / HMAC-only logs:** Repudiable by any entity with access to the log store or shared secret.
- **Centralized remote audit store:** Introduces network dependency and external custody; conflicts with v4 local-first architecture (ADR-0001).

## Consequences

- `cryptography>=42.0.0` is a core dependency of `drako`.
- Every governed workflow produces tamper-evident, offline-verifiable compliance artifacts out of the box.

## Verification

- `tests/test_kernel_guardian.py`, `tests/test_kernel_v4_extensions.py` (Ed25519 roundtrip, tamper detection, chain break indexing, Q1 HMAC `"telemetry"` grading, `provenance_subgraph`).
