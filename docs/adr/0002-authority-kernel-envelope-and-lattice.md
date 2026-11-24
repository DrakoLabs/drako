# ADR-0002: Authority Kernel — Single Chokepoint Envelope & Origin-Bound Lattice

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Most AI agent compromises in 2025–2026 (AgentJacking, indirect prompt injection via MCP/RAG, cross-boundary exfiltration) share one primitive failure: **authority laundering** — untrusted data enters through a tool or memory channel and exercises the authority of a trusted user prompt. Meanwhile, static-only guardrails fail on open-ended tasks (AgentDyn, arXiv 2602.03117), and multi-stage pipelines allow alternate code paths to bypass enforcement altogether.

## Decision

1. **Single Chokepoint (`drako.kernel.envelope` + `drako.kernel.host`):** Every governed tool call, memory write, or proxied request flows through one `Proposal -> Guardian.evaluate() -> Decision` chokepoint wrapped by `Host`. Internal errors synthesize `deny(host_error:*)` (fail-closed).
2. **Origin-Bound Authority Lattice (`drako.kernel.authority`):**
   - Totally ordered trust levels (`UNTRUSTED < AGENT < TOOL < USER`).
   - Conservative merge: `trust(merge(a, b)) <= min(trust(a), trust(b))`, scope = intersection (empty scope = deny-all).
   - Fail-closed origin ceilings at construction (`tool:* <= TOOL`, `memory:* <= AGENT`, `ctk:* <= UNTRUSTED`) to resist TMA-NM laundering (Louck, arXiv 2606.24322).
   - Call-site attestation helper (`OriginAttester`) scoped per `Host` instance.
3. **Signed `ConsentToken` Elevation ("AI Proposes, Human Signs"):**
   - Irreversible actions (or `approval_liftable` denies) emit an approval seam bound to `args_hash` (JCS SHA-256, anti-TOCTOU).
   - Operators sign `ConsentToken`s offline using Ed25519 (`drako kernel sign-consent`); the target `Guardian` verifies against a sealed `operator_public_pem` without ever holding the operator's private key.
4. **Honest Claim Boundary:** Drako asserts **property-tested non-malleability** (Hypothesis in CI), never "proven security" or invulnerability to prompt injection.

## Alternatives Considered

- **LLM-as-a-Judge guardrail:** Adds latency, nondeterminism, cost, and a second prompt-injection surface.
- **Static allow/deny lists without provenance:** Cannot stop a trusted tool from acting on untrusted tool output.

## Consequences

- Deterministic sub-millisecond evaluation with zero LLM calls in the control loop.
- Residual limitation explicitly documented: in-process Python adapters remain best-effort if the agent process suffers unsandboxed RCE; pair with `drako proxy`, CI gates, and OS/container isolation.

## Verification

- `tests/test_kernel_guardian.py`, `tests/test_kernel_properties.py` (Hypothesis), `tests/test_kernel_v4_extensions.py`.
