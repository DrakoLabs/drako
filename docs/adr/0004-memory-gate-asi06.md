# ADR-0004: Memory Gate for Agent Memory Poisoning Defense (OWASP ASI06)

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Research benchmarks in 2026 — **MPBench** (arXiv 2606.04329, 4 injection channels and 6 attack classes into persistent agent memory) and **MemSecBench** (arXiv 2607.27080) — showed that untrusted tool output or retrieved RAG content written into persistent memory is later read back as trusted agent state (sleeper/MINJA implants).

## Decision

Treat memory writes as a dedicated side-effect class (`memory_write`) gated by `drako.kernel.memory_gate.authorize_memory_write()` and exposed on `Host.govern_memory_write()` with three fail-closed invariants:

1. **Mandatory Origin:** Every `Label` in the provenance chain must carry a non-empty `origin`; sourceless writes are denied.
2. **Mandatory Bounded TTL:** Every `Label` must carry an explicit, unexpired `ttl_seconds`; immortal memory writes are denied, and permitted writes return `effective_ttl_seconds = min(ttls)` for the consumer store to persist.
3. **Lattice Floor (`>= AGENT` + `memory_write` in scope):** Untrusted tool outputs (`UNTRUSTED`, or `TOOL` labels lacking `memory_write` scope) cannot launder themselves into persistent memory.

Every `Host.govern_memory_write()` call mints a chained Ed25519 receipt carrying provenance `ttl_seconds`.

## Alternatives Considered

- **Content-only regex/classifier filtering on memory payloads:** Bypassable by semantic paraphrasing and blind to provenance/persistence lifetime.

## Consequences

- Consumers integrating persistent memory must store and enforce `effective_ttl_seconds` returned by `MemoryDecision`.
- Content inspection stays cleanly orthogonal; memory-gate enforces provenance, lifetime, and authority invariants deterministically offline.

## Verification

- `tests/test_kernel_memory.py` (15 tests covering MPBench attack channels + TTL min-propagation + receipt TTL recording) and `tests/test_kernel_v4_extensions.py`.
