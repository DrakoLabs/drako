# ADR-0001: Single-Repo Local-First Consolidation & SaaS Backend Retirement

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Drako originally grew out of an open-core experiment split between a private FastAPI/PostgreSQL SaaS backend (`agentmesh-backend`) and a public Python CLI/SDK mirror (`DrakoLabs/drako`). Over time, this split produced severe structural drag:

1. **Value split across repos:** High-value deterministic primitives built in September 2026 — the `kernel/` Authority Lattice, `memory_gate`, Ed25519 Receipts, `AGENT-HOOKS-0.1` CTK harness, `mcp_drift`, `mcp_lock`, `egress`, `loop_breaker`, and `a2a_cards` — remained trapped in the private repo while the public repo looked like a static linter from early 2026.
2. **Dead SaaS surface inside the public CLI:** `client.py`, `telemetry.py`, `middleware/*`, `push/status/history/diff/rollback/simulate/serve`, and `--upload` all pointed to an unmaintained `api.getdrako.com` backend requiring `DRAKO_API_KEY`.
3. **Multi-copy drift:** Multiple local copies and stale editable installs caused subtle test divergence and false confidence.

In Q4 2026, developer security infrastructure (e.g., `snyk/agent-scan`, `microsoft/agent-governance-toolkit`, OpenAI/Cisco `shirudo-dev/shirudo`) converges on **local-first, zero-daemon, cryptographically verifiable tools** that run offline in CI and developer workflows without mandatory cloud backends.

## Decision

1. **Retire the private SaaS backend (`agentmesh-backend`) permanently** and make `DrakoLabs/drako` the **single source of truth** starting with **`v4.0.0`**.
2. **Zero-network-by-default architecture:** All core capabilities (`scan`, `bom`, `desktop`, `kernel`, `memory_gate`, `drift`, `why`, `verify`, `a2a sign/verify`, `mcp audit`) execute 100% locally with no account, no API key, and no telemetry pings.
3. **Explicit network opt-in behind a single SSRF chokepoint:** Network egress occurs only when the operator invokes an explicit network command (`drako proxy`, `drako mcp pin`, `drako mcp audit --live`, `drako a2a fetch`) and is routed through `drako.kernel.egress.assert_public_url()`.
4. **Single 4-layer architecture:**
   - **Layer 1 (Bootstrap):** Static AST scan (Python + TypeScript), heuristic reachability, Agent BOM, desktop + instruction/skill scanning, OWASP 2026 advisories.
   - **Layer 2 (Authority Kernel):** `envelope`, `authority`, `memory_gate`, `policies`, `host`, `receipts`, `drift`, `loop_breaker`, `egress`, `ctk_host`.
   - **Layer 3 (Protocol Guards & Unified Adapters):** `mcp_guard`, `a2a`, offline `adapters/` (replacing SaaS `middleware/`), and kernel-backed local `proxy/`.
   - **Layer 4 (Compliance Evidence):** `drako[comply]` EU AI Act pack generation fed by local BOM + Ed25519 receipt chains.

## Alternatives Considered

- **Keep maintaining both repos with automated mirroring:** Preserves dead SaaS complexity, slows iteration, and keeps core runtime defenses disconnected from the public package.
- **Publish the entire FastAPI/Postgres SaaS backend:** Exposes ~40k LOC of unmaintained billing/multi-tenant/Temporal code that adds operational burden without advancing deterministic agent security.

## Consequences

- **Breaking changes in v4.0.0:** Removal of `DrakoClient`, `DRAKO_API_KEY`, remote telemetry, and all cloud-only CLI commands (documented in `docs/migration-v4.md` and `ADR-0006`).
- **Drastically simpler threat surface and DX:** Single `pip install drako`, deterministic offline tests, no hidden network calls.

## Verification

- `rg "api\.getdrako\.com|DRAKO_API_KEY|DrakoClient" src/drako/` returns **0 matches**.
- Full test suite runs 100% offline with zero external network calls or database dependencies.
