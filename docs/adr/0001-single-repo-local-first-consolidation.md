# ADR-0001: Local-First Architecture & Zero-Network Default

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Earlier versions of Drako paired a local static scanner with optional remote API calls (`DrakoClient`, `DRAKO_API_KEY`, and cloud-backed CLI subcommands). In practice, agent security infrastructure belongs directly inside developer workflows, CI pipelines, and agent runtimes — without mandatory cloud accounts, external API keys, or remote control-plane dependencies.

In Q4 2026, developer security tooling (e.g., `snyk/agent-scan`, `microsoft/agent-governance-toolkit`, `shirudo-dev/shirudo`) converges on **local-first, zero-daemon, cryptographically verifiable tools** that run fully offline by default.

## Decision

1. **Single self-contained package (`DrakoLabs/drako`):** Ship the full static scanner, Authority Kernel, protocol guards, framework adapters, and compliance evidence generator in one standalone package starting with **`v4.0.0`**.
2. **Zero-network-by-default architecture:** All core capabilities (`scan`, `bom`, `desktop`, `kernel`, `memory_gate`, `drift`, `why`, `verify`, `a2a sign/verify`, `mcp audit`) execute 100% locally with no account, no API key, and no outbound telemetry.
3. **Explicit network opt-in behind a single SSRF chokepoint:** Network egress occurs only when the operator invokes an explicit network command (`drako proxy`, `drako mcp pin`, `drako mcp audit --live`, `drako a2a fetch`) and is routed through `drako.kernel.egress.assert_public_url()`.
4. **Four-layer architecture:**
   - **Layer 1 (Bootstrap):** Static AST scan (Python + TypeScript), heuristic reachability, Agent BOM, desktop + instruction/skill scanning, OWASP 2026 advisories.
   - **Layer 2 (Authority Kernel):** `envelope`, `authority`, `memory_gate`, `policies`, `host`, `receipts`, `drift`, `loop_breaker`, `egress`, `ctk_host`.
   - **Layer 3 (Protocol Guards & Unified Adapters):** `mcp_guard`, `a2a`, offline `adapters/`, and kernel-backed local `proxy/`.
   - **Layer 4 (Compliance Evidence):** `drako[comply]` EU AI Act pack generation fed by local BOM + Ed25519 receipt chains.

## Alternatives Considered

- **Require a hosted control plane / API key for runtime enforcement:** Adds network latency, credential management overhead, and vendor lock-in for teams running agents in air-gapped or CI environments.
- **Bundle a required database / daemon stack:** Adds operational overhead for a library designed to drop into Python agents and CI pipelines with a single `pip install`.

## Consequences

- **Breaking changes in v4.0.0:** Removal of `DrakoClient`, `DRAKO_API_KEY`, remote telemetry, and remote-only CLI commands (documented in `docs/migration-v4.md` and `ADR-0006`).
- **Smaller threat surface and faster adoption:** Single `pip install drako`, deterministic offline tests, no hidden network calls.

## Verification

- `rg "api\.getdrako\.com|DRAKO_API_KEY|DrakoClient" src/drako/` returns **0 matches**.
- Full test suite runs 100% offline with zero external network calls or database dependencies.
