# ADR-0007: MCP Supply-Chain & Runtime Security (`mcp.lock`, `tools/list` Drift, CycloneDX 1.7, GA `2026-07-28`)

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

In 2026, Model Context Protocol (MCP) supply-chain and runtime attacks moved from theory to active exploitation:
- Floating `npx -y <pkg>` execution installs unverified bytes (postmark-mcp / npm breach class).
- Mid-session `tools/list` mutation (*Deadbugz*, Aug–Sep 2026) bypasses static artifact review by mutating tool descriptions after initial benign calls.
- The MCP `2026-07-28` GA specification transitioned to a **stateless core** (`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name`), mandatory OAuth 2.1 + PKCE + RFC 8707 Resource Indicators, and CIMD replacing deprecated DCR.
- CycloneDX 1.7 (ECMA-424) added native `citations` provenance alongside `machine-learning-model` / component metadata.

## Decision

Consolidate all MCP security primitives into a single DB-free package `drako.mcp_guard`:

1. **`mcp_guard.lock` & `mcp_guard.admission`:** Strict `mcp.lock` JSON lockfile requiring exact versions (no ranges) and `sha512-...` npm `dist.integrity` hashes; undeclared or mismatched servers fail closed.
2. **`mcp_guard.drift`:** Order-independent canonical SHA-256 fingerprinting of `(name, description, inputSchema)` checked on every `tools/list` call; mid-session mutation raises `ToolsDriftError` (fail-closed).
3. **`mcp_guard.agbom`:** Canonical `snapshot_hash` over admitted servers + `lock_hash` minted as a signed Ed25519 receipt, with **CycloneDX 1.7 (ECMA-424)** transport export (`citations`, SHA-512 hex hashes, `drako:principal`, `drako:integrity`; 1.6 supported via `spec_version="1.6"`).
4. **`mcp_guard.client` (`MCPGAClient`):** Stateless `2026-07-28` HTTP client sending `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name`, enforcing `drako.kernel.egress` on every request and redirect hop (stripping `Authorization` on redirects) and running `check_tools_drift` automatically on `tools/list`.
5. **`mcp_guard.audit`:** Static auditor detecting unpinned, unlisted, or high-risk local MCP configs (`drako mcp audit`).

## Alternatives Considered

- **Keep legacy `src/drako/mcp/local_server.py` (`2024-11-05` + SSE):** Superseded protocol revision and coupled to the removed remote client (ADR-0006).

## Consequences

- Complete end-to-end MCP defense (pin -> admit -> CycloneDX 1.7 AgBOM -> runtime `tools/list` drift -> SSRF guard) works 100% locally.

## Verification

- `tests/test_mcp_guard.py`, `tests/test_kernel_mcp_admission.py`, `tests/test_mcp_audit.py`, `tests/test_mcp_pin.py`.
