# Migration Guide: Drako v3.0 → v4.0

Drako v4.0 retires the legacy cloud SaaS backend (`api.getdrako.com`) and consolidates the entire platform — including the **Authority Kernel**, **Memory Gate**, **MCP Guard**, **A2A v1.0 JWS**, and **unified offline framework adapters** — into one local-first **Apache-2.0** package.

## Automated Config Migration (`drako upgrade --v4`)

Run the idempotent migrator on your existing `.drako.yaml`:

```bash
drako upgrade --v4 --config .drako.yaml
drako validate .drako.yaml
```

This automatically:
- Sets `version: "4.0"` and preserves your `tenant_id` as `project_id`.
- Removes retired SaaS keys (`api_key`, `api_key_env`, `endpoint`, `governance`, `bft`, `chaos`, `topology`).
- Adds `kernel` (`spec_pin: AGENT-HOOKS-0.1`, fail-closed `default_effect: deny`), `loop_breaker`, `egress`, and pinned `mcp` defaults (`protocol_version: "2026-07-28"`).

## Breaking Changes Summary

| v3.0 Surface | v4.0 Replacement | ADR |
|---|---|---|
| `DrakoClient`, `DRAKO_API_KEY`, `api.getdrako.com` | **Removed** — 100% local-first offline execution | [ADR-0001](adr/0001-single-repo-local-first-consolidation.md) |
| `drako push`, `status`, `history`, `diff`, `rollback`, `simulate`, `serve`, `scan --upload` | **Removed** — use `drako validate`, `drako drift`, `drako verify`, `drako why` | [ADR-0006](adr/0006-surface-pruning-v4.md) |
| `drako.middleware.{crewai,langgraph,maf,openai_agents}` | Unified offline **`drako.adapters.*`** over `drako.kernel.Host` | [ADR-0009](adr/0009-unified-offline-framework-adapters.md) |
| `drako.middleware.autogen` | **Removed** (AutoGen merged into Microsoft Agent Framework; use `drako.adapters.maf`) | [ADR-0009](adr/0009-unified-offline-framework-adapters.md) |
| `drako.reachability` shim | Use `drako.heuristic_reachability` directly | [ADR-0006](adr/0006-surface-pruning-v4.md) |
| `drako scan --simple` | Use `drako scan --compact` | [ADR-0006](adr/0006-surface-pruning-v4.md) |
| `drako nocode` & `tools/` scrapers | **Removed** from core package | [ADR-0006](adr/0006-surface-pruning-v4.md) |
| `BUSL-1.1` license | Relicense to **`Apache-2.0`** | [ADR-0012](adr/0012-apache-2-0-license-migration.md) |
