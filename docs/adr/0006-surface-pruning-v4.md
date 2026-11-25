# ADR-0006: v4.0 Surface Simplification & Removal of Legacy Cloud/Auxiliary Modules

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

With v4.0's move to a strictly local-first Authority Kernel (ADR-0001), several v2–v3 modules no longer fit the package boundary:

- **Remote-client commands & middleware:** `client.py`, `telemetry.py`, `cli/{push,status,simulate,history,diff,rollback,upload,serve}_command.py`, and remote-coupled `middleware/*` depended on a hosted API model superseded by offline kernel enforcement.
- **Legacy MCP server (`2024-11-05` + SSE):** `src/drako/mcp/local_server.py` targeted an older MCP protocol revision and transport, superseded by `drako.mcp_guard` (`2026-07-28` GA stateless client, lockfile pinning, and runtime drift detection).
- **Redundant or out-of-scope surfaces:** `src/drako/simple/` (duplicated compact output formatting), `src/drako/nocode/` (JSON workflow parsers for Flowise/n8n outside code-level agent runtime governance), `src/drako/reachability.py` (deprecated shim over `heuristic_reachability.py`), auxiliary scripts under `tools/`, and legacy cloud-era manifests/docs.

## Decision

Remove the following surfaces in v4.0.0:

1. **Remote API clients and cloud-only commands:** `client.py`, `telemetry.py`, `push`, `status`, `simulate`, `history`, `diff`, `rollback`, `upload`, `--upload` in `scan`, and remote-coupled `middleware/` (replaced by unified offline `adapters/` per ADR-0009).
2. **Legacy MCP proxy server and superseded manifests:** `src/drako/mcp/`, `serve_command.py`, `Dockerfile.mcp`, `smithery.yaml`, `glama.json`, `server.json`, and `ROADMAP.md`.
3. **Deprecated reachability shim:** `src/drako/reachability.py` (use `drako.heuristic_reachability` directly).
4. **Redundant `simple/` formatter:** Folded into `drako scan --compact` using `Finding.fix_snippet`.
5. **Out-of-scope `nocode/` scanner:** Removed from core `drako` to keep the codebase focused on code-level AI agents, MCP, A2A, and the Authority Kernel.
6. **Auxiliary scripts & legacy cloud docs:** `tools/`, `data/ecosystem_index*.json`, `.github/workflows/threat-intel-sync.yml`, `docs/observability.md`, and `docs/runtime-capabilities.md`.

## Alternatives Considered

- **Keep deprecated commands for another release cycle:** Ships non-functional remote commands in a major `v4.0.0` release and expands maintenance surface.
- **Keep `nocode/` as a core subcommand:** Maintains separate JSON-workflow parsers with no integration into the runtime Authority Kernel.

## Consequences

- Breaking v4.0.0 CLI surface change, documented in `docs/migration-v4.md` with an automated `drako upgrade --v4` config migrator.
- Every module in `src/drako/` directly serves the 4-layer local-first architecture with zero hidden network dependencies.

## Verification

- `rg "api\.getdrako\.com|DRAKO_API_KEY|DrakoClient" src/drako/` returns **0 matches**.
- `python -m compileall src/drako` succeeds with zero errors.
