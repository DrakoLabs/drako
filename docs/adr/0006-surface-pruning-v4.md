# ADR-0006: Surface Pruning — Removal of Dead SaaS Code, Legacy MCP Server, `nocode/`, `simple/`, and Research Scrapers

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Prior to v4.0, `DrakoLabs/drako` accumulated ~8,500+ lines of code that either depended on the retired `api.getdrako.com` SaaS backend, duplicated core functionality, or sat outside the Authority Kernel mission:

- **Dead SaaS coupling:** `client.py`, `telemetry.py`, `cli/{push,status,simulate,history,diff,rollback,upload,serve}_command.py`, and SaaS-coupled `middleware/*` failed without an unmaintained cloud backend.
- **Obsolete MCP server & broken marketplace files:** `src/drako/mcp/local_server.py` targeted the obsolete `2024-11-05` MCP spec + deprecated SSE transport and merely proxied to `DrakoClient`. Root files `Dockerfile.mcp`, `smithery.yaml`, `glama.json`, `server.json`, and `ROADMAP.md` referenced missing paths and unimplemented capabilities.
- **Redundant / off-mission surfaces:** `src/drako/simple/` (10 files duplicating fixes for 5 older frameworks), `src/drako/nocode/` (15 files for Flowise/n8n JSON workflows with no runtime kernel story), and `tools/` (41 files of research/marketing scrapers including committed `.pyc` bytecode).
- **Misleading documentation:** `docs/observability.md` and `docs/runtime-capabilities.md` claimed features (Presidio DLP, Chaos Engineering, sub-5s collective IOC feeds) that do not exist in the public package.

## Decision

Permanently delete the following surfaces in v4.0.0:

1. **All cloud/SaaS clients and commands:** `client.py`, `telemetry.py`, `push`, `status`, `simulate`, `history`, `diff`, `rollback`, `upload`, `--upload` in `scan`, and SaaS `middleware/` (replaced by unified offline `adapters/` per ADR-0009).
2. **Legacy MCP proxy server and broken marketplace configs:** `src/drako/mcp/`, `serve_command.py`, `Dockerfile.mcp`, `smithery.yaml`, `glama.json`, `server.json`, `ROADMAP.md`.
3. **Deprecated reachability shim:** `src/drako/reachability.py` (replaced exclusively by `drako.heuristic_reachability`).
4. **Redundant `simple/` formatter:** Folded into `drako scan --compact` using `Finding.fix_snippet`.
5. **Off-mission `nocode/` scanner:** Removed from core `drako` to keep the codebase focused on code-level AI agents, MCP, A2A, and the Authority Kernel.
6. **Research scrapers & unmaintained feed scripts:** `tools/`, `data/ecosystem_index*.json`, `.github/workflows/threat-intel-sync.yml`, and inaccurate docs (`docs/observability.md`, `docs/runtime-capabilities.md`).

## Alternatives Considered

- **Deprecate in-place for another release cycle:** Keeps broken commands (`drako push`, `drako status`) shipping in a major `v4.0.0` release, confusing new users and bloating CI.
- **Keep `nocode/` as a core subcommand:** Adds 1,150+ LOC of orthogonal Flowise/n8n parsers with no Authority Kernel integration.

## Consequences

- Breaking v4.0.0 CLI surface change, documented in `docs/migration-v4.md` with an automated `drako upgrade --v4` config migrator.
- Every surviving file in `src/drako/` directly serves the 4-layer local-first architecture with zero hidden network dependencies.

## Verification

- `rg "api\.getdrako\.com|DRAKO_API_KEY|DrakoClient" src/drako/` returns **0 matches**.
- `python -m compileall src/drako` succeeds with zero errors.
