# ADR-0009: Unified Offline Framework Adapters Replacing SaaS Middleware

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

In v3, `src/drako/middleware/` contained six framework wrappers (`base`, `crewai`, `langgraph`, `autogen`, `maf`, `openai_agents`) tightly coupled to `DrakoClient` HTTP calls against the retired SaaS backend. Meanwhile, the September 2026 Authority Kernel only shipped a single adapter (`kernel/adapters/langgraph.py`), leaving modern Q4 2026 production frameworks — **OpenAI Agents SDK**, **Microsoft Agent Framework (GA)**, **Claude Agent SDK**, and **Google ADK** — without an offline kernel integration. Upstream AutoGen was absorbed into Microsoft Agent Framework.

## Decision

1. **Delete `src/drako/middleware/`** and unify all runtime integrations under `src/drako/adapters/` built on one shared `BaseAdapter` (`drako/adapters/base.py`) translating framework calls into `drako.kernel.Host.govern_tool_call()` with the **T-5 re-govern-after-modify + loop-guard** invariant.
2. **Cover the Q4 2026 Big 5 + CrewAI (legacy):**
   - `drako.adapters.langgraph` (ToolNode wrapper)
   - `drako.adapters.openai_agents` (`on_invoke_tool` + callable wrapper)
   - `drako.adapters.maf` (Microsoft Agent Framework Agent Hooks / function-invocation middleware; explicitly declares MAF Workflows outside the single-agent tool hook boundary)
   - `drako.adapters.claude_agent` (`PreToolUse` hook returning structured `allow`/`deny`/`updatedInput`)
   - `drako.adapters.google_adk` (`before_tool_callback` short-circuiting denies and propagating modified args)
   - `drako.adapters.crewai` (Crew tool `_run` wrapper)
3. **Remove AutoGen runtime middleware** (keep static AST rules `FW-003/004` to flag legacy AutoGen repos for migration to MAF).
4. **Zero mandatory framework deps & honest in-process limits:** All framework SDKs are duck-typed / lazy-imported; docs explicitly state that in-process hooks are best-effort defense-in-depth and must be paired with `drako proxy`, CI gates, and OS/container isolation.

## Alternatives Considered

- **Keep `middleware/` with a mock `DrakoClient`:** Preserves ~1,200 LOC of dead SaaS abstractions (`agent_did`, `check_ioc_sync`) instead of speaking the Authority Kernel directly.

## Consequences

- Every supported framework emits identical Ed25519 hash-chained receipts and enforces identical ACS profiles, Memory Gate, and LoopBreaker semantics offline.

## Verification

- `tests/test_adapters_v4.py` and `tests/test_kernel_host_adapter.py` (all hermetic with fakes, zero external SDK installs required in base CI).
