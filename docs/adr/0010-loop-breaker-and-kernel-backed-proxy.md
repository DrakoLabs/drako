# ADR-0010: Runaway Loop Circuit-Breaker & Kernel-Backed Local Proxy

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Real-world runaway agent incidents in 2026 (Cursor >$1,300/hr, Replit >$600/4d) exposed a blind spot in failure-based circuit breakers: an agent trapped in a loop repeats the *identical* tool or model call hundreds of times while every single call returns HTTP 200 OK. Separately, the legacy proxy in `drako/` ran uncoupled from the Authority Kernel and previously carried a critical FastAPI annotation bug (`422` on all handlers) and hardcoded 2025 pricing tables.

## Decision

1. **Repetition Circuit-Breaker (`drako.kernel.loop_breaker`):** Thread-safe rolling-window repetition counter (`LoopBreaker`) keyed by `(session_id, agent_id, call_fingerprint(tool, args_hash))`. Reaching `trip_threshold` (default 10 calls / 300s) escalates once and denies subsequent identical repetitions fast (`kernel:loop-breaker`) until explicitly reset by operator approval.
2. **Integrated into `Host` and Local Proxy:**
   - `Host.govern_tool_call()` runs `LoopBreaker` before policy evaluation and mints a signed `deny` receipt when tripped.
   - `drako.proxy.proxy_server` runs `LoopBreaker`, optional `kernel.Host` (attaching `X-Drako-Receipt-Id`), `egress.assert_public_url()` on upstream targets, loopback-only default binding (`127.0.0.1`), strict CORS, bearer auth (`DRAKO_PROXY_TOKEN`) on `/status` and `/audit`, and configurable pricing via `.drako.yaml -> finops.tracking.model_costs`.
3. **Honest Boundary Posture:** The proxy is an optional out-of-process host of the Authority Kernel (protecting LLM API traffic and emitting receipts); it is not claimed as an unbypassable OS sandbox.

## Alternatives Considered

- **Failure-only circuit breaker:** Completely blind to successful-status runaway loops (OWASP ASI08/ASI10).

## Consequences

- Stops Denial-of-Wallet loops locally in sub-millisecond time without external state stores.
- Multi-replica deployments observe per-process windows (documented trade-off).

## Verification

- `tests/test_kernel_v4_extensions.py` (`test_host_loop_breaker_trips_and_mints_receipt`, `test_proxy_v4_auth_and_loop_breaker`).
