# AGENT-HOOKS-0.1 Conformance Claim — Drako Authority Kernel

- **Product:** `drako` (`DrakoLabs/drako`) v4.0.0
- **Component:** `drako.kernel.ctk_host.DrakoHarness`
- **Specification Pin:** `AGENT-HOOKS-0.1` (OWASP Agent Control Standard working draft v0.1.0)
- **CTK Harness Pin:** `agent-hooks-sdk==0.1.0a5` (47 vectors)
- **Claim (canonical phrasing):** **Conformant on declared surface (44/44 applicable vectors passing, 3 capability-gated skips, 0 failures).**

## Declared Surface

See [`declared_surface.json`](declared_surface.json) for the machine-readable capability matrix.

- **Supported hooks:** `pre_tool_call`, `post_tool_call`, `pre_model_call`, `post_model_call`
- **Supported verdicts:** `allow` (`permit`), `deny`, `transform` (`modify`), plus liftable deny via signed `ConsentToken`
- **Fail-closed guarantee:** Any internal policy/interceptor error synthesizes `deny(host_error:*)`
- **Excluded capabilities (explicitly declared):** `int64` / arbitrary-precision `bigint` JSON numeric edge vectors (3 CTK vectors skipped by capability gating)

## Verification

Run locally or in CI with the `[guardian]` extra installed:

```bash
pytest tests/test_kernel_ctk.py -v
```
