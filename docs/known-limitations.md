# Known Limitations

This document states where Drako's controls stop so teams can pair it with the right surrounding isolation.

1. **Prompt Injection Is Not "Solved" (AgentDyn):** No static or runtime policy engine eliminates prompt injection in open-ended tasks. Drako provides **blast-radius containment** (origin-bound authority lattice, memory TTLs, irreversible consent gates) and **offline answerability** (Ed25519 receipts), not immunity from model manipulation.
2. **Property-Tested, Never "Proven":** Non-malleability invariants (`tests/test_kernel_properties.py`) are verified via bounded Hypothesis property testing in CI — never claimed as formal unbounded theorem proofs.
3. **In-Process Adapters Are Best-Effort:** Python framework adapters (`drako.adapters.*`) run inside the agent's own Python process. Unsandboxed arbitrary code execution (RCE) in the same process can unwrap hooks or read in-memory `OriginAttester` secrets. Pair adapters with out-of-process controls (`drako proxy`, OS/container isolation such as gVisor/containers, and `drako-gate` CI checks).
4. **Origin Strings Within a Ceiling:** Origin ceilings (`tool:* <= TOOL`, `memory:* <= AGENT`) are enforced fail-closed, and `Host.attest_label()` binds labels via a host-scoped HMAC, but within a single compromised Python process an attacker with memory access could spoof labels within the same ceiling.
5. **DNS-Rebinding TOCTOU (`egress.py`):** `assert_public_url()` validates schemes, allowlists, literal IPs, DNS resolutions, and every redirect hop (stripping `Authorization` on redirects). However, resolve-then-connect in user-space HTTP clients remains inherently subject to sub-second DNS rebinding; high-security production deployments should add a network-layer egress proxy with DNS pinning.
6. **Heuristic Reachability:** `drako.heuristic_reachability` uses AST/string matching over agent definitions and source files — it is **not** full inter-procedural taint/dataflow analysis.
7. **Per-Process `LoopBreaker`:** The repetition circuit breaker keeps state in process memory; in multi-replica deployments without sticky routing, effective thresholds scale with replica count.
8. **OWASP LLM07 & LLM10:** Misinformation detection (`LLM07`) and runtime sink-specific output encoding (`LLM10`) are intentionally outside Drako's zero-LLM kernel scope.
9. **MAF Workflows Boundary:** `drako.adapters.maf` governs tool invocations through Microsoft Agent Framework's Agent Hooks/middleware; multi-agent Workflow graphs outside per-agent tool hooks must explicitly attach hooks per node.
