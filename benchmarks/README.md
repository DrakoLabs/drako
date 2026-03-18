# Drako SDK Benchmarks

Professional benchmark suite for measuring the latency and overhead of the Drako SDK components.

## Methodology

*   **Precision:** Nanosecond precision using `time.perf_counter_ns()`.
*   **Warmups:** Each test has a configured set of warmup iterations (10-1,000 based on test duration) to ensure the JIT compiler and memory states are stable.
*   **Memory:** `tracemalloc` is used to trace peak memory footprint.
*   **Hardware and Environment:** Standard execution in Local OS.

## Benchmarks Included

*   `bench_policy_engine.py`: Evaluates deterministic rules via `drako.cli.policies`. We target `<10ms` for full AST policy inference scans to claim that governance is `<1%` of an average LLM call overhead (~800ms).
*   `bench_discovery.py`: Latency of offline Agent/Tool/Model and framework Discovery (AST parser).
## Running

```bash
pip install drako
python benchmarks/run_all.py
```

Results are saved to `benchmarks/results/` as JSON and SVG badge.

**Hardware for last published results:** benchmarks run on commodity hardware (any modern laptop). Results are relative, not absolute — the important metric is overhead as a percentage of a typical LLM call (~800ms).

### Competitor Comparison

| Agent Governance Wrapper | Language | Single Policy Latency |
| :--- | :--- | :--- |
| **Bifrost** | Go | ~0.011 ms (11µs) |
| **AgentBouncr** | TypeScript | <5 ms |
| **LiteLLM Guardrails** | Python | ~0.44 ms (440µs) |
| **Drako SDK** | Python | **<10 ms (Target)** |

If Policy rule evaluation goes consistently beyond 10ms in critical workloads for AST extraction, document potential optimizations or consider a rust-based module (PyO3).
