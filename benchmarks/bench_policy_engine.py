import json
import time
import tracemalloc
import sys
from collections import defaultdict
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    Console = None

from drako.cli.bom import AgentBOM, DetectedTool, DetectedAgent
from drako.cli.discovery import ProjectMetadata
from drako.cli.policies import evaluate_all_policies, ALL_POLICIES
from drako.cli.policies.governance import GOV003

ITERATIONS = 10000
WARMUP = 1000

def get_stats(times_ns):
    times_ns.sort()
    n = len(times_ns)
    return {
        "p50_ms": times_ns[int(n * 0.50)] / 1e6,
        "p95_ms": times_ns[int(n * 0.95)] / 1e6,
        "p99_ms": times_ns[int(n * 0.99)] / 1e6,
        "min_ms": times_ns[0] / 1e6,
        "max_ms": times_ns[-1] / 1e6,
        "mean_ms": (sum(times_ns) / n) / 1e6,
    }

def run_benchmark(name, func, *args, **kwargs):
    # Warmup
    for _ in range(WARMUP):
        func(*args, **kwargs)
        
    times_ns = []
    
    tracemalloc.start()
    for _ in range(ITERATIONS):
        t0 = time.perf_counter_ns()
        func(*args, **kwargs)
        t1 = time.perf_counter_ns()
        times_ns.append(t1 - t0)
    
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    stats = get_stats(times_ns)
    stats["memory_peak_kb"] = peak / 1024
    return stats

def main():
    print(f"Running Policy Engine Benchmarks ({ITERATIONS} iterations, {WARMUP} warmup)...")
    
    single_rule = GOV003()
    
    # Setup standard BOM and metadata
    bom_single = AgentBOM(tools=[DetectedTool("fetch_data")])
    metadata_single = ProjectMetadata(file_contents={"main.py": "def fetch_data():\n    pass"})
    
    # 1. Single policy evaluation
    stats_single = run_benchmark(
        "Single Policy Eval (1 rule)", 
        single_rule.evaluate, 
        bom_single, 
        metadata_single
    )
    
    # 2. Full scan evaluation
    stats_full = run_benchmark(
        "Full Scan Eval (25 rules)", 
        evaluate_all_policies, 
        bom_single, 
        metadata_single
    )
    
    # 3. Batch evaluation (100 tool calls)
    # create 100 tools
    tools_100 = [DetectedTool(f"tool_{i}") for i in range(100)]
    bom_batch = AgentBOM(tools=tools_100)
    # using full scan on 100 tools to represent evaluating 100 tool calls in batch
    stats_batch = run_benchmark(
        "Batch Eval (100 tools)", 
        evaluate_all_policies, 
        bom_batch, 
        metadata_single
    )
    
    results = {
        "Single Policy": stats_single,
        "Full Scan (25 rules)": stats_full,
        "Batch (100 tools)": stats_batch
    }
    
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True, parents=True)
    with open(out_dir / "policy_engine.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("\nBenchmark Results saved to results/policy_engine.json")
    
    if Console:
        console = Console()
        table = Table(title="Policy Engine Latency Benchmark")
        table.add_column("Scenario", style="cyan")
        table.add_column("Mean (ms)", justify="right")
        table.add_column("P50 (ms)", justify="right")
        table.add_column("P95 (ms)", justify="right")
        table.add_column("P99 (ms)", justify="right")
        table.add_column("Peak Mem (KB)", justify="right")
        
        for name, stat in results.items():
            table.add_row(
                name,
                f"{stat['mean_ms']:.3f}",
                f"{stat['p50_ms']:.3f}",
                f"{stat['p95_ms']:.3f}",
                f"{stat['p99_ms']:.3f}",
                f"{stat['memory_peak_kb']:.1f}"
            )
        console.print(table)
    else:
        for name, stat in results.items():
            print(f"{name}: Mean={stat['mean_ms']:.3f}ms P95={stat['p95_ms']:.3f}ms")

if __name__ == "__main__":
    main()
