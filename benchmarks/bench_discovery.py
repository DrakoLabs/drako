import json
import time
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    Console = None

from drako.cli.discovery import collect_project_files, detect_frameworks
from drako.cli.bom import generate_bom

def run_discovery_benchmark(project_dir: Path):
    if not project_dir.exists():
        return None
        
    # Warmup
    for _ in range(5):
        m = collect_project_files(project_dir)
        m.frameworks = detect_frameworks(m)
        generate_bom(m)
        
    times_ms = []
    
    for _ in range(20):
        t0 = time.perf_counter_ns()
        
        m = collect_project_files(project_dir)
        m.frameworks = detect_frameworks(m)
        bom = generate_bom(m)
        
        t1 = time.perf_counter_ns()
        times_ms.append((t1 - t0) / 1e6)
        
    return {
        "mean_ms": sum(times_ms) / len(times_ms),
        "min_ms": min(times_ms),
        "max_ms": max(times_ms)
    }

def main():
    print("Running AST Discovery Benchmarks...")
    repo_root = Path(__file__).parent.parent.parent
    fixtures_dir = repo_root / "sdk" / "tests" / "fixtures"
    
    projects = ["crewai_basic", "langgraph_clean", "autogen_vulnerable", "mixed_framework"]
    
    results = {}
    for p in projects:
        project_path = fixtures_dir / p
        stats = run_discovery_benchmark(project_path)
        if stats:
            results[p] = stats
        else:
            print(f"Warning: Fixture {p} not found at {project_path}")
            
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True, parents=True)
    with open(out_dir / "discovery.json", "w") as f:
        json.dump(results, f, indent=2)
        
    if Console and results:
        console = Console()
        table = Table(title="AST Discovery Latency")
        table.add_column("Fixture Project", style="cyan")
        table.add_column("Mean Latency (ms)", justify="right")
        table.add_column("Min (ms)", justify="right")
        table.add_column("Max (ms)", justify="right")
        
        for name, stat in results.items():
            table.add_row(
                name,
                f"{stat['mean_ms']:.2f}",
                f"{stat['min_ms']:.2f}",
                f"{stat['max_ms']:.2f}"
            )
        console.print(table)

if __name__ == "__main__":
    main()
