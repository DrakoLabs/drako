# mypy: strict
"""Curated Ecosystem Scanner — discovers repos by framework via GitHub Code
Search and scans each with Drako governance rules.

Replaces the noisy topic-based discovery in ``build_index.py`` with targeted
code-search queries (e.g. ``"from crewai" language:python``), so every
discovered repo already has a known framework.

Usage:
    python tools/scan_ecosystem.py --token $GITHUB_TOKEN
    python tools/scan_ecosystem.py --token $GITHUB_TOKEN --resume
    python tools/scan_ecosystem.py --token $GITHUB_TOKEN --config tools/ecosystem_queries.yaml
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import click
import httpx
import yaml

# Minimum number of .py files that must import the framework for a repo
# to be considered "relevant" to that framework and included in the
# published ecosystem index.
MIN_FRAMEWORK_FILES = 3

_QUOTED_RE = re.compile(r'"([^"]+)"')

# ---------------------------------------------------------------------------
# Reuse governance-index modules via sys.path
# ---------------------------------------------------------------------------
_GOV_INDEX_DIR = str(Path(__file__).parent / "governance-index")
if _GOV_INDEX_DIR not in sys.path:
    sys.path.insert(0, _GOV_INDEX_DIR)

from checkpoint import load_checkpoint, save_checkpoint  # noqa: E402
from github_discovery import RepoInfo, _headers, _sleep_for_rate_limit  # noqa: E402
from scan_runner import RepoScanResult, cleanup_repo, scan_repo  # noqa: E402

_GITHUB_API = "https://api.github.com"


# ---------------------------------------------------------------------------
# Discovery via Code Search API
# ---------------------------------------------------------------------------

def discover_by_code_search(
    token: str,
    config: dict[str, dict[str, object]],
) -> dict[str, list[RepoInfo]]:
    """Discover repos per framework using GitHub Code Search API.

    For each framework query, searches code, extracts unique repos,
    fetches repo metadata, and filters by min_stars.  Deduplicates
    globally so a repo only appears under one framework.

    Args:
        token: GitHub personal access token.
        config: Parsed ``ecosystem_queries.yaml`` ``frameworks`` section.

    Returns:
        Mapping of framework name to list of RepoInfo.
    """
    global_seen: set[str] = set()
    result: dict[str, list[RepoInfo]] = {}
    client = httpx.Client(timeout=30.0)
    headers = _headers(token)

    try:
        for fw_name, fw_cfg in config.items():
            queries = list(fw_cfg["queries"])  # type: ignore[arg-type]
            min_stars = int(fw_cfg.get("min_stars", 50))  # type: ignore[arg-type]
            limit = int(fw_cfg.get("limit", 15))  # type: ignore[arg-type]

            click.echo(f"  [{fw_name}] {len(queries)} queries, min_stars={min_stars}, limit={limit}")
            seen_in_fw: set[str] = set()

            # Phase A: union candidate repo names across all queries
            for query in queries:
                click.echo(f"    Searching: {query}")
                for page in range(1, 4):
                    url = f"{_GITHUB_API}/search/code"
                    params = {"q": str(query), "per_page": 30, "page": page}

                    try:
                        resp = client.get(url, headers=headers, params=params)
                    except httpx.HTTPError as e:
                        click.echo(f"      HTTP error: {e}", err=True)
                        break

                    if resp.status_code in (403, 429):
                        _sleep_for_rate_limit(resp)
                        continue

                    if resp.status_code == 422:
                        click.echo(f"      Code search returned 422 (validation error), skipping", err=True)
                        break

                    if resp.status_code != 200:
                        click.echo(f"      Code search returned {resp.status_code}", err=True)
                        break

                    _sleep_for_rate_limit(resp)

                    data = resp.json()
                    items: list[dict[str, object]] = data.get("items", [])
                    if not items:
                        break

                    new_in_page = 0
                    for item in items:
                        repo_data = item.get("repository", {})
                        full_name = str(repo_data.get("full_name", ""))  # type: ignore[union-attr]
                        if not full_name or full_name in seen_in_fw or full_name in global_seen:
                            continue
                        seen_in_fw.add(full_name)
                        new_in_page += 1

                    if new_in_page == 0:
                        break  # nothing new on this page, stop paginating this query

                # Code Search rate limit: 10 req/min for authenticated users
                time.sleep(6)

            click.echo(f"    Union: {len(seen_in_fw)} candidate repos")

            # Phase B: fetch metadata, filter by min_stars, dedupe globally
            repos_for_fw: list[RepoInfo] = []
            for full_name in seen_in_fw:
                if full_name in global_seen or len(repos_for_fw) >= limit:
                    continue

                time.sleep(1)  # Be gentle with the core API
                try:
                    repo_resp = client.get(
                        f"{_GITHUB_API}/repos/{full_name}",
                        headers=headers,
                    )
                except httpx.HTTPError:
                    continue

                if repo_resp.status_code != 200:
                    continue

                _sleep_for_rate_limit(repo_resp)
                repo_json = repo_resp.json()

                stars = int(repo_json.get("stargazers_count", 0))
                if stars < min_stars:
                    continue

                global_seen.add(full_name)
                repos_for_fw.append(RepoInfo(
                    full_name=full_name,
                    clone_url=str(repo_json.get("clone_url", "")),
                    stars=stars,
                    language=str(repo_json.get("language", "") or ""),
                    description=str(repo_json.get("description", "") or "")[:200],
                    topics=tuple(repo_json.get("topics", [])),
                ))

            repos_for_fw.sort(key=lambda r: r.stars, reverse=True)
            result[fw_name] = repos_for_fw[:limit]
            click.echo(f"    Kept {len(result[fw_name])} repos after min_stars/limit")

    finally:
        client.close()

    return result


# ---------------------------------------------------------------------------
# Framework relevance analysis
# ---------------------------------------------------------------------------

def extract_patterns_from_queries(queries: list[str]) -> list[str]:
    """Extract quoted substrings from GitHub code-search queries.

    ``'"from crewai import" language:python'`` -> ``["from crewai import"]``
    Multiple quoted phrases per query are all returned.
    """
    patterns: list[str] = []
    for q in queries:
        patterns.extend(_QUOTED_RE.findall(q))
    return patterns


def analyze_framework_usage(
    repo_dir: Path,
    patterns: list[str],
) -> tuple[int, int, int]:
    """Count .py files that import the framework and their LOC.

    Returns:
        (framework_file_count, framework_loc, repo_total_loc)

    ``framework_file_count`` is the number of .py files whose raw
    content contains any of the ``patterns`` as a substring.  LOC is
    measured as ``content.count("\\n") + 1`` — cheap and good enough
    for ordering and reporting.  Unreadable files are skipped.
    """
    framework_files = 0
    framework_loc = 0
    repo_total_loc = 0

    if not repo_dir.exists():
        return (0, 0, 0)

    for py in repo_dir.rglob("*.py"):
        try:
            content = py.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        loc = content.count("\n") + 1
        repo_total_loc += loc
        if patterns and any(p in content for p in patterns):
            framework_files += 1
            framework_loc += loc

    return framework_files, framework_loc, repo_total_loc


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def _anonymize(repo_name: str) -> str:
    """SHA-256 hash truncated to 8 hex chars."""
    return hashlib.sha256(repo_name.encode()).hexdigest()[:8]


def generate_ecosystem_index(
    completed: dict[str, RepoScanResult],
    fw_map: dict[str, str],
    usage_stats: dict[str, tuple[int, int, int]],
    reason: str | None = None,
) -> dict[str, object]:
    """Build the ecosystem_index.json structure.

    Args:
        completed: Scan results keyed by repo full_name.
        fw_map: Mapping of repo full_name -> framework name (from discovery).
        usage_stats: Map of repo full_name -> (framework_file_count,
            framework_loc, repo_total_loc).
        reason: Optional ``exclusion_reason`` added to every project entry.
            Used for the excluded index.

    Returns:
        JSON-serializable dict.
    """
    by_framework: dict[str, dict[str, object]] = {}
    projects: list[dict[str, object]] = []

    # Group results by framework
    fw_groups: dict[str, list[RepoScanResult]] = {}
    for repo_name, result in completed.items():
        fw = fw_map.get(repo_name, result.framework)
        if fw == "unknown":
            fw = fw_map.get(repo_name, "unknown")
        fw_groups.setdefault(fw, []).append(result)

        fc, floc, total_loc = usage_stats.get(repo_name, (0, 0, 0))
        entry: dict[str, object] = {
            "id": _anonymize(repo_name),
            "framework": fw,
            "governance_score": result.score,
            "grade": result.grade,
            "agents": result.agents,
            "tools": result.tools,
            "findings_by_severity": result.findings_by_severity,
            "framework_file_count": fc,
            "framework_loc": floc,
            "repo_total_loc": total_loc,
        }
        if reason:
            entry["exclusion_reason"] = reason
        projects.append(entry)

    for fw, results in fw_groups.items():
        scores = [r.score for r in results]
        grades: dict[str, int] = {}
        for r in results:
            grades[r.grade] = grades.get(r.grade, 0) + 1
        by_framework[fw] = {
            "count": len(results),
            "avg_governance": round(sum(scores) / len(scores), 1),
            "grade_distribution": grades,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_scanned": len(projects),
        "by_framework": by_framework,
        "projects": projects,
    }


def save_ecosystem_index(
    index: dict[str, object],
    output_dir: Path,
    filename: str = "ecosystem_index.json",
) -> Path:
    """Atomically write the given index JSON to ``output_dir/filename``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / filename

    fd, tmp_path = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)
        if out_path.exists():
            out_path.unlink()
        os.rename(tmp_path, str(out_path))
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option(
    "--token",
    envvar="GITHUB_TOKEN",
    required=True,
    help="GitHub personal access token (env: GITHUB_TOKEN)",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=str(Path(__file__).parent / "ecosystem_queries.yaml"),
    help="Path to ecosystem_queries.yaml",
)
@click.option(
    "--output",
    "output_dir",
    type=click.Path(),
    default="data",
    help="Output directory (default: data/)",
)
@click.option(
    "--resume",
    is_flag=True,
    help="Resume from checkpoint if available",
)
@click.option(
    "--timeout",
    type=int,
    default=120,
    help="Per-repo scan timeout in seconds (default: 120)",
)
@click.option(
    "--keep-clones",
    is_flag=True,
    help="Keep cloned repos after scanning",
)
def main(
    token: str,
    config_path: str,
    output_dir: str,
    resume: bool,
    timeout: int,
    keep_clones: bool,
) -> None:
    """Curated Ecosystem Scanner — scan repos by framework."""
    out = Path(output_dir)
    work = Path("work")
    # Nuke any stale clone directories from prior runs.  On Windows,
    # shutil.rmtree(..., ignore_errors=True) inside cleanup_repo can
    # leave empty stubs that scan_runner mistakes for "already cloned",
    # which causes drako to scan nothing and return default high scores.
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    # --- Load config ---
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    frameworks_cfg: dict[str, dict[str, object]] = cfg["frameworks"]

    # Derive per-framework substring patterns from the code-search queries
    patterns_by_fw: dict[str, list[str]] = {
        fw: extract_patterns_from_queries([str(q) for q in fw_cfg["queries"]])  # type: ignore[arg-type]
        for fw, fw_cfg in frameworks_cfg.items()
    }

    # --- Phase 1: Discovery ---
    click.echo("Phase 1: Discovering repos via code search...")
    discovered = discover_by_code_search(token=token, config=frameworks_cfg)

    total_discovered = sum(len(repos) for repos in discovered.values())
    click.echo(f"  Total discovered: {total_discovered} repos across {len(discovered)} frameworks")

    if total_discovered == 0:
        click.secho("No repos found. Check your token and queries.", fg="red")
        sys.exit(1)

    # Build framework map (repo_name -> framework)
    fw_map: dict[str, str] = {}
    all_repos: list[RepoInfo] = []
    for fw_name, repos in discovered.items():
        for repo in repos:
            fw_map[repo.full_name] = fw_name
            all_repos.append(repo)

    # --- Phase 2: Load checkpoint ---
    completed: dict[str, RepoScanResult] = {}
    usage_stats: dict[str, tuple[int, int, int]] = {}
    if resume:
        checkpoint = load_checkpoint(out)
        if checkpoint is not None:
            completed, _ = checkpoint
            click.echo(f"  Resumed: {len(completed)} repos from checkpoint")

    # --- Phase 3: Scan ---
    pending = [r for r in all_repos if r.full_name not in completed]
    click.echo(f"Phase 2: Scanning {len(all_repos)} repos ({len(pending)} pending, {len(completed)} cached)...")

    for i, repo in enumerate(pending, 1):
        fw = fw_map.get(repo.full_name, "?")
        click.echo(f"  [{i}/{len(pending)}] [{fw}] {repo.full_name} ({repo.stars}*)...", nl=False)

        result = scan_repo(repo, work_dir=work, timeout=timeout)
        if result is not None:
            # Override framework if scanner returned "unknown"
            if result.framework == "unknown" and repo.full_name in fw_map:
                result = RepoScanResult(
                    repo_name=result.repo_name,
                    score=result.score,
                    grade=result.grade,
                    framework=fw_map[repo.full_name],
                    findings_by_severity=result.findings_by_severity,
                    agents=result.agents,
                    tools=result.tools,
                    scan_duration_ms=result.scan_duration_ms,
                )

            # Framework relevance: count .py files importing the framework
            # BEFORE cleanup wipes the clone directory.
            fw_for_repo = fw_map.get(repo.full_name, "unknown")
            patterns = patterns_by_fw.get(fw_for_repo, [])
            repo_dir = work / repo.full_name.replace("/", "__")
            usage_stats[repo.full_name] = analyze_framework_usage(repo_dir, patterns)

            completed[repo.full_name] = result
            grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "red", "F": "red"}
            color = grade_colors.get(result.grade, "white")
            fc = usage_stats[repo.full_name][0]
            click.echo(" ", nl=False)
            click.secho(f"{result.score}/100 [{result.grade}] fw_files={fc}", fg=color)

            if not keep_clones:
                cleanup_repo(repo, work)
        else:
            click.secho(" SKIP", fg="yellow")

        # Save checkpoint after each repo
        remaining_names = [r.full_name for r in pending[i:]]
        save_checkpoint(completed, remaining_names, out)

    click.echo(f"\n  Scanned {len(completed)}/{len(all_repos)} repos")

    if not completed:
        click.secho("No repos could be scanned.", fg="red")
        sys.exit(1)

    # --- Phase 4: Partition by framework relevance ---
    kept: dict[str, RepoScanResult] = {}
    excluded: dict[str, RepoScanResult] = {}
    for name, r in completed.items():
        fc = usage_stats.get(name, (0, 0, 0))[0]
        if fc >= MIN_FRAMEWORK_FILES:
            kept[name] = r
        else:
            excluded[name] = r

    click.echo(
        f"  Relevance filter (>= {MIN_FRAMEWORK_FILES} framework files): "
        f"kept={len(kept)}, excluded={len(excluded)}"
    )

    # --- Phase 5: Generate outputs ---
    click.echo("Phase 3: Generating ecosystem index...")
    index = generate_ecosystem_index(kept, fw_map, usage_stats)
    index_path = save_ecosystem_index(index, out, filename="ecosystem_index.json")
    click.echo(f"  Output: {index_path}")

    if excluded:
        excluded_index = generate_ecosystem_index(
            excluded, fw_map, usage_stats,
            reason="insufficient_framework_usage",
        )
        excluded_path = save_ecosystem_index(
            excluded_index, out, filename="ecosystem_index_excluded.json"
        )
        click.echo(f"  Output: {excluded_path}")

    # --- Summary ---
    click.echo()
    click.echo("=== Framework Summary (kept only) ===")
    all_fws = sorted(set(fw_map.get(n, "unknown") for n in completed))
    for fw_name in all_fws:
        k_list = [r for n, r in kept.items() if fw_map.get(n) == fw_name]
        e_count = sum(1 for n in excluded if fw_map.get(n) == fw_name)
        if k_list:
            avg_k = round(sum(r.score for r in k_list) / len(k_list), 1)
        else:
            avg_k = 0.0
        click.echo(
            f"  {fw_name:18s} kept={len(k_list):2d}  excluded={e_count:2d}  avg={avg_k}"
        )

    click.echo("\n=== Top / Bottom per framework (kept only) ===")
    for fw_name in all_fws:
        repos_in_fw = [(n, r) for n, r in kept.items() if fw_map.get(n) == fw_name]
        if not repos_in_fw:
            click.echo(f"  {fw_name}: (no kept repos)")
            continue
        repos_in_fw.sort(key=lambda x: x[1].score, reverse=True)
        top_name, top_r = repos_in_fw[0]
        bot_name, bot_r = repos_in_fw[-1]
        top_fc = usage_stats[top_name][0]
        bot_fc = usage_stats[bot_name][0]
        click.echo(f"  {fw_name}")
        click.echo(f"    top:    {top_name:55s} {top_r.score:3d}  (framework_files={top_fc})")
        click.echo(f"    bottom: {bot_name:55s} {bot_r.score:3d}  (framework_files={bot_fc})")

    click.echo("\n=== Totals ===")
    click.echo(f"  Total kept:     {len(kept)}")
    click.echo(f"  Total excluded: {len(excluded)}")
    click.echo(f"  Total scanned:  {len(completed)}")
    click.echo(f"  Total unique repos discovered: {len(all_repos)}")

    # Discovered vs scanned vs failed per framework
    click.echo("\n=== Scan Success/Failure ===")
    discovered_per_fw: dict[str, int] = {fw: len(repos) for fw, repos in discovered.items()}
    scanned_per_fw: dict[str, int] = {}
    for repo_name in completed:
        fw = fw_map.get(repo_name, "unknown")
        scanned_per_fw[fw] = scanned_per_fw.get(fw, 0) + 1
    for fw_name in sorted(discovered_per_fw.keys()):
        d = discovered_per_fw[fw_name]
        s = scanned_per_fw.get(fw_name, 0)
        f = d - s
        click.echo(f"  {fw_name:18s} {d:3d} discovered  ->  {s:3d} scanned, {f:3d} failed")


if __name__ == "__main__":
    main()
