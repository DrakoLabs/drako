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
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import click
import httpx
import yaml

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
            query = str(fw_cfg["query"])
            min_stars = int(fw_cfg.get("min_stars", 50))  # type: ignore[arg-type]
            limit = int(fw_cfg.get("limit", 15))  # type: ignore[arg-type]

            click.echo(f"  [{fw_name}] Searching: {query}")
            repos_for_fw: list[RepoInfo] = []
            seen_in_query: set[str] = set()

            # Code Search API: paginate up to 3 pages
            for page in range(1, 4):
                if len(repos_for_fw) >= limit:
                    break

                url = f"{_GITHUB_API}/search/code"
                params = {"q": query, "per_page": 30, "page": page}

                try:
                    resp = client.get(url, headers=headers, params=params)
                except httpx.HTTPError as e:
                    click.echo(f"    HTTP error: {e}", err=True)
                    break

                if resp.status_code in (403, 429):
                    _sleep_for_rate_limit(resp)
                    continue

                if resp.status_code == 422:
                    click.echo(f"    Code search returned 422 (validation error), skipping", err=True)
                    break

                if resp.status_code != 200:
                    click.echo(f"    Code search returned {resp.status_code}", err=True)
                    break

                _sleep_for_rate_limit(resp)

                data = resp.json()
                items: list[dict[str, object]] = data.get("items", [])
                if not items:
                    break

                # Extract unique repos from code search results
                for item in items:
                    repo_data = item.get("repository", {})
                    full_name = str(repo_data.get("full_name", ""))  # type: ignore[union-attr]
                    if not full_name or full_name in seen_in_query or full_name in global_seen:
                        continue
                    seen_in_query.add(full_name)

                # Fetch metadata for each unique repo
                for full_name in list(seen_in_query):
                    if full_name in global_seen or len(repos_for_fw) >= limit:
                        continue

                    time.sleep(1)  # Be gentle with API
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

                # Code Search rate limit: 10 req/min for authenticated users
                time.sleep(6)

            repos_for_fw.sort(key=lambda r: r.stars, reverse=True)
            result[fw_name] = repos_for_fw[:limit]
            click.echo(f"    Found {len(result[fw_name])} repos (>={min_stars} stars)")

    finally:
        client.close()

    return result


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def _anonymize(repo_name: str) -> str:
    """SHA-256 hash truncated to 8 hex chars."""
    return hashlib.sha256(repo_name.encode()).hexdigest()[:8]


def generate_ecosystem_index(
    completed: dict[str, RepoScanResult],
    fw_map: dict[str, str],
) -> dict[str, object]:
    """Build the ecosystem_index.json structure.

    Args:
        completed: All scan results keyed by repo full_name.
        fw_map: Mapping of repo full_name -> framework name (from discovery).

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

        projects.append({
            "id": _anonymize(repo_name),
            "framework": fw,
            "governance_score": result.score,
            "grade": result.grade,
            "agents": result.agents,
            "tools": result.tools,
            "findings_by_severity": result.findings_by_severity,
        })

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


def save_ecosystem_index(index: dict[str, object], output_dir: Path) -> Path:
    """Atomically write ecosystem_index.json."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "ecosystem_index.json"

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
    work.mkdir(parents=True, exist_ok=True)

    # --- Load config ---
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    frameworks_cfg: dict[str, dict[str, object]] = cfg["frameworks"]

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

            completed[repo.full_name] = result
            grade_colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "red", "F": "red"}
            color = grade_colors.get(result.grade, "white")
            click.echo(" ", nl=False)
            click.secho(f"{result.score}/100 [{result.grade}]", fg=color)

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

    # --- Phase 4: Generate output ---
    click.echo("Phase 3: Generating ecosystem index...")
    index = generate_ecosystem_index(completed, fw_map)
    index_path = save_ecosystem_index(index, out)
    click.echo(f"  Output: {index_path}")

    # --- Summary ---
    click.echo()
    click.echo("=== Summary ===")
    by_fw = index.get("by_framework", {})
    assert isinstance(by_fw, dict)
    for fw_name, stats in sorted(by_fw.items()):
        assert isinstance(stats, dict)
        click.echo(
            f"  {fw_name}: {stats['count']} repos, "
            f"avg governance {stats['avg_governance']}/100, "
            f"grades {stats['grade_distribution']}"
        )
    avg = round(sum(r.score for r in completed.values()) / len(completed), 1)
    click.echo(f"\n  Overall: {len(completed)} projects, average governance score: {avg}/100")


if __name__ == "__main__":
    main()
