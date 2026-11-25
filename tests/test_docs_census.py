"""Anti-drift CI census: proves README, pyproject, docs, CI, deploy, and templates match live v4 code."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from drako import __version__
from drako.cli.policies import ALL_POLICIES
from drako.config import DrakoConfig
from drako.kernel import ACS_SPEC_PIN, CTK_PIN

ROOT = Path(__file__).resolve().parent.parent

_FORBIDDEN_SAAS_PATTERNS = (
    "Pro plan",
    "Drako dashboard",
    "api.getdrako.com",
    "api.useagentmesh.com",
    "DRAKO_API_KEY",
    "DrakoClient",
    "BUSL-1.1",
    "Collective Intelligence",
    "angelnicolasc/drako",
    "from drako import with_compliance",
    "GovernanceMiddleware(api_key",
)

_FORBIDDEN_SAAS_RE = re.compile(
    "|".join(re.escape(p) for p in _FORBIDDEN_SAAS_PATTERNS)
)


def _iter_surface_files() -> list[Path]:
    """Return all active source, docs, legal, CI, pre-commit, and deploy files."""
    files: list[Path] = []

    for py_file in sorted((ROOT / "src" / "drako").rglob("*")):
        if py_file.is_file() and py_file.suffix in {".py", ".yaml", ".yml", ".json", ".proxy"}:
            files.append(py_file)

    for doc_file in sorted((ROOT / "docs").rglob("*.md")):
        rel = doc_file.relative_to(ROOT).as_posix()
        if rel.startswith("docs/adr/") or rel == "docs/migration-v4.md":
            continue
        files.append(doc_file)

    for top_file in ("CONTRIBUTING.md", "SECURITY.md", ".pre-commit-hooks.yaml", "pyproject.toml"):
        p = ROOT / top_file
        if p.exists():
            files.append(p)

    for extra_dir in (ROOT / ".github", ROOT / "deploy"):
        if extra_dir.exists():
            for f in sorted(extra_dir.rglob("*")):
                if f.is_file():
                    files.append(f)

    return files


def test_version_and_license_consistency():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in pyproject
    assert 'license = "Apache-2.0"' in pyproject
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text and "Version 2.0" in license_text


def test_readme_honesty_and_exact_rule_census():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    unique_rules = len({p.policy_id for p in ALL_POLICIES})
    total_objects = len(ALL_POLICIES)

    assert str(unique_rules) in readme, f"README missing exact unique rule count ({unique_rules})"
    assert str(total_objects) in readme, f"README missing exact policy object count ({total_objects})"
    assert "Apache-2.0" in readme
    assert ACS_SPEC_PIN in readme

    # Retired v3 / SaaS / false claims must NEVER creep back into README
    for forbidden in (
        "BUSL-1.1",
        "api.getdrako.com",
        "DRAKO_API_KEY",
        "drako push",
        "drako status",
        "OWASP LLM01:2025",
    ):
        assert forbidden not in readme, f"Forbidden stale string in README.md: {forbidden!r}"


def test_all_adrs_indexed_and_accepted():
    adr_dir = ROOT / "docs" / "adr"
    index = (adr_dir / "README.md").read_text(encoding="utf-8")
    adr_files = sorted(adr_dir.glob("[0-9][0-9][0-9][0-9]-*.md"))
    assert len(adr_files) >= 14
    for f in adr_files:
        assert f.name in index, f"ADR {f.name} missing from docs/adr/README.md"
        text = f.read_text(encoding="utf-8")
        assert "**Status:** Accepted" in text, f"ADR {f.name} is not marked Accepted"


def test_conformance_surface_matches_kernel_pins():
    surface = json.loads((ROOT / "conformance" / "declared_surface.json").read_text(encoding="utf-8"))
    assert surface["spec_pin"] == ACS_SPEC_PIN
    assert surface["ctk_pin"] == CTK_PIN
    assert surface["version"] == __version__
    assert (ROOT / "conformance" / "CLAIMS.md").exists()


def test_zero_saas_strings_in_repo_surface():
    violations: list[str] = []
    for path in _iter_surface_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        match = _FORBIDDEN_SAAS_RE.search(text)
        if match:
            rel = path.relative_to(ROOT).as_posix()
            violations.append(f"{rel}: matched {match.group(0)!r}")
    assert not violations, "Stale open-core/SaaS strings found:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    "template_name,expected_dlp,expected_retention,expected_hitl,expected_a2a",
    [
        ("base", "audit", 7, "audit", "audit"),
        ("startup", "audit", 30, "audit", "audit"),
        ("fintech", "enforce", 365, "enforce", "enforce"),
        ("healthcare", "enforce", 2190, "enforce", "enforce"),
        ("eu-ai-act", "enforce", 3650, "enforce", "enforce"),
        ("enterprise", "enforce", 365, "enforce", "enforce"),
    ],
)
def test_extends_template_fields_apply_in_drako_config(
    tmp_path: Path,
    template_name: str,
    expected_dlp: str,
    expected_retention: int,
    expected_hitl: str,
    expected_a2a: str,
):
    cfg = tmp_path / ".drako.yaml"
    cfg.write_text(f'version: "4.0"\nextends: {template_name}\n', encoding="utf-8")
    loaded = DrakoConfig.load(str(cfg))
    assert loaded.dlp.mode == expected_dlp
    assert loaded.audit.retention_days == expected_retention
    assert loaded.hitl.mode == expected_hitl
    assert loaded.a2a.mode == expected_a2a


def test_hypothesis_cache_not_tracked_in_git():
    if not (ROOT / ".git").exists():
        pytest.skip("Not running inside a git checkout")
    proc = subprocess.run(
        ["git", "ls-files", ".hypothesis"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    tracked = [line for line in proc.stdout.splitlines() if line.strip()]
    assert not tracked, f"Tracked .hypothesis cache files found in git: {tracked[:5]}"
