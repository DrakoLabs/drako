"""Anti-drift CI census: proves README, pyproject, conformance, and ADRs match live code."""

from __future__ import annotations

import json
import re
from pathlib import Path

from drako import __version__
from drako.cli.policies import ALL_POLICIES
from drako.kernel import ACS_SPEC_PIN, CTK_PIN

ROOT = Path(__file__).resolve().parent.parent


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


def test_zero_saas_strings_in_src():
    forbidden = re.compile(r"api\.getdrako\.com|DRAKO_API_KEY|DrakoClient")
    for py_file in (ROOT / "src" / "drako").rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        assert not forbidden.search(text), f"Stale SaaS reference found in {py_file}"
