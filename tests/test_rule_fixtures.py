"""Auto-discovers rule fixtures and validates scanner accuracy.

For each rule in tests/fixtures/rules/<RULE-ID>/:
  - vulnerable.py MUST trigger the rule
  - safe.py must NOT trigger the rule

Important: Both files are tested in isolation (copied to a temp dir)
to prevent cross-contamination from the other .py file.

Directory convention for test-specific auxiliary files:
  - _safe/   — contents are only copied into the safe test temp dir
  - _vuln/   — contents are only copied into the vulnerable test temp dir
  - All other files/dirs are shared by both tests
"""
import json
import shutil
import tempfile
from pathlib import Path

import pytest

from drako.cli.scanner import run_scan

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "rules"


def discover_fixtures():
    if not FIXTURES_DIR.exists():
        return []
    results = []
    for rule_dir in sorted(FIXTURES_DIR.iterdir()):
        if not rule_dir.is_dir():
            continue
        meta_path = rule_dir / "rule.meta.json"
        vuln_path = rule_dir / "vulnerable.py"
        safe_path = rule_dir / "safe.py"
        if meta_path.exists() and vuln_path.exists() and safe_path.exists():
            meta = json.loads(meta_path.read_text())
            results.append((meta["id"], str(vuln_path), str(safe_path), meta))
    return results


_fixtures = discover_fixtures()


def _copy_entry(src: Path, dst: Path):
    """Copy a file or directory to the destination."""
    if src.is_file():
        shutil.copy2(src, dst)
    elif src.is_dir():
        shutil.copytree(src, dst)


def _populate_tmp(src_dir: Path, tmp_path: Path, *, skip: set[str], extra_dir: str | None = None):
    """Copy fixture contents to a temp dir, skipping named files.

    If extra_dir is given (e.g. '_safe'), also merge its contents into
    the temp dir root — so ``_safe/README.md`` becomes ``<tmp>/README.md``.
    """
    for f in src_dir.iterdir():
        if f.name in skip or f.name.startswith("_"):
            continue
        _copy_entry(f, tmp_path / f.name)

    # Merge test-specific overlay directory
    if extra_dir:
        overlay = src_dir / extra_dir
        if overlay.is_dir():
            for f in overlay.iterdir():
                _copy_entry(f, tmp_path / f.name)


@pytest.mark.parametrize(
    "rule_id,vuln,safe,meta",
    _fixtures,
    ids=[f[0] for f in _fixtures],
)
def test_vulnerable_triggers_rule(rule_id, vuln, safe, meta):
    """Vulnerable fixture must trigger the expected rule.

    Copies vulnerable.py to a temporary directory so the scanner only sees
    the vulnerable code — not the safe.py sitting in the same fixture dir.
    Any auxiliary files (requirements.txt, .drako.yaml, .gitignore) are
    also copied so framework/config detection still works.
    """
    src_dir = Path(vuln).parent
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(vuln, tmp_path / "vulnerable.py")
        _populate_tmp(
            src_dir, tmp_path,
            skip={"safe.py", "rule.meta.json", "vulnerable.py"},
            extra_dir="_vuln",
        )

        result = run_scan(str(tmp_path))
        triggered_ids = [f.policy_id for f in result.findings]
        assert rule_id in triggered_ids, (
            f"{rule_id}: vulnerable.py did not trigger rule. "
            f"Triggered: {triggered_ids}"
        )


@pytest.mark.parametrize(
    "rule_id,vuln,safe,meta",
    _fixtures,
    ids=[f[0] for f in _fixtures],
)
def test_safe_does_not_trigger_rule(rule_id, vuln, safe, meta):
    """Safe fixture must NOT trigger the expected rule.

    Copies safe.py to a temporary directory so the scanner only sees
    the safe code — not the vulnerable.py sitting in the same fixture dir.
    Any auxiliary files (requirements.txt, .drako.yaml, .gitignore) are
    also copied so framework/config detection still works.
    """
    src_dir = Path(safe).parent
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(safe, tmp_path / "safe.py")
        _populate_tmp(
            src_dir, tmp_path,
            skip={"vulnerable.py", "rule.meta.json", "safe.py"},
            extra_dir="_safe",
        )

        result = run_scan(str(tmp_path))
        false_positives = [
            f.policy_id for f in result.findings if f.policy_id == rule_id
        ]
        assert not false_positives, (
            f"{rule_id}: safe.py incorrectly triggered rule"
        )
