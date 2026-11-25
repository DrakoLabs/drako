"""Auto-discovers TypeScript rule fixtures and validates scanner accuracy.

For each rule in tests/fixtures/rules/typescript/<RULE-ID>/:
  - vulnerable.ts MUST trigger the rule
  - safe.ts must NOT trigger the rule

Requires ``pip install drako[typescript]`` (tree-sitter).
"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from drako.ts_parser._compat import ts_available

if not ts_available():
    pytest.skip("tree-sitter not installed — skipping TS fixtures", allow_module_level=True)

from drako.cli.scanner import run_scan

TS_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "rules" / "typescript"


def discover_ts_fixtures() -> list[tuple[str, str, str, dict[str, str]]]:
    if not TS_FIXTURES_DIR.exists():
        return []
    results: list[tuple[str, str, str, dict[str, str]]] = []
    for rule_dir in sorted(TS_FIXTURES_DIR.iterdir()):
        if not rule_dir.is_dir():
            continue
        meta_path = rule_dir / "rule.meta.json"
        vuln_path = rule_dir / "vulnerable.ts"
        safe_path = rule_dir / "safe.ts"
        if meta_path.exists() and vuln_path.exists() and safe_path.exists():
            meta = json.loads(meta_path.read_text())
            results.append((meta["id"], str(vuln_path), str(safe_path), meta))
    return results


_ts_fixtures = discover_ts_fixtures()


def _copy_entry(src: Path, dst: Path) -> None:
    if src.is_file():
        shutil.copy2(src, dst)
    elif src.is_dir():
        shutil.copytree(src, dst)


def _populate_tmp(
    src_dir: Path, tmp_path: Path, *, skip: set[str], extra_dir: str | None = None,
) -> None:
    for f in src_dir.iterdir():
        if f.name in skip or f.name.startswith("_"):
            continue
        _copy_entry(f, tmp_path / f.name)
    if extra_dir:
        overlay = src_dir / extra_dir
        if overlay.is_dir():
            for f in overlay.iterdir():
                _copy_entry(f, tmp_path / f.name)


@pytest.mark.parametrize(
    "rule_id,vuln,safe,meta",
    _ts_fixtures,
    ids=[f[0] + "-TS-vuln" for f in _ts_fixtures],
)
def test_ts_vulnerable_triggers_rule(
    rule_id: str, vuln: str, safe: str, meta: dict[str, str],
) -> None:
    """Vulnerable .ts fixture MUST trigger the expected rule."""
    src_dir = Path(vuln).parent
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(vuln, tmp_path / "vulnerable.ts")
        _populate_tmp(
            src_dir, tmp_path,
            skip={"safe.ts", "rule.meta.json", "vulnerable.ts"},
            extra_dir="_vuln",
        )

        result = run_scan(str(tmp_path))
        triggered_ids = [f.policy_id for f in result.findings]
        assert rule_id in triggered_ids, (
            f"{rule_id}: vulnerable.ts did not trigger rule. "
            f"Triggered: {triggered_ids}"
        )


@pytest.mark.parametrize(
    "rule_id,vuln,safe,meta",
    _ts_fixtures,
    ids=[f[0] + "-TS-safe" for f in _ts_fixtures],
)
def test_ts_safe_does_not_trigger_rule(
    rule_id: str, vuln: str, safe: str, meta: dict[str, str],
) -> None:
    """Safe .ts fixture must NOT trigger the expected rule."""
    src_dir = Path(safe).parent
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(safe, tmp_path / "safe.ts")
        _populate_tmp(
            src_dir, tmp_path,
            skip={"vulnerable.ts", "rule.meta.json", "safe.ts"},
            extra_dir="_safe",
        )

        result = run_scan(str(tmp_path))
        false_positives = [
            f.policy_id for f in result.findings if f.policy_id == rule_id
        ]
        assert not false_positives, (
            f"{rule_id}: safe.ts incorrectly triggered rule"
        )
