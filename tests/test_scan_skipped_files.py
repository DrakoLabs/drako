"""U-4: skipped files are observable (2026-09-04).

AST-based rules `except SyntaxError: continue` on unparseable files. The
scan-level pre-pass must surface exactly that set: counter in terminal +
JSON, never silent.
"""

import json

from drako.cli.formats.json_fmt import format_json
from drako.cli.scanner import find_unparseable_files, run_scan

BROKEN = "def broken(:\n  this is not python\n"
VALID = "x = 1\n"


def test_broken_file_is_listed(tmp_path):
    (tmp_path / "broken.py").write_text(BROKEN)
    (tmp_path / "ok.py").write_text(VALID)
    result = run_scan(str(tmp_path))
    assert any(str(p).endswith("broken.py") for p in result.skipped_files)
    assert not any(str(p).endswith("ok.py") for p in result.skipped_files)


def test_clean_project_skips_nothing(tmp_path):
    (tmp_path / "ok.py").write_text(VALID)
    assert run_scan(str(tmp_path)).skipped_files == []


def test_helper_matches_scan(tmp_path):
    (tmp_path / "broken.py").write_text(BROKEN)
    result = run_scan(str(tmp_path))
    from drako.cli.discovery import collect_project_files
    from pathlib import Path

    meta = collect_project_files(Path(str(tmp_path)).resolve())
    assert find_unparseable_files(meta.file_contents) == result.skipped_files


def test_json_output_carries_skipped(tmp_path):
    (tmp_path / "broken.py").write_text(BROKEN)
    data = json.loads(format_json(run_scan(str(tmp_path))))
    assert any(str(p).endswith("broken.py") for p in data["skipped_files"])
