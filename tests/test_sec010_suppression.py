"""U-5: suppression by AST USE for the WHOLE pattern list (2026-09-04).

For every entry in _INJECTION_DEFENSE_PATTERNS: calling it silences SEC-010,
merely importing it still flags. Table-driven: one test per pattern ×2.
"""

import pytest

from drako.cli.policies.security import _INJECTION_DEFENSE_PATTERNS
from drako.cli.scanner import run_scan

AGENT = "from crewai import Agent\nagent = Agent(name='a', system_prompt='hi')\n"


def _call_snippet(pattern: str) -> str:
    name = pattern.strip("_")
    return f"{AGENT}\nresult = {name}(user_input)\n"


def _import_snippet(pattern: str) -> str:
    name = pattern.strip("_")
    return f"import {name}\n{AGENT}"


@pytest.mark.parametrize("pattern", _INJECTION_DEFENSE_PATTERNS)
def test_call_silences(tmp_path, pattern):
    (tmp_path / "agent.py").write_text(_call_snippet(pattern))
    ids = [f.policy_id for f in run_scan(str(tmp_path)).findings]
    assert "SEC-010" not in ids, pattern


@pytest.mark.parametrize("pattern", _INJECTION_DEFENSE_PATTERNS)
def test_import_only_still_flags(tmp_path, pattern):
    (tmp_path / "agent.py").write_text(_import_snippet(pattern))
    ids = [f.policy_id for f in run_scan(str(tmp_path)).findings]
    assert "SEC-010" in ids, pattern
