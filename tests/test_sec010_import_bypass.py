"""P1-4 regression: bare `import drako` must NOT silence SEC-010 (2026-09-04).

Only an actual governance CALL (govern/with_compliance/GovernanceMiddleware)
counts as a configured defense.
"""

from drako.cli.scanner import run_scan


def test_bare_import_still_triggers(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import drako\n"
        "from crewai import Agent\n"
        "agent = Agent(name='a', system_prompt='hi')\n"
    )
    result = run_scan(str(tmp_path))
    assert "SEC-010" in [f.policy_id for f in result.findings]


def test_govern_call_silences(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from drako import govern\n"
        "from crewai import Agent, Crew\n"
        "agent = Agent(name='a', system_prompt='hi')\n"
        "crew = govern(Crew(agents=[agent]))\n"
    )
    result = run_scan(str(tmp_path))
    assert "SEC-010" not in [f.policy_id for f in result.findings]
