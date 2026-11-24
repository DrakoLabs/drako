"""Tests for determinism policy rules (DET-001 through DET-007)."""

from __future__ import annotations

from pathlib import Path

import pytest

from drako.cli.policies.determinism import DETERMINISM_POLICIES, DET001, DET002, DET003, DET004, DET005, DET006, DET007
from drako.cli.bom import AgentBOM, DetectedAgent, DetectedTool
from drako.cli.discovery import ProjectMetadata, FrameworkInfo
from drako.cli.scoring import calculate_determinism_score, calculate_score, score_to_grade


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_metadata(files: dict[str, str]) -> ProjectMetadata:
    return ProjectMetadata(
        root=Path("/fake"),
        python_files=[],
        config_files={},
        file_contents=files,
        dependencies={},
        frameworks=[],
    )


def _make_bom(
    agents: list | None = None,
    tools: list | None = None,
) -> AgentBOM:
    return AgentBOM(
        agents=agents or [],
        tools=tools or [],
        models=[],
        mcp_servers=[],
        prompts=[],
        permissions=[],
        frameworks=[],
        dependencies={},
    )


def _agent(name: str, tools: list[str], n_tools: int = 0) -> DetectedAgent:
    if n_tools > 0:
        tools = [f"tool_{i}" for i in range(n_tools)]
    return DetectedAgent(
        name=name,
        class_name="Agent",
        file_path="agents.py",
        line_number=1,
        framework="crewai",
        tools=tools,
        model="gpt-4",
    )


# ---------------------------------------------------------------------------
# DET-001: Temperature
# ---------------------------------------------------------------------------

class TestDET001:
    def test_fires_when_temperature_not_set(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        policy = DET001()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) > 0
        assert all(f.policy_id == "DET-001" for f in findings)

    def test_fires_when_temperature_high(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[], temperature=0.7)
'''
        policy = DET001()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) > 0

    def test_no_finding_when_temperature_zero(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[], temperature=0)
'''
        policy = DET001()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DET-002: Timeout
# ---------------------------------------------------------------------------

class TestDET002:
    def test_fires_when_no_timeout(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        policy = DET002()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) > 0

    def test_no_finding_when_timeout_set(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[], timeout=30)
'''
        policy = DET002()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DET-003: Retry/Fallback
# ---------------------------------------------------------------------------

class TestDET003:
    def test_fires_when_no_retry(self):
        code = '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4")
result = llm.invoke("hello")
'''
        policy = DET003()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) > 0

    def test_no_finding_when_retry_present(self):
        code = '''
from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt

@retry(stop=stop_after_attempt(3))
def call_llm():
    llm = ChatOpenAI(model="gpt-4")
    return llm.invoke("hello")
'''
        policy = DET003()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DET-004: External API without try/except
# ---------------------------------------------------------------------------

class TestDET004:
    def test_fires_when_no_error_handling(self):
        code = '''
import httpx
data = httpx.get("https://api.example.com/data").json()
'''
        policy = DET004()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) > 0

    def test_no_finding_when_wrapped_in_try(self):
        code = '''
import httpx
try:
    data = httpx.get("https://api.example.com/data").json()
except httpx.HTTPError:
    data = {}
'''
        policy = DET004()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DET-005: No max_iterations
# ---------------------------------------------------------------------------

class TestDET005:
    def test_fires_when_no_iteration_limit(self):
        bom = _make_bom(agents=[_agent("researcher", ["search"])])
        metadata = _make_metadata({"app.py": "agent = Agent(name='researcher')"})
        policy = DET005()
        findings = policy.evaluate(bom, metadata)
        assert len(findings) > 0

    def test_no_finding_when_limit_set(self):
        bom = _make_bom(agents=[_agent("researcher", ["search"])])
        metadata = _make_metadata({"app.py": "agent = Agent(name='researcher', max_iterations=10)"})
        policy = DET005()
        findings = policy.evaluate(bom, metadata)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DET-006: Non-deterministic tool ordering
# ---------------------------------------------------------------------------

class TestDET006:
    def test_fires_when_many_tools(self):
        bom = _make_bom(agents=[_agent("researcher", [], n_tools=7)])
        policy = DET006()
        findings = policy.evaluate(bom, _make_metadata({}))
        assert len(findings) > 0

    def test_no_finding_when_few_tools(self):
        bom = _make_bom(agents=[_agent("researcher", ["a", "b", "c"])])
        policy = DET006()
        findings = policy.evaluate(bom, _make_metadata({}))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DET-007: No seed
# ---------------------------------------------------------------------------

class TestDET007:
    def test_fires_when_no_seed(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
'''
        policy = DET007()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) > 0

    def test_no_finding_when_seed_set(self):
        code = '''
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[], seed=42)
'''
        policy = DET007()
        findings = policy.evaluate(_make_bom(), _make_metadata({"app.py": code}))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Scoring integration
# ---------------------------------------------------------------------------

class TestDeterminismScoring:
    def test_determinism_score_computed_separately(self):
        from drako.cli.policies.base import Finding

        det_finding = Finding(
            policy_id="DET-001", category="Determinism", severity="HIGH",
            title="test", message="test",
        )
        sec_finding = Finding(
            policy_id="SEC-001", category="Security", severity="CRITICAL",
            title="test", message="test",
        )
        findings = [det_finding, sec_finding]

        det_score = calculate_determinism_score(findings)
        gov_score = calculate_score(findings)

        # Determinism score should only be affected by DET findings
        assert det_score == 100 - 5  # one HIGH = -5
        # Governance score should include both (with category cap on Determinism)
        assert gov_score < 100

    def test_all_determinism_policies_registered(self):
        assert len(DETERMINISM_POLICIES) == 7
        ids = [p.policy_id for p in DETERMINISM_POLICIES]
        assert ids == ["DET-001", "DET-002", "DET-003", "DET-004", "DET-005", "DET-006", "DET-007"]

    def test_all_have_category_determinism(self):
        for p in DETERMINISM_POLICIES:
            assert p.category == "Determinism"
