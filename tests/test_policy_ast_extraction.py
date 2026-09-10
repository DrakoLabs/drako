"""P1-4 regression: AST function extraction (2026-09-04).

The old regex (`def NAME(...).*?(?=\\ndef)`) broke on decorators, async def,
and methods. These tests pin the fixed behavior at helper level and through
run_scan end-to-end.
"""

from drako.cli.policies.base import find_function_node, function_body_text
from drako.cli.scanner import run_scan

DECORATED = '''
from crewai import Agent, Task, Crew

@tool("fetch_page")
def fetch_page(url: str) -> str:
    import requests
    return requests.get(url, timeout=10).text

agent = Agent(name="r", system_prompt="x")
task = Task(description="fetch", agent=agent)
crew = Crew(agents=[agent], tasks=[task])
'''

DECORATED_SAFE = DECORATED.replace(
    "return requests.get(url, timeout=10).text",
    "from urllib.parse import urlparse\n"
    "    host = urlparse(url).hostname\n"
    "    if host not in ALLOWED_DOMAINS:\n"
    "        raise ValueError('blocked')\n"
    "    import requests\n"
    "    return requests.get(url, timeout=10).text",
)

ASYNC_TOOL = DECORATED.replace("def fetch_page", "async def fetch_page")

METHOD_TOOL = '''
from crewai import Agent, Task, Crew

class Tools:
    def fetch_page(self, url: str) -> str:
        import requests
        return requests.get(url, timeout=10).text

agent = Agent(name="r", system_prompt="x")
task = Task(description="fetch", agent=agent)
crew = Crew(agents=[agent], tasks=[task])
'''


def test_find_decorated_async_method():
    assert find_function_node(DECORATED, "fetch_page") is not None
    assert find_function_node(ASYNC_TOOL, "fetch_page") is not None
    assert find_function_node(METHOD_TOOL, "fetch_page") is not None
    assert find_function_node(DECORATED, "nope") is None
    assert find_function_node("def broken(:", "broken") is None


def test_body_is_exact_function_source():
    body = function_body_text(DECORATED, "fetch_page")
    assert body is not None and "requests.get" in body
    assert "agent = Agent" not in body  # not the regex slice bleed
    assert function_body_text(DECORATED, "missing") is None


def test_decorated_unvalidated_tool_still_flags(tmp_path):
    (tmp_path / "agent.py").write_text(DECORATED)
    ids = [f.policy_id for f in run_scan(str(tmp_path)).findings]
    assert "SEC-004" in ids  # network without allowlist, body found


def test_decorated_validated_tool_does_not_flag_sec004(tmp_path):
    (tmp_path / "agent.py").write_text(DECORATED_SAFE)
    ids = [f.policy_id for f in run_scan(str(tmp_path)).findings]
    assert "SEC-004" not in ids
