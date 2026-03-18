"""Best practices policy rules (BP-001 through BP-005)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata

# Known latest major versions for framework outdated checks
_KNOWN_LATEST: dict[str, str] = {
    "crewai": "0.85",
    "langgraph": "0.3",
    "autogen": "0.5",
    "langchain": "0.3",
    "llamaindex": "0.11",
    "pydantic_ai": "0.1",
}

# Retry/fallback patterns
_RETRY_PATTERNS = [
    "retry", "tenacity", "backoff", "retrying", "max_retries",
    "retry_count", "fallback", "with_retry", "exponential_backoff",
]

# Timeout patterns
_TIMEOUT_PATTERNS = [
    "timeout", "time_limit", "max_time", "deadline", "timer",
    "asyncio.wait_for", "asyncio.timeout",
]


def _content_has_pattern(all_content: str, patterns: list[str]) -> bool:
    lower = all_content.lower()
    return any(p.lower() in lower for p in patterns)


# ---------------------------------------------------------------------------
# BP-001: Framework outdated (major version behind)
# ---------------------------------------------------------------------------

class BP001(BasePolicy):
    policy_id = "BP-001"
    category = "Best Practices"
    severity = "LOW"
    title = "Framework outdated"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for fw in bom.frameworks:
            if fw.name not in _KNOWN_LATEST or not fw.version:
                continue

            try:
                current_major = fw.version.split(".")[0]
                latest_version = _KNOWN_LATEST[fw.name]
                latest_major = latest_version.split(".")[0]

                if int(current_major) < int(latest_major):
                    findings.append(Finding(
                        policy_id=self.policy_id,
                        category=self.category,
                        severity=self.severity,
                        title=self.title,
                        message=f"{fw.name} {fw.version} is outdated (latest: {latest_version}+). Consider upgrading.",
                        fix_snippet=f"pip install --upgrade {fw.name}",
                    ))
            except (ValueError, IndexError):
                continue

        return findings


# ---------------------------------------------------------------------------
# BP-002: No tests for agents
# ---------------------------------------------------------------------------

class BP002(BasePolicy):
    policy_id = "BP-002"
    category = "Best Practices"
    severity = "MEDIUM"
    title = "No tests for agents"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.agents:
            return []

        # Check if there are any test files
        test_files = [
            p for p in metadata.file_contents.keys()
            if p.endswith(".py") and ("test_" in p or "_test.py" in p or p.startswith("tests/"))
        ]

        if not test_files:
            agent_names = ", ".join(a.name for a in bom.agents[:5])
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"No test files found for agents: {agent_names}. Agent behavior should be tested.",
                fix_snippet='# Create tests for your agents\n# tests/test_agents.py\nimport pytest\n\ndef test_agent_responds():\n    """Test that agent produces valid output."""\n    result = my_agent.run("test query")\n    assert result is not None\n    assert len(result) > 0\n\ndef test_agent_handles_error():\n    """Test agent error handling."""\n    result = my_agent.run("")\n    assert "error" not in result.lower()',
            )]

        # Check if test files reference agent names
        all_test_content = "\n".join(
            c for p, c in metadata.file_contents.items()
            if p.endswith(".py") and ("test_" in p or "_test.py" in p)
        ).lower()

        untested_agents = []
        for agent in bom.agents:
            agent_lower = agent.name.lower()
            if agent_lower not in all_test_content:
                untested_agents.append(agent.name)

        if untested_agents and len(untested_agents) == len(bom.agents):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"Test files exist but no agents are tested: {', '.join(untested_agents[:5])}",
                fix_snippet='# Add tests that cover your agents\n# Ensure each agent\'s name or class is referenced in test files\ndef test_research_agent():\n    agent = ResearchAgent()\n    result = agent.run("test query")\n    assert result is not None',
            )]

        return []


# ---------------------------------------------------------------------------
# BP-003: No retry/fallback in LLM calls
# ---------------------------------------------------------------------------

class BP003(BasePolicy):
    policy_id = "BP-003"
    category = "Best Practices"
    severity = "LOW"
    title = "No retry/fallback in LLM calls"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.models:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _RETRY_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message="No retry or fallback mechanism detected for LLM calls. API failures will crash the pipeline.",
                fix_snippet='from tenacity import retry, stop_after_attempt, wait_exponential\n\n@retry(\n    stop=stop_after_attempt(3),\n    wait=wait_exponential(multiplier=1, min=1, max=10),\n)\ndef call_llm(prompt: str) -> str:\n    return client.chat(prompt)\n\n# Or use a fallback model\ndef call_with_fallback(prompt: str) -> str:\n    try:\n        return call_llm_primary(prompt)\n    except Exception:\n        return call_llm_fallback(prompt)',
            )]

        return []


# ---------------------------------------------------------------------------
# BP-004: No timeout on tool executions
# ---------------------------------------------------------------------------

class BP004(BasePolicy):
    policy_id = "BP-004"
    category = "Best Practices"
    severity = "MEDIUM"
    title = "No timeout on tool executions"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.tools:
            return []

        all_content = "\n".join(
            c for p, c in metadata.file_contents.items() if p.endswith(".py")
        )

        if not _content_has_pattern(all_content, _TIMEOUT_PATTERNS):
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=f"No timeout configured for {len(bom.tools)} tool(s). Hanging tools could block the entire pipeline.",
                fix_snippet='import asyncio\nimport signal\nfrom functools import wraps\n\ndef with_timeout(seconds: int = 30):\n    def decorator(func):\n        @wraps(func)\n        async def wrapper(*args, **kwargs):\n            return await asyncio.wait_for(\n                func(*args, **kwargs),\n                timeout=seconds,\n            )\n        return wrapper\n    return decorator\n\n@with_timeout(30)\nasync def my_tool(query: str) -> str:\n    ...',
            )]

        return []


# ---------------------------------------------------------------------------
# BP-005: More than 10 tools registered on a single agent
# ---------------------------------------------------------------------------

class BP005(BasePolicy):
    policy_id = "BP-005"
    category = "Best Practices"
    severity = "LOW"
    title = "Too many tools on single agent"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        findings: list[Finding] = []

        for agent in bom.agents:
            if len(agent.tools) > 10:
                findings.append(Finding(
                    policy_id=self.policy_id,
                    category=self.category,
                    severity=self.severity,
                    title=self.title,
                    message=f'Agent "{agent.name}" has {len(agent.tools)} tools registered (recommend < 10). Too many tools reduce accuracy.',
                    file_path=agent.file_path,
                    line_number=agent.line_number,
                    fix_snippet=f'# Split tools across specialized sub-agents\nresearch_agent = Agent(\n    name="researcher",\n    tools=[search_web, read_url],  # 2 tools\n)\nwriter_agent = Agent(\n    name="writer",\n    tools=[write_file, format_text],  # 2 tools\n)',
                ))

        return findings


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

BEST_PRACTICE_POLICIES: list[BasePolicy] = [
    BP001(),
    BP002(),
    BP003(),
    BP004(),
    BP005(),
]
