"""Demo CrewAI project with intentional governance gaps.

This project is designed for testing Drako scan. It contains
deliberate security and governance issues to demonstrate findings.

Expected scan score: ~35 (Grade F)

Run: drako scan .
"""

import os

from crewai import Agent, Crew, Task

# ruleid: SEC-001 — Hardcoded API key
OPENAI_API_KEY = "sk-proj-demo-key-not-real-1234567890abcdef"

# ruleid: SEC-007 — Prompt injection via f-string
def build_prompt(user_input):
    prompt = f"Research the following topic thoroughly: {user_input}"
    return prompt


# ruleid: SEC-005 — Arbitrary code execution
def run_analysis(code: str) -> str:
    """Execute analysis code provided by the agent."""
    result = {}
    exec(code, {"__builtins__": {}}, result)
    return str(result)


# ruleid: SEC-003 — Unrestricted filesystem access
def read_file(path: str) -> str:
    """Read any file from the filesystem."""
    with open(path) as f:
        return f.read()


# ruleid: SEC-003 — Unrestricted filesystem write
def write_file(path: str, content: str) -> str:
    """Write content to any file."""
    with open(path, "w") as f:
        f.write(content)
    return f"Written to {path}"


# No input validation (SEC-006)
def search_web(query, max_results):
    """Search the web without validation."""
    return f"Results for: {query}"


# ruleid: GOV-006 — Agent can modify its own prompt
class ResearchAgent(Agent):
    def adapt_to_feedback(self, feedback):
        self.system_prompt = f"Updated instructions based on: {feedback}"
        return self.run()


researcher = Agent(
    role="Senior Researcher",
    goal="Find comprehensive information on any topic",
    backstory="An experienced researcher with access to all tools",
    tools=[read_file, write_file, search_web, run_analysis],
    llm="gpt-4o",
    verbose=True,
)

writer = Agent(
    role="Content Writer",
    goal="Write detailed reports based on research",
    backstory="A skilled writer who produces comprehensive reports",
    tools=[read_file, write_file],
    llm="gpt-4o",
    verbose=True,
)

research_task = Task(
    description=build_prompt("AI governance best practices"),
    expected_output="A comprehensive research summary",
    agent=researcher,
)

writing_task = Task(
    description="Write a detailed report based on the research findings",
    expected_output="A polished report in markdown format",
    agent=writer,
)

# ruleid: GOV-001 — No audit logging
# ruleid: GOV-009 — Destructive actions without HITL
# ruleid: ODD-001 — No operational boundaries
# ruleid: MAG-001 — No spend cap
crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    verbose=True,
)

if __name__ == "__main__":
    result = crew.kickoff()
    print(result)
