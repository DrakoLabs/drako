# ruleid: HOOK-001
# Tools defined but no pre-action validation hooks configured
from crewai import Agent

agent = Agent(
    name="assistant",
    role="DB Admin",
    tools=["execute_sql", "file_write"],
)

# No .drako.yaml with hooks.pre_action
agent.run(task="Run maintenance queries")
