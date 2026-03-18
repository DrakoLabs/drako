# ok: HOOK-001
# Pre-action hooks configured in .drako.yaml
# hooks:
#   pre_action:
#     - name: block-dangerous-sql
#       condition: "tool_name == 'execute_sql' and 'DROP' in tool_args"
#       action_on_fail: block
from crewai import Agent

agent = Agent(
    name="assistant",
    role="DB Admin",
    tools=["execute_sql", "file_write"],
)
agent.run(task="Run maintenance queries")
