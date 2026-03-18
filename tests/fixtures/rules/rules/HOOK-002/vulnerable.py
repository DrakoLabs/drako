# ruleid: HOOK-002
# Config exists with hooks but no session-end gate (on_session_end)
# .drako.yaml:
#   hooks:
#     pre_action:
#       - name: validate-input
#         condition: "..."
#         action_on_fail: block
# (missing on_session_end)
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Complete user workflow")
