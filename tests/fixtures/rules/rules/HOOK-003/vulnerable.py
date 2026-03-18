# ruleid: HOOK-003
# Hook scripts defined without timeout_ms — runaway scripts could block pipeline
# .drako.yaml:
#   hooks:
#     pre_action:
#       - name: validate-schema
#         script: .drako/hooks/validate_schema.py
#         (missing timeout_ms)
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Execute validated actions")
