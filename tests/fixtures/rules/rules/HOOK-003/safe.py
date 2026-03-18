# ok: HOOK-003
# Hook scripts have explicit timeout_ms configured
# .drako.yaml:
#   hooks:
#     pre_action:
#       - name: validate-schema
#         script: .drako/hooks/validate_schema.py
#         timeout_ms: 5000
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Execute validated actions")
