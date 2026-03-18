# ruleid: CV-002
# Audit logging configured but without platform connection —
# audit entries will not reference the active policy version
# .drako.yaml:
#   audit:
#     enabled: true
#     log_level: verbose
#   (missing api_key_env / endpoint)
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Run audited workflow without version tracking")
