# ok: CV-001
# Local-first v4 .drako.yaml pinned to AGENT-HOOKS-0.1:
#   version: "4.0"
#   kernel:
#     spec_pin: AGENT-HOOKS-0.1
#     default_effect: deny
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Process requests with versioned governance")
