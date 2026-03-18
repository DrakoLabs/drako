# ok: CV-001
# .drako.yaml with platform connection for policy versioning
# .drako.yaml:
#   api_key_env: DRAKO_API_KEY
#   endpoint: https://api.useagentmesh.com
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Process requests with versioned governance")
