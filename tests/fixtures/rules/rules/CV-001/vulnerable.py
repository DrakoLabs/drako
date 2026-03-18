# ruleid: CV-001
# No .drako.yaml or platform connection — policy changes are not versioned
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Process requests without versioned governance")
