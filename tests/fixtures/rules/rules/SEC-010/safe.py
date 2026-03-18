# ok: SEC-010
# Prompt injection defense is configured
from drako import with_compliance
from crewai import Agent

agent = Agent(
    name="assistant",
    system_prompt="You are a helpful assistant that answers questions.",
)
crew = with_compliance(agent)
