"""Vulnerable: MAF Agent with tools and no middleware."""
from agent_framework import Agent


async def get_weather(city: str) -> str:
    return f"sunny in {city}"


agent = Agent(
    name="helper",
    instructions="You are helpful.",
    tools=[get_weather],
)

# middleware=[] is theater, not governance: empty chain, still flags.
agent2 = Agent(
    name="helper2",
    instructions="You are helpful.",
    tools=[get_weather],
    middleware=[],
)
