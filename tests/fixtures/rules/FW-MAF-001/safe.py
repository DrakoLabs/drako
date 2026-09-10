"""Safe: MAF Agent with tools governed by Drako middleware."""
from agent_framework import Agent
from drako.middleware.maf import with_maf_compliance


async def get_weather(city: str) -> str:
    return f"sunny in {city}"


async def logging_middleware(context, call_next):
    await call_next()


agent = Agent(
    name="helper",
    instructions="You are helpful.",
    tools=[get_weather],
    middleware=[logging_middleware],
)

governed = with_maf_compliance(agent)
