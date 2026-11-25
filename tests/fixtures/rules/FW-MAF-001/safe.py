"""Safe: MAF Agent with tools governed by Drako v4 adapter."""
from agent_framework import Agent
from drako import build_host
from drako.adapters.maf import wrap_maf_agent


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

host = build_host(allow=["get_weather"])
governed = wrap_maf_agent(agent, host)
