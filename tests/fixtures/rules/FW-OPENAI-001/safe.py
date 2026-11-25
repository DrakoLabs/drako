"""Safe: OpenAI Agent wrapped with Drako v4 adapter."""
from agents import Agent
from drako import build_host
from drako.adapters.openai_agents import wrap_openai_agent


def no_secrets(text: str) -> bool:
    return "secret" in text.lower()


agent = Agent(
    name="Support",
    instructions="You are customer support.",
    input_guardrails=[no_secrets],
)

host = build_host(allow=["lookup_*"])
governed = wrap_openai_agent(agent, host)
