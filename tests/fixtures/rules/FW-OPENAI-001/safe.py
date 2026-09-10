"""Safe: OpenAI Agent with a Drako input guardrail."""
from agents import Agent
from drako.middleware.openai_agents import make_drako_input_guardrail


def no_secrets(text: str) -> bool:
    return "secret" in text.lower()


agent = Agent(
    name="Support",
    instructions="You are customer support.",
    input_guardrails=[make_drako_input_guardrail(no_secrets)],
)
