"""Vulnerable: OpenAI Agent with no input guardrails."""
from agents import Agent

agent = Agent(
    name="Support",
    instructions="You are customer support.",
)
