# ok: SEC-010
# Prompt injection defense is configured AND USED via AST call — a bare import,
# a comment mentioning "guardrails", or a plain `input_validation = True`
# assignment does NOT silence this rule.
from crewai import Agent
from drako import guard

agent = Agent(
    name="assistant",
    system_prompt="You are a helpful assistant that answers questions.",
)

# Defense in use: the agent runs wrapped in Drako's local Authority Kernel.
safe_agent = guard(agent, allow=["search_*"])
