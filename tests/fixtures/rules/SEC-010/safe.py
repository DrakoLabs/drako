# ok: SEC-010
# Prompt injection defense is configured AND USED. U-5 (2026-09-04):
# suppression requires an actual defense CALL (AST) — a bare import,
# a comment mentioning "guardrails", or a plain `input_validation = True`
# assignment does NOT silence this rule (that was the substring bypass).
from crewai import Agent
from drako import with_compliance

agent = Agent(
    name="assistant",
    system_prompt="You are a helpful assistant that answers questions.",
)

# Defense in use: the agent runs wrapped in injection-detection middleware.
crew = with_compliance(agent, config_path=".drako.yaml")
