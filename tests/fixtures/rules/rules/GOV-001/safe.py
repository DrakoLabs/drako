# ok: GOV-001
# Audit logging is configured via GovernanceMiddleware
from drako import GovernanceMiddleware
from crewai import Agent

middleware = GovernanceMiddleware(api_key="key")
agent = Agent(
    name="worker",
    system_prompt="You are a helpful assistant that processes tasks.",
)
audit_log = middleware.get_audit_trail()
