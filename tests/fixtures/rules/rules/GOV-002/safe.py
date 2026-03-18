# ok: GOV-002
# Policy enforcement middleware configured
from drako import GovernanceMiddleware

middleware = GovernanceMiddleware(api_key="key")
result = middleware.evaluate_policy(action="read_file", agent="worker")
