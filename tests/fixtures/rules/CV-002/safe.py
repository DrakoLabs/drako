# ok: CV-002
# Audit logging with local Ed25519 receipt binding:
#   version: "4.0"
#   kernel:
#     spec_pin: AGENT-HOOKS-0.1
#   audit:
#     enabled: true
#     cryptographic: true
#     receipt_store: .drako/receipts.jsonl
from crewai import Agent

agent = Agent(name="assistant", role="Helper")
agent.run(task="Run audited workflow with cryptographic receipt binding")
