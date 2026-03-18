# Drako Policy Rules Reference

Drako enforces **60 deterministic rules** across 13 categories. Every rule runs offline, with no LLM in the evaluation loop. Same code, same result, every time.

## Scoring

| Severity | Points per finding | Category cap |
|----------|-------------------|--------------|
| CRITICAL | -15 | -60 |
| HIGH | -8 | -40 |
| MEDIUM | -3 | -20 |
| LOW | -1 | -10 |

**Score range:** 0-100. **Grades:** A (90-100), B (75-89), C (60-74), D (40-59), F (0-39).

Category caps prevent one domain from dominating the score.

---

## Table of Contents

- [Security (SEC-001 to SEC-011)](#security)
- [Governance (GOV-001 to GOV-011)](#governance)
- [Compliance (COM-001 to COM-006)](#compliance)
- [Operational Boundaries (ODD-001 to ODD-004)](#operational-boundaries)
- [Magnitude (MAG-001 to MAG-003)](#magnitude)
- [Identity (ID-001 to ID-003)](#identity)
- [Multi-Agent (MULTI-001 to MULTI-004)](#multi-agent)
- [Hooks (HOOK-001 to HOOK-003)](#hooks)
- [Context Versioning (CV-001 to CV-002)](#context-versioning)
- [FinOps (FIN-001 to FIN-003)](#finops)
- [Resilience (RES-001 to RES-002)](#resilience)
- [Agent-to-Agent (A2A-001 to A2A-003)](#agent-to-agent)
- [Best Practices (BP-001 to BP-005)](#best-practices)

---

## Security

### SEC-001: API key hardcoded in source code

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-798, OWASP Top 10 for LLM #6

API keys or secrets embedded directly in source code. If the repo is public or shared, credentials are exposed. If compromised, an attacker inherits all permissions the key grants — including the agent's ability to call tools, spend money, and access data.

**Vulnerable:**
```python
# ruleid: SEC-001
client = OpenAI(api_key="sk-proj-abc123def456")
```

**Correct:**
```python
# ok: SEC-001
import os
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
```

---

### SEC-002: Secrets in prompts or configuration

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-798, OWASP Top 10 for LLM #6

Secrets referenced inside prompt templates or system messages. Prompt content is often logged, cached, or visible in traces. A secret in a prompt is a secret in your logs.

**Vulnerable:**
```python
# ruleid: SEC-002
system_prompt = "Use api_key sk-proj-abc123 to authenticate requests"
```

**Correct:**
```python
# ok: SEC-002
system_prompt = "Authenticate using the credentials provided at runtime"
# Inject secrets via runtime environment, never in prompt text
```

---

### SEC-003: Unrestricted filesystem access in tool

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-22 (Path Traversal), OWASP Top 10 for LLM #1

A tool that reads or writes files without path validation. An agent with unrestricted filesystem access can read sensitive files (`.env`, SSH keys), overwrite configuration, or traverse to parent directories.

**Vulnerable:**
```python
# ruleid: SEC-003
@tool
def read_file(path: str) -> str:
    return open(path).read()
```

**Correct:**
```python
# ok: SEC-003
ALLOWED_DIR = Path("/data/workspace")

@tool
def read_file(path: str) -> str:
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(ALLOWED_DIR):
        raise ValueError("Access denied: path outside allowed directory")
    return resolved.read_text()
```

---

### SEC-004: Unrestricted network access in tool

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-918 (SSRF), OWASP Top 10 for LLM #1

A tool that makes HTTP requests without a domain allowlist. An agent can be manipulated to exfiltrate data to attacker-controlled servers, or access internal services via SSRF.

**Vulnerable:**
```python
# ruleid: SEC-004
@tool
def fetch_url(url: str) -> str:
    return requests.get(url).text
```

**Correct:**
```python
# ok: SEC-004
ALLOWED_DOMAINS = {"api.example.com", "docs.example.com"}

@tool
def fetch_url(url: str) -> str:
    domain = urlparse(url).hostname
    if domain not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain {domain} not in allowlist")
    return requests.get(url).text
```

---

### SEC-005: Arbitrary code execution in tool

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-94 (Code Injection), OWASP Top 10 for LLM #2

`exec()`, `eval()`, `os.system()`, or `subprocess` calls with untrusted input. If an agent can execute arbitrary code, a prompt injection becomes remote code execution.

**Vulnerable:**
```python
# ruleid: SEC-005
@tool
def run_code(code: str) -> str:
    result = {}
    exec(code, result)
    return str(result.get("output"))
```

**Correct:**
```python
# ok: SEC-005
import ast

@tool
def evaluate_expression(expr: str) -> str:
    # Only allow literal expressions — no function calls
    return str(ast.literal_eval(expr))
```

---

### SEC-006: No input validation on tool parameters

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** CWE-20 (Improper Input Validation), NIST AI RMF GV-1.3

Tool functions without type annotations or validation. Agents pass arbitrary strings to tools — without validation, malformed input propagates through the system unchecked.

**Vulnerable:**
```python
# ruleid: SEC-006
@tool
def search_records(query, limit):
    return db.search(query=query, limit=limit)
```

**Correct:**
```python
# ok: SEC-006
@tool
def search_records(query: str, limit: int = 10) -> list[dict]:
    if not query or len(query) > 500:
        raise ValueError("Query must be 1-500 characters")
    if not 1 <= limit <= 100:
        raise ValueError("Limit must be between 1 and 100")
    return db.search(query=query, limit=limit)
```

---

### SEC-007: Prompt injection vulnerability

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-74 (Injection), OWASP Top 10 for LLM #1

User input interpolated directly into prompts via f-strings or `.format()`. An attacker can override system instructions by injecting directives into the user-controlled portion of the prompt.

**Vulnerable:**
```python
# ruleid: SEC-007
prompt = f"Summarize this document: {user_input}"
```

**Correct:**
```python
# ok: SEC-007
messages = [
    {"role": "system", "content": "Summarize the document provided by the user."},
    {"role": "user", "content": user_input},
]
```

---

### SEC-008: No input sanitization on tool results

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-79 (XSS analog), OWASP Top 10 for LLM #2

Tools that fetch external data (HTTP, files, databases) without sanitizing the response before returning it to the agent. External data can contain prompt injection payloads that hijack agent behavior.

**Vulnerable:**
```python
# ruleid: SEC-008
@tool
def web_search(query: str) -> str:
    return requests.get(f"https://api.search.com/?q={query}").text
```

**Correct:**
```python
# ok: SEC-008
@tool
def web_search(query: str) -> str:
    raw = requests.get(f"https://api.search.com/?q={query}").text
    return sanitize(raw, max_length=5000, strip_instructions=True)
```

---

### SEC-009: Agent processes untrusted external data

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-74 (Injection), OWASP Top 10 for LLM #1

Tool output (from web searches, API calls, file reads) concatenated into prompt variables. External data flowing unsanitized into prompts is the primary vector for indirect prompt injection.

**Vulnerable:**
```python
# ruleid: SEC-009
result = web_search_tool(query)
prompt = f"Based on this research: {result}\nNow answer the question."
```

**Correct:**
```python
# ok: SEC-009
result = web_search_tool(query)
messages = [
    {"role": "system", "content": "Answer based on the tool results provided."},
    {"role": "tool", "content": result},
    {"role": "user", "content": question},
]
```

---

### SEC-010: No prompt injection defense configured

**Severity:** HIGH (-8 points, cap -40)
**Standard:** OWASP Top 10 for LLM #1, NIST AI RMF MG-2.6

No prompt injection detection library, middleware, or guardrail configured in the project. Without defense, injected instructions in tool results or user input pass through unchecked.

**Vulnerable:**
```python
# ruleid: SEC-010
# No guardrails, no drako, no injection detection
crew = Crew(agents=[researcher], tasks=[task])
crew.kickoff()
```

**Correct:**
```python
# ok: SEC-010
from drako import govern
crew = govern(Crew(agents=[researcher], tasks=[task]))
crew.kickoff()
```

---

### SEC-011: No intent verification on high-impact actions

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-352 (CSRF analog), NIST AI RMF GV-1.1

High-impact tools (payments, deletions, deployments) without cryptographic intent verification. An attacker who compromises the message pipeline can forge tool call requests.

**Vulnerable:**
```python
# ruleid: SEC-011
@tool
def transfer_funds(amount: float, to_account: str) -> str:
    return bank_api.transfer(amount=amount, to=to_account)
```

**Correct:**
```python
# ok: SEC-011
# Configure in .drako.yaml:
# intent_verification:
#   mode: enforce
#   required_for:
#     tool_types: [payment, write, execute]
#   anti_replay: true
```

---

## Governance

### GOV-001: No audit logging configured

**Severity:** HIGH (-8 points, cap -40)
**Standard:** EU AI Act Art. 12, NIST AI RMF GV-4.1

No audit trail for agent actions. Without logging, you cannot reconstruct what happened during an incident, demonstrate compliance, or detect anomalous behavior.

**Vulnerable:**
```python
# ruleid: GOV-001
crew = Crew(agents=[agent], tasks=[task])
crew.kickoff()
```

**Correct:**
```python
# ok: GOV-001
from drako import govern
crew = govern(Crew(agents=[agent], tasks=[task]))
# Every tool call is now logged with SHA-256 hash chain
```

---

### GOV-002: No policy enforcement middleware

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF GV-1.1, Drako best practice

No governance middleware evaluating tool calls against policies. Without policy checks, agents operate without guardrails — any tool call passes unchecked.

**Vulnerable:**
```python
# ruleid: GOV-002
crew = Crew(agents=[agent], tasks=[task])
crew.kickoff()
```

**Correct:**
```python
# ok: GOV-002
from drako import govern
crew = govern(Crew(agents=[agent], tasks=[task]))
```

---

### GOV-003: No rate limiting on tool calls

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** CWE-770 (Resource Exhaustion), NIST AI RMF MS-2.7

No rate limiting on tool invocations. A runaway agent can make thousands of API calls per minute, exhaust quotas, and incur unbounded costs.

**Vulnerable:**
```python
# ruleid: GOV-003
@tool
def search(query: str) -> str:
    return api.search(query)  # No rate limit — can be called unlimited times
```

**Correct:**
```python
# ok: GOV-003
from functools import wraps
import time

def rate_limit(max_calls=10, period=60):
    calls = []
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            now = time.time()
            calls[:] = [c for c in calls if now - c < period]
            if len(calls) >= max_calls:
                raise RuntimeError("Rate limit exceeded")
            calls.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
```

---

### GOV-004: No human-in-the-loop for destructive actions

**Severity:** HIGH (-8 points, cap -40)
**Standard:** EU AI Act Art. 14, NIST AI RMF GV-1.5

Tools with filesystem access or code execution capability without human approval gates. Destructive actions (delete, overwrite, execute) should require human confirmation.

**Vulnerable:**
```python
# ruleid: GOV-004
@tool
def delete_files(pattern: str) -> str:
    for f in Path(".").glob(pattern):
        f.unlink()
    return "Done"
```

**Correct:**
```python
# ok: GOV-004
# Configure HITL in .drako.yaml:
# hitl:
#   mode: enforce
#   triggers:
#     tool_types: [write, execute]
```

---

### GOV-005: No circuit breaker configured

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF MS-2.7, Drako best practice

No circuit breaker to stop cascading failures. If a tool or downstream service fails repeatedly, the agent keeps retrying — amplifying the failure instead of containing it.

**Vulnerable:**
```python
# ruleid: GOV-005
# No circuit breaker — agent retries failed calls indefinitely
result = tool.run(args)
```

**Correct:**
```python
# ok: GOV-005
import pybreaker
breaker = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=30)

@breaker
def call_tool(args):
    return tool.run(args)
```

---

### GOV-006: Agent can modify its own system prompt

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-284 (Access Control), OWASP Top 10 for LLM #8

Agent modifies `self.system_prompt`, `self.prompt`, or `self.instructions` outside of `__init__`. If an agent can rewrite its own instructions at runtime, a prompt injection can permanently alter its behavior.

**Vulnerable:**
```python
# ruleid: GOV-006
class MyAgent(Agent):
    def process(self, input):
        self.system_prompt = f"New instructions: {input}"
        return self.run()
```

**Correct:**
```python
# ok: GOV-006
class MyAgent(Agent):
    def __init__(self):
        self.system_prompt = "Fixed instructions that cannot change"

    @property
    def prompt(self):
        return self.system_prompt  # Read-only access
```

---

### GOV-007: No per-tool failure handling

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** CWE-755 (Improper Error Handling), NIST AI RMF MS-2.5

Tools making external calls (HTTP, file I/O, database) without try/except. Unhandled exceptions from external services crash the agent instead of degrading gracefully.

**Vulnerable:**
```python
# ruleid: GOV-007
@tool
def fetch_data(url: str) -> str:
    return requests.get(url).json()  # No error handling
```

**Correct:**
```python
# ok: GOV-007
@tool
def fetch_data(url: str) -> str:
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except (requests.ConnectionError, requests.Timeout) as e:
        return f"Service unavailable: {e}"
```

---

### GOV-008: No fallback for critical tool

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF MS-2.5, Drako best practice

Critical tools (write, delete, send, pay, execute, deploy) without retry or fallback logic. If a critical tool fails, the agent has no recovery path.

**Vulnerable:**
```python
# ruleid: GOV-008
@tool
def send_payment(amount: float, to: str) -> str:
    return payment_api.send(amount=amount, to=to)
```

**Correct:**
```python
# ok: GOV-008
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential())
@tool
def send_payment(amount: float, to: str) -> str:
    return payment_api.send(amount=amount, to=to)
```

---

### GOV-009: Agent can execute destructive actions autonomously

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** EU AI Act Art. 14, CWE-284

Critical tools (delete, write, execute, pay, deploy) without HITL checkpoints. The EU AI Act Art. 14 requires human oversight for high-risk AI systems. Autonomous destructive actions violate this requirement.

**Vulnerable:**
```python
# ruleid: GOV-009
@tool
def delete_database(table: str) -> str:
    return db.execute(f"DROP TABLE {table}")
```

**Correct:**
```python
# ok: GOV-009
# Configure HITL in .drako.yaml:
# hitl:
#   mode: enforce
#   triggers:
#     tool_types: [write, execute, payment]
#     tools: [delete_database, drop_table]
#   approval_timeout_minutes: 30
#   timeout_action: reject
```

---

### GOV-010: No escalation path defined

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF GV-1.5, Drako best practice

No escalation mechanism for when agents encounter situations beyond their capability. Without escalation, agents either fail silently or make unsafe decisions.

**Vulnerable:**
```python
# ruleid: GOV-010
# No escalation, no supervisor, no notification webhook
crew = Crew(agents=[agent], tasks=[task])
```

**Correct:**
```python
# ok: GOV-010
# Configure escalation in .drako.yaml:
# hitl:
#   mode: enforce
#   notification:
#     webhook_url: https://hooks.slack.com/your-channel
#     email: ops@company.com
#   approval_timeout_minutes: 30
#   timeout_action: reject
```

---

### GOV-011: Action replay vulnerability

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-294 (Authentication Bypass by Replay), NIST AI RMF GV-1.3

Critical tools without replay protection. Without nonces or idempotency keys, an intercepted tool call can be replayed to duplicate payments, deletions, or other destructive actions.

**Vulnerable:**
```python
# ruleid: GOV-011
@tool
def transfer_funds(amount: float, to: str) -> str:
    return bank.transfer(amount, to)  # Can be replayed
```

**Correct:**
```python
# ok: GOV-011
# Configure in .drako.yaml:
# intent_verification:
#   mode: enforce
#   anti_replay: true
#   intent_ttl_seconds: 300
```

---

## Compliance

### COM-001: No automatic logging (EU AI Act Art. 12)

**Severity:** HIGH (-8 points, cap -40)
**Standard:** EU AI Act Art. 12

Article 12 of the EU AI Act requires automatic recording-keeping for high-risk AI systems. Without logging, you cannot demonstrate compliance or reconstruct agent decisions during an audit.

**Vulnerable:**
```python
# ruleid: COM-001
crew = Crew(agents=[agent], tasks=[task])
crew.kickoff()  # No logging
```

**Correct:**
```python
# ok: COM-001
from drako import govern
crew = govern(Crew(agents=[agent], tasks=[task]))
# Automatic audit logging with hash-chained records
```

---

### COM-002: No human oversight mechanism (EU AI Act Art. 14)

**Severity:** HIGH (-8 points, cap -40)
**Standard:** EU AI Act Art. 14

Article 14 mandates human oversight for high-risk AI operations. No mechanism exists to pause, override, or review agent decisions before execution.

**Vulnerable:**
```python
# ruleid: COM-002
# No HITL, no approval gate, no human review
agent.run(task)
```

**Correct:**
```python
# ok: COM-002
# Configure HITL in .drako.yaml:
# hitl:
#   mode: enforce
#   triggers:
#     tool_types: [write, execute, payment]
```

---

### COM-003: No technical documentation (EU AI Act Art. 11)

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** EU AI Act Art. 11

Article 11 requires technical documentation for high-risk AI systems. No `docs/` directory, `ARCHITECTURE.md`, or meaningful README describing the agent system.

**Vulnerable:**
```
# ruleid: COM-003
# Project has no docs/ directory and no README with agent documentation
```

**Correct:**
```
# ok: COM-003
docs/
  architecture.md
  agents.md
  risk-assessment.md
README.md  # Contains agent descriptions, tools, and governance policies
```

---

### COM-004: No risk management documentation (EU AI Act Art. 9)

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** EU AI Act Art. 9

Article 9 requires a risk management system. No `RISK_ASSESSMENT.md` or risk management documentation exists for the agent system.

**Vulnerable:**
```
# ruleid: COM-004
# No risk assessment file anywhere in the project
```

**Correct:**
```markdown
# ok: COM-004
# Create RISK_ASSESSMENT.md with:
# - Risk inventory (tool access, data handling, cost exposure)
# - Mitigation strategies per risk
# - Residual risk acceptance criteria
```

---

### COM-005: No Agent BOM / inventory maintained

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** EU AI Act Art. 11, Drako best practice

No `.drako.yaml` or Agent Bill of Materials documenting agents, tools, models, and permissions. Without an inventory, governance is ad-hoc.

**Vulnerable:**
```
# ruleid: COM-005
# No .drako.yaml, no agent-bom.json
```

**Correct:**
```bash
# ok: COM-005
drako init  # Generates .drako.yaml with full BOM
```

---

### COM-006: No HITL checkpoint for high-risk actions

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** EU AI Act Art. 14

Tools with side effects (delete, write, send, pay, execute, deploy) exist but no HITL configuration in `.drako.yaml`. Article 14 violation for high-risk AI systems.

**Vulnerable:**
```python
# ruleid: COM-006
# .drako.yaml has no hitl: section
# But project has tools: send_email, delete_record, execute_query
```

**Correct:**
```yaml
# ok: COM-006
# .drako.yaml
hitl:
  mode: enforce
  triggers:
    tool_types: [write, execute, payment]
  approval_timeout_minutes: 30
  timeout_action: reject
```

---

## Operational Boundaries

### ODD-001: No operational boundary definition

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** NIST AI RMF GV-1.1, Drako best practice

No Operational Design Domain (ODD) defined. Agents operate without defined boundaries for where, when, and how they can act. ODD enforcement requires the Drako platform.

**Vulnerable:**
```python
# ruleid: ODD-001
# No ODD defined — agent can do anything, anywhere, anytime
agent = Agent(role="researcher", tools=[search, write, delete])
```

**Correct:**
```yaml
# ok: ODD-001
# Define ODD via Drako dashboard (Pro plan)
# Restrict: permitted tools, time windows, allowed data sources
```

---

### ODD-002: Unrestricted tool access

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-269 (Improper Privilege Management), NIST AI RMF GV-1.3

Agents have access to tools without an explicit allowlist. Each agent should only access the tools it needs — principle of least privilege.

**Vulnerable:**
```python
# ruleid: ODD-002
agent = Agent(
    role="researcher",
    tools=[search, read_file, write_file, delete_file, execute_code, send_email]
)
```

**Correct:**
```python
# ok: ODD-002
agent = Agent(
    role="researcher",
    tools=[search, read_file]  # Only the tools this agent needs
)
# permitted_tools enforced via Drako ODD
```

---

### ODD-003: No spend cap

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF MS-2.7, Drako best practice

No token or cost limits defined. A runaway agent can consume unlimited API tokens, generating unbounded costs.

**Vulnerable:**
```python
# ruleid: ODD-003
# No max_tokens, no budget, no cost_limit anywhere
agent.run(task)
```

**Correct:**
```python
# ok: ODD-003
agent = Agent(
    role="researcher",
    max_tokens=10000,  # Per-call token limit
)
# Budget enforcement via Drako magnitude limits
```

---

### ODD-004: No time constraints

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** CWE-400 (Resource Exhaustion), NIST AI RMF MS-2.7

No timeout, max_iterations, or time_limit configured. An agent can run indefinitely, consuming resources and blocking other processes.

**Vulnerable:**
```python
# ruleid: ODD-004
# No timeout, no max_iterations, no step_limit
agent.run(task)  # Could run forever
```

**Correct:**
```python
# ok: ODD-004
agent = Agent(
    role="researcher",
    max_iterations=20,
)
# Or configure via Drako ODD time constraints
```

---

## Magnitude

### MAG-001: No spend cap defined

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** NIST AI RMF MS-2.7, Drako best practice

No financial magnitude limits defined. Without spend caps, a compromised or runaway agent can make unlimited API calls, each costing money. Financial exposure is unbounded.

**Vulnerable:**
```python
# ruleid: MAG-001
# No budget, max_tokens, or cost_limit in codebase
crew = Crew(agents=[agent1, agent2], tasks=tasks)
crew.kickoff()
```

**Correct:**
```yaml
# ok: MAG-001
# .drako.yaml
finops:
  budgets:
    daily_usd: 50
    monthly_usd: 500
    alert_at_percent: [50, 80, 95]
```

---

### MAG-002: No rate limit defined

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-770 (Resource Exhaustion), NIST AI RMF MS-2.7

No iteration or action rate limits. Agents can loop indefinitely or spam tool calls without any governor.

**Vulnerable:**
```python
# ruleid: MAG-002
# No max_iterations, max_steps, rate_limit
while not done:
    result = agent.step()
```

**Correct:**
```python
# ok: MAG-002
agent = Agent(
    role="researcher",
    max_iterations=50,
    max_steps=100,
)
```

---

### MAG-003: Sensitive data access without clearance

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-269 (Improper Privilege Management), NIST AI RMF GV-1.3

Agents have tools that access databases or sensitive data without data classification or access clearance configuration.

**Vulnerable:**
```python
# ruleid: MAG-003
@tool
def query_database(sql: str) -> str:
    return db.execute(sql)  # No access level, no sensitivity check
```

**Correct:**
```yaml
# ok: MAG-003
# Define data sensitivity in Drako magnitude config
# Restrict which agents can access which data classification levels
```

---

## Identity

### ID-001: Static credentials in agent code

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-798, OWASP Top 10 A07:2021

Hardcoded credential strings (API keys, tokens, passwords) assigned to variables. Static credentials cannot be rotated, revoked, or scoped per agent.

**Vulnerable:**
```python
# ruleid: ID-001
api_key = "sk-proj-a1b2c3d4e5f6g7h8"
auth_token = "ghp_abcdefghijklmnop"
```

**Correct:**
```python
# ok: ID-001
import os
api_key = os.environ["OPENAI_API_KEY"]
# Or use Drako Identity Management for auto-rotating credentials
```

---

### ID-002: No identity definition for agent

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF GV-1.3, Drako best practice

No identity configuration for agents. Without unique identity, you cannot distinguish which agent performed an action in audit trails or enforce per-agent policies.

**Vulnerable:**
```python
# ruleid: ID-002
# No identity, credentials, or auth configuration
agent = Agent(role="researcher", tools=[search])
```

**Correct:**
```yaml
# ok: ID-002
# Configure managed identities via Drako dashboard
# Each agent gets a unique DID with auto-rotating credentials
```

---

### ID-003: Shared credentials across agents

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-522 (Insufficiently Protected Credentials), NIST AI RMF GV-1.3

Same credential variable used in multiple files or by multiple agents. Shared credentials mean you cannot revoke access for a single agent without affecting all of them.

**Vulnerable:**
```python
# ruleid: ID-003
# file: agent_a.py
api_key = os.environ["SHARED_API_KEY"]

# file: agent_b.py
api_key = os.environ["SHARED_API_KEY"]  # Same credential!
```

**Correct:**
```python
# ok: ID-003
# file: agent_a.py
api_key = os.environ["AGENT_A_API_KEY"]

# file: agent_b.py
api_key = os.environ["AGENT_B_API_KEY"]
```

---

## Multi-Agent

### MULTI-001: Multi-agent system without topology monitoring

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF MS-2.3, Drako best practice

Multiple agents (2+) without topology monitoring. Without observability into agent interactions, you cannot detect cascading failures, circular dependencies, or resource conflicts.

**Vulnerable:**
```python
# ruleid: MULTI-001
# 3 agents, no topology monitoring
crew = Crew(agents=[researcher, writer, reviewer], tasks=tasks)
```

**Correct:**
```yaml
# ok: MULTI-001
# .drako.yaml
topology:
  enabled: true
  conflict_detection:
    resource_contention: true
    contradictory_actions: true
    cascade_amplification: true
```

---

### MULTI-002: Circular agent dependency detected

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-835 (Infinite Loop), NIST AI RMF MS-2.5

Circular delegation between agents detected via AST analysis. Agent A delegates to Agent B, which delegates back to Agent A — creating an infinite loop that exhausts resources.

**Vulnerable:**
```python
# ruleid: MULTI-002
# agent_a delegates to agent_b, which delegates back to agent_a
agent_a = Agent(role="planner", tools=[delegate_to_b])
agent_b = Agent(role="executor", tools=[delegate_to_a])
```

**Correct:**
```python
# ok: MULTI-002
# Unidirectional flow: planner -> executor (no back-delegation)
agent_a = Agent(role="planner", tools=[delegate_to_b])
agent_b = Agent(role="executor", tools=[search, write])
# Or set max_propagation_depth in a2a config
```

---

### MULTI-003: Shared resource without contention protection

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-362 (Race Condition), NIST AI RMF MS-2.5

Multiple agents use the same write/execute/payment tool without contention protection. Concurrent access to shared resources can cause data corruption, double-spending, or conflicting writes.

**Vulnerable:**
```python
# ruleid: MULTI-003
# Both agents can write to the same file simultaneously
agent_a = Agent(role="writer_a", tools=[write_file])
agent_b = Agent(role="writer_b", tools=[write_file])
```

**Correct:**
```yaml
# ok: MULTI-003
# .drako.yaml
topology:
  enabled: true
  conflict_detection:
    resource_contention: true
```

---

### MULTI-004: No chaos testing configured

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF MS-2.5, Drako best practice

No chaos testing or fault injection configured. Without testing how agents behave under failure conditions, you cannot validate resilience or discover cascading failure paths.

**Vulnerable:**
```
# ruleid: MULTI-004
# No chaos, fault_inject, or resilience_test configuration anywhere
```

**Correct:**
```yaml
# ok: MULTI-004
# .drako.yaml
chaos:
  experiments:
    - name: tool-deny-search
      target_tool: web_search
      fault_type: tool_deny
      duration_seconds: 60
  safety:
    max_blast_radius: 1
    auto_rollback_on_failure: true
    require_approval: true
```

---

## Hooks

### HOOK-001: No pre-action validation hooks

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF GV-1.3, Drako best practice

No pre-action hooks configured in `.drako.yaml`. Pre-action hooks allow custom validation before tool execution — business rules, compliance checks, or rate limiting logic specific to your domain.

**Vulnerable:**
```yaml
# ruleid: HOOK-001
# .drako.yaml — no hooks section or no pre_action
```

**Correct:**
```yaml
# ok: HOOK-001
# .drako.yaml
hooks:
  pre_action:
    - name: validate-business-rules
      condition: "tool_type == 'payment'"
      script: scripts/validate_payment.py
      timeout_ms: 5000
      action_on_fail: block
```

---

### HOOK-002: No session-end gate (Stop hook)

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF GV-4.1, Drako best practice

No `on_session_end` hook configured. Session-end gates ensure agents don't terminate without passing final checks (e.g., audit completeness, state persistence).

**Vulnerable:**
```yaml
# ruleid: HOOK-002
# .drako.yaml — no on_session_end hook
hooks:
  pre_action:
    - name: validate
```

**Correct:**
```yaml
# ok: HOOK-002
hooks:
  on_session_end:
    - name: final-audit-check
      script: scripts/session_audit.py
      timeout_ms: 10000
      action_on_fail: block
```

---

### HOOK-003: Hook without timeout configured

**Severity:** LOW (-1 point, cap -10)
**Standard:** CWE-400 (Resource Exhaustion), Drako best practice

Hook scripts defined without `timeout_ms`. A hanging hook script can block the entire enforcement pipeline indefinitely.

**Vulnerable:**
```yaml
# ruleid: HOOK-003
hooks:
  pre_action:
    - name: validate
      script: scripts/validate.py
      # No timeout_ms — can hang forever
```

**Correct:**
```yaml
# ok: HOOK-003
hooks:
  pre_action:
    - name: validate
      script: scripts/validate.py
      timeout_ms: 5000
```

---

## Context Versioning

### CV-001: No policy versioning configured

**Severity:** HIGH (-8 points, cap -40)
**Standard:** EU AI Act Art. 12, NIST AI RMF GV-4.1

No Drako platform connection for policy versioning. Without versioning, policy changes are untracked — you cannot audit which rules were active when an incident occurred.

**Vulnerable:**
```yaml
# ruleid: CV-001
# .drako.yaml without endpoint or api_key_env
tenant_id: my-org
# No platform connection — policies are local-only
```

**Correct:**
```yaml
# ok: CV-001
tenant_id: my-org
api_key_env: DRAKO_API_KEY
endpoint: https://api.useagentmesh.com
# Run: drako push — creates immutable policy snapshot
```

---

### CV-002: Audit logs without policy version reference

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** EU AI Act Art. 12, Drako best practice

Audit logging is configured but no platform connection exists. Audit entries cannot reference which policy version was active at the time of the action.

**Vulnerable:**
```yaml
# ruleid: CV-002
audit:
  enabled: true
# No api_key_env or endpoint — audit logs are orphaned from policy versions
```

**Correct:**
```yaml
# ok: CV-002
audit:
  enabled: true
api_key_env: DRAKO_API_KEY
endpoint: https://api.useagentmesh.com
```

---

## FinOps

### FIN-001: No cost tracking on LLM calls

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF MS-2.7, Drako best practice

LLM API calls detected but no cost tracking. Without tracking, you cannot report costs, detect anomalies, or enforce budgets.

**Vulnerable:**
```python
# ruleid: FIN-001
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o", messages=messages
)  # No token or cost tracking
```

**Correct:**
```yaml
# ok: FIN-001
# .drako.yaml
finops:
  tracking:
    enabled: true
    model_costs:
      gpt-4o:
        input: 0.0025
        output: 0.01
```

---

### FIN-002: Single model for all tasks (no cost optimization)

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF MS-2.7, Drako best practice

Only one LLM model referenced in the project. Using the same expensive model for simple tasks (summaries, formatting) wastes budget.

**Vulnerable:**
```python
# ruleid: FIN-002
# Every agent uses gpt-4o — even for simple tasks
agent1 = Agent(llm="gpt-4o")
agent2 = Agent(llm="gpt-4o")
agent3 = Agent(llm="gpt-4o")
```

**Correct:**
```python
# ok: FIN-002
agent1 = Agent(llm="gpt-4o")       # Complex reasoning
agent2 = Agent(llm="gpt-4o-mini")   # Simple formatting
agent3 = Agent(llm="gpt-4o-mini")   # Summarization
```

---

### FIN-003: No response caching configured

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF MS-2.7, Drako best practice

LLM calls detected but no caching. Identical or near-identical queries are sent to the LLM API repeatedly, wasting tokens and increasing latency.

**Vulnerable:**
```python
# ruleid: FIN-003
# No cache — same queries hit the API every time
response = client.chat.completions.create(model="gpt-4o", messages=messages)
```

**Correct:**
```yaml
# ok: FIN-003
# .drako.yaml
finops:
  cache:
    enabled: true
    similarity_threshold: 0.92
    ttl_hours: 24
```

---

## Resilience

### RES-001: No fallback defined for critical operations

**Severity:** HIGH (-8 points, cap -40)
**Standard:** NIST AI RMF MS-2.5, Drako best practice

Critical tools (payment, write, execute) without fallback configuration. When a critical tool fails, there is no recovery path — the agent is stuck.

**Vulnerable:**
```python
# ruleid: RES-001
@tool
def process_payment(amount: float) -> str:
    return payment_api.charge(amount)  # No fallback
```

**Correct:**
```yaml
# ok: RES-001
# .drako.yaml
fallback:
  mode: enforce
  tools:
    process_payment:
      fallback_action: escalate_human
      triggers: [circuit_breaker_open, timeout, error]
```

---

### RES-002: No state preservation on agent failure

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF MS-2.5, Drako best practice

No checkpointing or state persistence. If an agent crashes mid-task, all progress is lost and the task must restart from scratch.

**Vulnerable:**
```python
# ruleid: RES-002
# No checkpoint, save_state, or MemorySaver
agent.run(long_task)  # Crash = start over
```

**Correct:**
```python
# ok: RES-002
from langgraph.checkpoint.memory import MemorySaver
graph = StateGraph(State)
graph.compile(checkpointer=MemorySaver())
```

---

## Agent-to-Agent

### A2A-001: No agent-to-agent authentication configured

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-287 (Improper Authentication), NIST AI RMF GV-1.3

Multi-agent system (2+ agents) without mutual authentication. Without auth, any process can impersonate an agent and inject malicious messages into the communication flow.

**Vulnerable:**
```python
# ruleid: A2A-001
# 2+ agents, no authentication between them
crew = Crew(agents=[agent_a, agent_b], tasks=tasks)
```

**Correct:**
```yaml
# ok: A2A-001
# .drako.yaml
a2a:
  mode: enforce
  auth:
    method: did_exchange
    auto_rotate: true
```

---

### A2A-002: Agent accepts unvalidated input from other agents

**Severity:** CRITICAL (-15 points, cap -60)
**Standard:** CWE-74 (Injection), OWASP Top 10 for LLM #1

Inter-agent message passing without validation. Prompt worm attacks propagate through agent-to-agent channels — one compromised agent can inject instructions that spread to all connected agents.

**Vulnerable:**
```python
# ruleid: A2A-002
# Agent B blindly trusts input from Agent A
result_from_a = agent_a.delegate(task)
agent_b.process(result_from_a)  # No validation
```

**Correct:**
```yaml
# ok: A2A-002
# .drako.yaml
a2a:
  mode: enforce
  worm_detection:
    enabled: true
    scan_inter_agent_messages: true
    max_propagation_depth: 3
```

---

### A2A-003: No isolation between agent communication channels

**Severity:** HIGH (-8 points, cap -40)
**Standard:** CWE-653 (Compartmentalization), NIST AI RMF GV-1.3

Shared memory or message history between agents without channel isolation. Without isolation, one agent can read or modify another agent's messages, enabling privilege escalation.

**Vulnerable:**
```python
# ruleid: A2A-003
# All agents share the same message history
shared_memory = SharedMemory()
agent_a = Agent(memory=shared_memory)
agent_b = Agent(memory=shared_memory)
```

**Correct:**
```yaml
# ok: A2A-003
# .drako.yaml
a2a:
  mode: enforce
  channels:
    - from: agent_a
      to: agent_b
      allowed_message_types: [task_result, status_update]
      max_payload_size_kb: 500
```

---

## Best Practices

### BP-001: Framework outdated

**Severity:** LOW (-1 point, cap -10)
**Standard:** Drako best practice

AI agent framework is behind the latest major version. Outdated frameworks may have known vulnerabilities, missing features, or deprecated APIs.

**Vulnerable:**
```
# ruleid: BP-001
# requirements.txt
crewai==0.70.0  # Latest is 0.85+
```

**Correct:**
```
# ok: BP-001
# requirements.txt
crewai>=0.85.0
```

---

### BP-002: No tests for agents

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** NIST AI RMF MS-2.11, Drako best practice

No test files found, or tests exist but don't reference agent names. Untested agents are ungoverned agents — you cannot validate behavior, detect regressions, or prove compliance.

**Vulnerable:**
```
# ruleid: BP-002
# No test files anywhere in the project
```

**Correct:**
```python
# ok: BP-002
# tests/test_agents.py
def test_researcher_returns_results():
    result = researcher_agent.run("test query")
    assert result is not None

def test_writer_handles_empty_input():
    result = writer_agent.run("")
    assert "error" in result.lower() or result == ""
```

---

### BP-003: No retry/fallback in LLM calls

**Severity:** LOW (-1 point, cap -10)
**Standard:** Drako best practice

LLM models used but no retry or backoff logic. LLM APIs have transient failures (rate limits, timeouts). Without retry, a single transient error fails the entire task.

**Vulnerable:**
```python
# ruleid: BP-003
response = client.chat.completions.create(model="gpt-4o", messages=messages)
```

**Correct:**
```python
# ok: BP-003
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def call_llm(messages):
    return client.chat.completions.create(model="gpt-4o", messages=messages)
```

---

### BP-004: No timeout on tool executions

**Severity:** MEDIUM (-3 points, cap -20)
**Standard:** CWE-400 (Resource Exhaustion), Drako best practice

No timeout configured for tool calls. A hanging tool can block the agent indefinitely, consuming resources and preventing task completion.

**Vulnerable:**
```python
# ruleid: BP-004
@tool
def fetch_data(url: str) -> str:
    return requests.get(url).text  # No timeout — can hang forever
```

**Correct:**
```python
# ok: BP-004
@tool
def fetch_data(url: str) -> str:
    return requests.get(url, timeout=10).text
```

---

### BP-005: Too many tools on single agent

**Severity:** LOW (-1 point, cap -10)
**Standard:** Drako best practice

An agent has more than 10 tools registered. Too many tools increase the attack surface, make the agent harder to reason about, and lead to tool selection errors by the LLM.

**Vulnerable:**
```python
# ruleid: BP-005
agent = Agent(
    role="do-everything",
    tools=[search, read, write, delete, email, payment, deploy,
           database, api_call, scrape, translate, summarize]  # 12 tools!
)
```

**Correct:**
```python
# ok: BP-005
researcher = Agent(role="researcher", tools=[search, read])
writer = Agent(role="writer", tools=[write, summarize])
ops = Agent(role="ops", tools=[deploy, database])
```
