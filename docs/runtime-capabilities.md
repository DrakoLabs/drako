# Runtime Capabilities

Drako has two enforcement modes: **Scan CLI** (free, offline, no account) and **Runtime Platform** (requires a Drako account). This document covers the full capability set for both.

---

## Capability Overview

### Scan CLI — Free, Offline, No Account Required

| Capability | Status | Details |
|---|---|---|
| Governance Score | ✅ | 80 rules across 16 categories. Deterministic — same code, same result every time. |
| Determinism Score | ✅ | Separate score for non-deterministic patterns (temperature, seed, timeouts). |
| Agent BOM | ✅ | AST-based discovery of agents, tools, models, MCP servers, prompts. 7 frameworks. |
| Reachability Analysis | ✅ | Separates findings by whether the vulnerable code is actually reachable. |
| EU AI Act Gap Detection | ✅ | Art. 9, 11, 12, 14 compliance checks with fix snippets. |
| Advisory Matching | ✅ | Maps findings to 25 DRAKO-ABSS advisories (OWASP, MITRE ATLAS, real CVEs). |
| SARIF 2.1.0 Export | ✅ | GitHub Code Scanning compatible. Uploads to Security tab. |
| SVG Badge | ✅ | Embeddable governance score badge. |
| Benchmark Comparison | ✅ | `--benchmark` compares your score against 100 scanned open-source projects. |
| Baseline Mode | ✅ | `--baseline` saves known findings. CI only reports new ones. |
| Auto-fix Preview | ✅ | `drako fix --dry-run` previews what Drako can fix automatically. |

### Runtime Platform — Requires Account

| Capability | Status | Details |
|---|---|---|
| Policy Enforcement | ✅ Production | Real-time evaluation on every tool call before execution. |
| DLP / PII Detection | ✅ Production | Presidio-based scanning. 8+ entity types. Blocks or logs. |
| Human-in-the-Loop (HITL) | ✅ Production | Agent pauses, escalates to human. Configurable triggers. |
| Circuit Breaker | ✅ Production | Per-agent AND per-tool. State machine with EigenTrust scoring. |
| Audit Trail | ✅ Production | SHA-256/BLAKE3 hash chain + Ed25519 signatures. Tamper-evident. |
| Trust Score | ✅ Production | 0–100 dynamic score per agent, decays over time. |
| ODD Enforcement | ✅ Production | Blocks tool calls outside each agent's Operator-Defined Domain. |
| Magnitude Limits | ✅ Production | Caps spend and record access per action and per session. |
| Intent Fingerprinting | ✅ Production | Anti-replay tokens for high-risk tool calls. |
| Agentic FinOps | ✅ Production | Cost tracking, model routing, semantic caching, budget alerts. |
| Programmable Hooks | ✅ Production | Pre/post action scripts at governance checkpoints. |
| Deterministic Fallback | ✅ Production | Configurable fallback when tools fail or circuit breaks open. |
| Secure A2A | ✅ Production | DID-based authentication for inter-agent communication. |
| Topology Monitoring | ✅ Production | Detects circular deps, resource contention, cascade amplification. |
| Chaos Engineering | ✅ Production | Inject controlled faults to test fallback and recovery. |
| Observability | 🔜 Next Sprint | OTEL export with semantic conventions for agent telemetry. |
| SIEM Export | 🔜 Next Sprint | Audit trail export to Splunk, Datadog, Elastic. |
| Alerting | 🔜 Next Sprint | Webhook + email alerts for governance events. |

---

## Runtime Integration

### SDK — In-Process (Recommended)

Wraps your agent framework with a middleware that intercepts every tool call:

```python
from drako import govern

# One line — every tool call goes through governance
crew = govern(crew)
result = crew.kickoff()
```

Framework-specific helpers:

```python
from drako import with_compliance             # CrewAI
from drako import with_langgraph_compliance   # LangGraph
from drako import with_autogen_compliance     # AutoGen
```

### Proxy — Out-of-Process (Zero Code Changes)

Routes all LLM API calls through a local governance proxy:

```bash
drako proxy start
export OPENAI_BASE_URL=http://localhost:8990/openai/v1
```

See [Proxy Mode →](proxy-mode.md) for full proxy documentation.

| | SDK | Proxy |
|---|---|---|
| Code changes required | One line | None |
| HITL callbacks | Built-in | Manual implementation |
| Intent verification | ✅ | ❌ |
| Persistent audit trail | ✅ (cloud) | In-memory only |
| Multi-process support | Per-process | Shared across processes |
| Framework-specific rules | ✅ | ❌ |

---

## Capability Details

### Policy Enforcement

Every tool call passes through a 13-stage evaluation pipeline before executing:

1. Agent identity verification
2. ODD boundary check (permitted/forbidden tools)
3. Trust score evaluation
4. Magnitude limit check (spend, record count, rate)
5. DLP scan (inputs)
6. Intent verification (anti-replay)
7. HITL checkpoint (if triggered)
8. Hook execution (pre-action scripts)
9. Tool execution
10. DLP scan (outputs)
11. Cost tracking
12. Audit logging
13. Hook execution (post-action scripts)

If any enforcement-mode check fails, the tool call is blocked and logged. Audit-mode checks log without blocking.

---

### DLP / PII Detection

Presidio-based scanning detects PII and PCI data in tool inputs and outputs.

**Supported entity types:**
- SSN (Social Security Number)
- Credit card numbers (all major formats)
- Email addresses
- Phone numbers
- Passport numbers
- IP addresses
- Driver's license numbers
- Bank account numbers

**Configuration:**

```yaml
policies:
  dlp:
    mode: enforce       # audit | enforce | off
    sensitivity: high   # low | medium | high
```

`audit` — logs detections, allows the call
`enforce` — blocks the call before it reaches the tool

---

### Human-in-the-Loop (HITL)

When a tool call matches a HITL trigger, the agent execution pauses and waits for human approval.

**Trigger conditions:**
- Tool type (`write`, `execute`, `payment`, `network`)
- Specific tool name
- Trust score below threshold
- Session spend above threshold
- Records accessed above threshold
- First-time tool use
- First-time action in a new session

**Approval flow:**
1. Agent reaches a HITL trigger
2. Governance middleware pauses the agent
3. Notification sent (webhook/email if configured)
4. Human approves or rejects via the Drako dashboard or API
5. Agent resumes (approved) or receives a rejection error (rejected)

**Timeout behavior:**
- `timeout_action: reject` — defaults to blocking if no response (safe for production)
- `timeout_action: allow` — defaults to allowing if no response (permissive, for dev)

---

### Circuit Breaker

Per-agent fault isolation. Prevents one failing tool from cascading failures.

**States:** `CLOSED` → `OPEN` → `HALF-OPEN` → `CLOSED`

- **CLOSED:** Normal operation. Failures counted within the time window.
- **OPEN:** Failures exceeded threshold. All calls to this agent/tool are blocked immediately.
- **HALF-OPEN:** After recovery timeout. One trial call allowed to test recovery.

**EigenTrust scoring:** The circuit breaker uses trust propagation to detect systemic failures across multi-agent networks, not just isolated tool failures.

```yaml
policies:
  circuit_breaker:
    agent_level:
      failure_threshold: 5
      time_window_seconds: 60
      recovery_timeout_seconds: 30
```

---

### Audit Trail

Every tool call, policy decision, and governance event is logged to a tamper-evident hash chain.

**Standard audit:** Each entry is JSON with timestamp, agent ID, tool name, decision, and cost.

**Cryptographic audit (`cryptographic: true`):**
- SHA-256 (or BLAKE3 for higher performance) hash chain — each entry links to the previous
- Ed25519 digital signatures — entries are signed with a per-tenant key
- Policy snapshot reference — each audit entry references the `.drako.yaml` version that was active

Verify integrity at any time:

```bash
drako verify                    # Check hash chain integrity
drako verify --from 2026-01-01  # Verify a specific time range
```

---

### Trust Score

Dynamic 0–100 score per agent, updated on each tool call.

**Score decreases for:**
- Failed tool calls
- DLP violations (even in audit mode)
- Circuit breaker events
- HITL rejections
- ODD boundary violations

**Score recovers over time** via exponential decay (configurable half-life, default 168 hours).

**Use in HITL triggers:**
```yaml
policies:
  hitl:
    triggers:
      trust_score_below: 60   # Auto-escalate low-trust agents
```

---

### ODD Enforcement (Operator-Defined Domains)

Defines exactly which tools each agent is allowed to use. Blocks unexpected tool invocations.

```yaml
policies:
  odd:
    enforcement_mode: enforce
    default_policy: deny          # Block any unrecognized tool
    agents:
      researcher:
        permitted_tools: [web_search, file_reader]
        forbidden_tools: [code_runner]
```

`default_policy: deny` is the recommended production posture — agents can only use tools you've explicitly approved.

---

### Magnitude Limits

Hard limits on how much an agent can spend or access in a single call or session.

```yaml
policies:
  magnitude:
    max_spend_per_action_usd: 10.00
    max_spend_per_session_usd: 100.00
    max_records_per_action: 50
    enforcement_mode: enforce
```

Magnitude enforcement at the proxy level also tracks **actions per minute** per agent to prevent runaway loops.

---

### Intent Fingerprinting

Binds each high-risk tool call to a cryptographically signed intent token, preventing:
- **Prompt injection hijacking:** Attacker injects a prompt that causes the agent to reuse an approved intent for a different action
- **Replay attacks:** Previously approved intents cannot be reused

```yaml
policies:
  intent_verification:
    mode: enforce
    required_for:
      tool_types: [payment, write, execute]
    anti_replay: true
    intent_ttl_seconds: 300
```

---

### Agentic FinOps

Track, route, and budget LLM spend across your entire agent fleet.

**Cost tracking:** Per-agent, per-model cost breakdown from API response usage fields.

**Intelligent routing:** Route tasks to cheaper models based on configurable conditions:
```yaml
policies:
  finops:
    routing:
      enabled: true
      rules:
        - condition: "task_complexity == 'low'"
          model: gpt-4o-mini
          reason: "Use cheaper model for simple tasks"
```

**Semantic caching:** Cache and reuse responses for semantically similar requests (configurable similarity threshold).

**Budget alerts:** Alert at configurable spend percentages (50%, 80%, 95%) via webhook or email.

---

### Secure A2A

Authenticate and authorize inter-agent communication in multi-agent systems.

**Authentication methods:**
- `did_exchange` — DID-based credential exchange (recommended)
- `mtls` — Mutual TLS
- `shared_secret` — Pre-shared key (least secure)

**Worm detection:** Scans inter-agent messages for prompt injection patterns. Blocks messages that exceed a configurable propagation depth (prevents chain-of-thought injection from spreading).

---

### Topology Monitoring

Detects dangerous interaction patterns in multi-agent networks:

| Pattern | Description |
|---------|-------------|
| Circular dependency | Agent A → Agent B → Agent A (infinite loop risk) |
| Resource contention | Multiple agents competing for the same exclusive resource |
| Cascade amplification | One agent's output triggers exponentially more agent calls |
| Resource exhaustion | Agent network collectively consuming unbounded resources |

---

### Chaos Engineering

Deliberately inject failures to verify your fallback and recovery configurations work before they're needed in production.

**Fault types:**
- `tool_deny` — Block a specific tool entirely
- `latency` — Inject artificial latency
- `budget_exhaustion` — Simulate the remaining budget being nearly zero

**Safety guardrails:**
- `max_blast_radius` — Limits how many agents/tools are affected simultaneously
- `auto_rollback_on_failure` — Automatically rolls back if the system becomes unhealthy
- `require_approval` — Experiments require explicit approval before running

---

## Upgrade Path

Start in audit mode, upgrade when you've reviewed the logs:

```bash
drako init                      # Autopilot: everything in audit mode
drako upgrade --balanced        # DLP enforce, ODD enforce, HITL reject on timeout
drako upgrade --strict          # + Intent verification, cryptographic audit, magnitude enforce
```

Review what will change before upgrading:

```bash
drako upgrade --balanced --dry-run   # Preview policy changes without applying them
```
