<h1 align="center">AgentMesh</h1>
<p align="center">
  The governance layer between your AI agents and everything they can touch.<br>
  <strong>Enforces policies on every action before it executes — deterministic, with no LLM in the loop.</strong>
</p>
<p align="center">
  <a href="https://pypi.org/project/useagentmesh/">
    <img src="https://img.shields.io/pypi/v/useagentmesh?style=flat-square&color=3776AB&logo=pypi&logoColor=white" alt="PyPI">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=yellow" alt="Python 3.10+">
  </a>
  <a href="https://github.com/angelnicolasc/agentmesh/actions">
    <img src="https://img.shields.io/badge/tests-1002%20passing-2ea44f.svg?style=flat-square&logo=github-actions&logoColor=white" alt="Tests">
  </a>
  <img src="https://img.shields.io/badge/rules-50%2B-6366F1.svg?style=flat-square" alt="Rules">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-BUSL--1.1-6366F1.svg?style=flat-square&logo=opensourceinitiative&logoColor=white" alt="License: BUSL-1.1">
  </a>
  <img src="https://img.shields.io/badge/policy%20eval-%3C2ms-6366F1.svg?style=flat-square" alt="Performance">
</p>

## What It Does

AI agents call tools, spend money, delete files, and make decisions — autonomously, at speed, without asking.

**AgentMesh** is the governance layer between your agent and everything it can touch. It scans your codebase to find governance gaps before production does. And it enforces policies on live agent traffic — blocking actions before they execute, not logging them after.

```bash
pip install useagentmesh && agentmesh scan .
```

The scan is free, offline, and needs no account. The runtime platform connects in one line and protects agents in production.

No LLM in the evaluation loop. Every rule is deterministic. Same code, same result, every time.

---

## Quick Start

```bash
pip install useagentmesh
agentmesh scan .
```

```
┌─ AgentMesh Scan ─────────────────────────────────────────┐
│ my-project  │  crewai 0.86.0  │  0.4s                    │
└──────────────────────────────────────────────────────────┘

  Agent BOM: 3 agents │ 12 tools │ 2 models │ 4 prompts

┌──────────────────────────────────────────────────────────┐
│ GOVERNANCE SCORE: 42/100 [D] ████████░░░░░░░░░░░░  42%  │
└──────────────────────────────────────────────────────────┘

  Risk Level: CRITICAL — API keys are exposed in source code.

  CRITICAL  3  │  HIGH  5  │  MEDIUM  4  │  LOW  2

  Top Issues
  • SEC-001  API key hardcoded in source code        (src/main.py)
  • SEC-005  Arbitrary code execution in tool         (tools/runner.py)
  • GOV-006  Agent can modify its own system prompt   (agents/writer.py)

👉 agentmesh scan --details    Full findings with code snippets
👉 agentmesh fix --dry-run     Preview auto-fixes
👉 agentmesh scan --share      Share your score on social media
```

```bash
agentmesh scan --format sarif       # SARIF 2.1.0 for GitHub Code Scanning
agentmesh scan --threshold 70       # Exit 1 if score < 70
agentmesh scan --fail-on critical   # Exit 1 on any critical finding
agentmesh scan --diff HEAD~1        # Only scan changed files
agentmesh scan --share              # Generate pre-written social posts with your score
```

---

## Configure Everything From One File

AgentMesh generates `.agentmesh.yaml` pre-populated with your real agents and tools. Edit it, push it, enforce it.

```bash
agentmesh scan .      # detects agents, tools, models
agentmesh init        # generates .agentmesh.yaml with your real tools
agentmesh push        # syncs policies to the enforcement engine
```

```yaml
# .agentmesh.yaml — generated with YOUR tools pre-filled
agents:
  researcher:
    source: agents/researcher.py
  writer:
    source: agents/writer.py

tools:
  web_search:
    source: tools/search.py
    type: read
  code_runner:
    source: tools/runner.py
    type: execute    # ⚠ flagged CRITICAL by scan

policies:
  odd:
    researcher:
      permitted_tools: [web_search, file_reader]
      forbidden_tools: [code_runner, db_write]
      max_actions_per_minute: 30
      max_cost_per_session_usd: 5.00

  magnitude:
    max_spend_per_action_usd: 10.00
    max_tokens_per_call: 4000

  dlp:
    mode: enforce

  circuit_breaker:
    agent_level:
      failure_threshold: 5
    per_tool:
      code_runner:
        failure_threshold: 3
        fallback: skip

  hitl:
    triggers:
      tool_types: [write, execute, payment]
      trust_score_below: 60
      spend_above_usd: 100.00
    notification:
      webhook_url: "https://hooks.slack.com/services/xxx"

  intent_verification:
    required_for:
      tool_types: [payment, write]
    anti_replay: true

  hooks:
    pre_action:
      - name: block-dangerous-sql
        condition: "tool_name == 'execute_sql' and 'DROP' in tool_args"
        action: deny

  finops:
    routing:
      rules:
        - condition: "estimated_tokens < 500"
          model: gpt-5-mini
    cache:
      enabled: true
    budgets:
      daily_usd: 50.00

  fallback:
    tools:
      transfer_funds:
        fallback_action: escalate_human
        triggers: [circuit_breaker_open, trust_below: 30]

  intel:
    enabled: true
    contribute: true
    block_severity: 7

  alerts:
    rules:
      - name: injection-spike
        condition: "injection_events_1h > 10"
        severity: critical
        channel: slack
```

Then one line in your code:

```python
from agentmesh import govern
crew = govern(crew)    # every tool call passes through enforcement
```

Every tool call is evaluated before executing. If a tool is forbidden, carries PII, exceeds spend caps, matches a known threat pattern, or requires human approval — blocked before it runs.

---

## What the Scan Detects

50+ deterministic rules across 11 categories.

| Category | Rules | What it catches |
|----------|-------|-----------------|
| **Security** | SEC-001 → SEC-011 | Hardcoded keys, secrets in prompts, arbitrary code execution, prompt injection vulnerability, unrestricted filesystem/network access, no input sanitization, unvalidated external data |
| **Governance** | GOV-001 → GOV-011 | No audit logging, no human-in-the-loop, self-modifying prompts, no per-tool error handling, no fallback for critical tools, destructive autonomous actions, action replay vulnerability |
| **Compliance** | COM-001 → COM-005 | EU AI Act Art. 12 logging, Art. 14 human oversight, Art. 9 risk management, Art. 11 documentation, no HITL for high-risk actions |
| **Operational Boundaries** | ODD-001 → ODD-004 | No boundary definition, unrestricted tool access, no spend cap, no time constraints |
| **Magnitude** | MAG-001 → MAG-003 | No spend cap, no rate limit, sensitive data without clearance |
| **Identity** | ID-001 → ID-003 | Static credentials, no identity definition, shared credentials |
| **Multi-Agent** | MULTI-001 → MULTI-004 | No topology monitoring, circular dependency, no conflict protection, no chaos testing |
| **Hooks** | HOOK-001 → HOOK-003 | No pre-action validation, no session-end gate, no hook timeout |
| **Versioning** | CV-001 → CV-002 | No policy versioning, audit logs without policy reference |
| **FinOps** | FIN-001 → FIN-003 | No cost tracking, single model for all tasks, no caching |
| **Resilience** | RES-001 → RES-002 | No fallback for critical ops, no state preservation |
| **CI/CD** | CI-001 | No governance gate in CI pipeline |

```
Scoring: Start at 100, deduct per finding (capped per category).
  CRITICAL: -15 (cap -60) │ HIGH: -8 (cap -40) │ MEDIUM: -3 (cap -20) │ LOW: -1 (cap -10)
  Grades: A (90-100) │ B (75-89) │ C (60-74) │ D (40-59) │ F (0-39)
```

---

## Agent BOM (Bill of Materials)

Walks your Python AST to inventory every component. No config files, no runtime agent, no network calls.

```
Agents     3 (researcher, writer, reviewer)
Tools      12 (web_search, file_reader, code_runner, ...)
Models     2 (gpt-5, claude-4.6-sonnet)
MCP        1 server
Prompts    4 system prompts detected
Perms      filesystem, network, code_execution
Framework  crewai 0.86.0
```

---

## Runtime Platform

The scan tells you what's wrong. The platform fixes it and keeps it fixed.

### Enforcement Pipeline

Every tool call passes through this chain. Each step can block, modify, or escalate:

```
Agent decides to act
  │
  ├─ Pre-action Hooks ─── custom validation scripts
  ├─ Identity Check ───── is this agent who it claims to be?
  ├─ ODD Check ────────── is this tool permitted for this agent?
  ├─ Magnitude Check ──── does this exceed spend/volume/scope limits?
  ├─ HITL Check ───────── does this need human approval?
  ├─ Intent Gate 1 ────── fingerprint the decision (SHA-256 + Ed25519)
  ├─ DLP Scan ─────────── does the payload contain PII/PCI?
  ├─ Injection Scan ───── does the input contain prompt injection?
  ├─ Trust Check ──────── is this agent's reputation sufficient?
  ├─ IOC Check ────────── does this match a known threat pattern?
  ├─ Circuit Breaker ──── is this tool/agent healthy enough?
  ├─ Intent Gate 2 ────── verify decision wasn't altered since Gate 1
  │
  ▼
  Execute (or block with reason)
  │
  ├─ Post-action Hooks ── validate/modify result
  ├─ Topology Tracker ─── log interaction for multi-agent graph
  ├─ Cost Tracker ─────── record tokens, cost, model used
  └─ Audit Trail ──────── SHA-256 hash chain + policy snapshot ID
```

### Capabilities

| Capability | What it does |
|---|---|
| **DLP** | Presidio-based PII/PCI detection on every tool call payload. CRITICAL PII → action rejected before it reaches downstream APIs. |
| **Prompt Injection Detection** | Bidirectional: scans inputs reaching the agent for injection attempts in external data (documents, API responses, tool results). 5 pattern categories, deterministic, no LLM. Complements DLP which scans outputs. |
| **Trust Score** | Per-agent EigenTrust reputation (0–100), updated on every interaction, time-decayed. Agents earn or lose trust based on behavior. |
| **Circuit Breaker** | Per-agent AND per-tool. If one tool fails repeatedly, that tool auto-suspends — the agent continues with everything else. Hierarchy: tool CB → agent CB → fleet halt. |
| **ODD Enforcement** | Operational Design Domain: declare which tools, APIs, data sources, and time windows each agent can operate in. Allowlisting, not denylisting. Modes: audit, enforce, escalate. |
| **Magnitude Limits** | Pre-action: spend caps per action/session/day, data volume limits, blast radius constraints, compute guardrails. Blocks before execution. |
| **Human-in-the-Loop** | Agent pauses on high-risk actions and escalates to a human supervisor. Configurable triggers: tool type, trust threshold, spend amount, first-time actions. Webhook notifications (Slack, Teams, email). EU AI Act Art. 14 compliance. |
| **Intent Fingerprinting** | Two-gate cryptographic verification (SHA-256 + Ed25519). Gate 1 fingerprints the decision. Gate 2 verifies it wasn't altered before execution. If an hallucination or injection changes the action between decision and execution — blocked. SOC 2 audit proof. |
| **Agent Identity** | Managed credential lifecycle per agent: dynamic provisioning, automatic rotation with grace periods, instant revocation. DID-based. No more shared static API keys across agents. |
| **Programmable Hooks** | Python scripts or YAML conditions that run at pre_action, post_action, on_error, on_session_end. Stop hooks can block session completion until checks pass. |
| **Context Versioning** | Every config push creates an immutable SHA-256 snapshot. Audit logs reference the exact policy version active at the time. Diff, rollback, full change history. |
| **FinOps** | Cost-per-outcome tracking, smart model routing (route simple tasks to cheaper models), semantic caching (skip LLM calls for repeated queries), budget alerts at 50/80/95%. Dashboard shows: "AgentMesh saved you $X this month." |
| **Deterministic Fallback** | When CB trips, operations don't die — they failover to deterministic code, a simpler agent, a human operator, or a retry queue. State is preserved. Business continuity, not just error handling. |
| **Secure A2A** | Agent-to-agent communication routed through a governance gateway. Mutual authentication (DID exchange), channel policies (who talks to whom), prompt worm prevention (injection scan on inter-agent messages), propagation depth limits. |
| **Multi-Agent Topology** | Live directed graph of agent interactions. Detects resource contention, contradictory actions, cascade amplification, circular dependencies. Fleet Health Score (0–100). |
| **Chaos Engineering** | Controlled fault injection: deny tools, inject latency, expire credentials, exhaust budgets, disconnect peers. Governance Grade (A–F) based on how the system responds. Safety-gated via HITL approval. |
| **Collective Intelligence** | When one agent detects a threat, every agent benefits. Anonymous IOC (Indicator of Compromise) sharing across tenants. 6 AI-native IOC types. EigenTrust scoring for IOC quality. Sub-5s propagation. One detection in São Paulo protects a deployment in Berlin. |
| **Observability** | Session traces with span trees, latency breakdowns (P50/P95/P99), violation heatmaps, drift detection from intent fingerprint mismatches, loop detection, quality scoring, A/B testing between policy versions. |
| **Alerting** | Configurable rules in YAML. Slack, email, PagerDuty. "Alert if drift rate > 5%", "Alert if daily spend > $100", "Alert if injection events > 10/hour". |
| **OTEL & SIEM Export** | Pipe traces to Datadog, Grafana, New Relic via OpenTelemetry. Export security events to Splunk, ELK via STIX 2.1 or CEF. |
| **Audit Trail** | SHA-256 hash chain with Ed25519 signatures. Every action logged with cryptographic integrity, policy snapshot reference, and intent proof. Tamper-evident, exportable, regulator-ready. |
| **Compliance Reports** | EU AI Act Articles 9, 11, 12, 14. Generated from real scan data and runtime telemetry. Exportable for auditors and regulators. |

---

## Supported Frameworks

- **LangGraph**, **CrewAI**, **AutoGen** — AST-based discovery
- **LangChain**, **LlamaIndex**, **PydanticAI** — import/pattern detection

Framework detection is automatic.

---

## CI/CD Integration

```yaml
# .github/workflows/agentmesh.yml
name: AgentMesh Governance
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install useagentmesh
      - run: agentmesh scan . --format sarif > results.sarif
      - run: agentmesh scan . --fail-on critical --threshold 70
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
        if: always()
```

---

## How It Works

1. **Discovery** — Reads `pyproject.toml` / `requirements.txt`, identifies framework via import analysis
2. **AST Parsing** — Parses every `.py` file. Extracts agents, tools, models, prompts, MCP servers, permissions
3. **Policy Evaluation** — Runs 50+ rules against the BOM. Each rule is a Python class with an `evaluate()` method
4. **Scoring** — Deducts points per severity with caps. Range: 0–100
5. **Output** — Terminal, JSON, or SARIF 2.1.0
6. **Runtime** — `govern()` wraps every tool call through the enforcement pipeline. Each call evaluated before execution.

Policy evaluation is deterministic — no LLM, no heuristics, no probabilistic scoring.

---

## Benchmarks

10,000 iterations, `time.perf_counter_ns()`, after 1,000 warmup:

| Scenario | P50 | P99 |
|---|---|---|
| Single rule | **0.031ms** | 0.08ms |
| Full scan (50+ rules) | **1.84ms** | 3.2ms |
| Batch (100 tool calls) | **1.79ms** | 2.8ms |

Governance overhead: **<0.2%** of a typical LLM call (~800ms).

---
## EU AI Act

High-risk system rules take effect **August 2, 2026**.

| Article | Requirement | How AgentMesh covers it |
|---------|-------------|------------------------|
| Art. 9 | Risk management | Scan rules (COM-004), ODD enforcement, magnitude limits |
| Art. 11 | Technical documentation | Agent BOM, compliance reports, context versioning |
| Art. 12 | Record-keeping / logging | Cryptographic audit trail with policy snapshot references |
| Art. 14 | Human oversight | HITL checkpoints, programmable hooks, escalation policies |

Runtime platform generates exportable compliance reports for these articles.

---

## Roadmap
 
AgentMesh today covers the full governance stack: static analysis,
runtime enforcement, cryptographic audit, human oversight, cost
control, collective threat intelligence, and multi-agent security.
 
What comes next:
 
**Beyond Python** — governance for agents built in TypeScript,
Go, and via REST. The enforcement pipeline, not the language,
is the product. If it makes a tool call, AgentMesh governs it.
 
**The compliance layer enterprises need** — SOC 2 Type II audit
packages, ISO 42001 certification support, FedRAMP groundwork,
and packaged compliance templates for financial services,
healthcare, and critical infrastructure. Governance that
survives a regulator asking questions at 9am.
 
**Governance-aware model routing** — real-time decision engine
that selects models based on task risk profile, not just cost.
High-risk financial action → routes to the most reliable model
with full intent verification. Low-risk summarization → routes
to the cheapest model with audit-only. The governance policy
decides the model, not the developer.
 
**Autonomous remediation** — when AgentMesh detects a governance
gap, it doesn't just report it. It proposes a fix, runs it
through the policy engine, and applies it with human approval.
From "here's what's wrong" to "here's what we fixed" in one
pipeline.
 
**Agent insurance scoring** — a quantified risk profile that
maps directly to AI liability insurance underwriting. Your
AgentMesh governance score, audit trail completeness, HITL
coverage, and incident history become a standardized package
that insurers can evaluate. The companies that can prove
governance get coverage. The ones that can't, don't.
 
**The governance mesh** — federated governance across
organizational boundaries. When Company A's agent talks to
Company B's agent, both governance policies apply. Cross-org
audit trails, mutual trust verification, and regulatory
reporting that spans supply chains. The agent economy needs
governance infrastructure, not just governance tools.
 
---
 
**AgentMesh is actively developed and moving fast.** If you're
deploying AI agents to production,
[watch the repo](https://github.com/angelnicolasc/agentmesh)
— or better, run the scan and see what it finds.

---


## License

BUSL-1.1. Free to use in production. Cannot offer governance capabilities as a competing hosted service. Converts to Apache 2.0 four years after release. See [LICENSE](LICENSE).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and how to add new policy rules.
