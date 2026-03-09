# AgentMesh

Deterministic governance middleware for AI agents. No LLM in the evaluation loop.

[![PyPI](https://img.shields.io/pypi/v/useagentmesh)](https://pypi.org/project/useagentmesh/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-798%20passing-brightgreen.svg)]()
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![Policy Eval](https://img.shields.io/badge/policy%20eval-<2ms-brightgreen.svg)]()

---

## What It Does

AI agents call tools, spend money, delete files, and make 
decisions — autonomously, at speed, without asking.

**AgentMesh** is the governance layer between your agent and 
everything it can touch. It scans your codebase to find 
governance gaps before production does. And it enforces 
policies on live agent traffic — blocking actions before 
they execute, not just logging them after.

The scan is free, offline, and needs no account. The runtime 
platform connects in one line and protects agents in production.

No LLM in the evaluation loop. Every rule is deterministic. 
Same code, same result, every time.

---

## Quick Start

```bash
pip install useagentmesh
agentmesh scan .
```

Output Example:

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
```

Common flags:

```bash
agentmesh scan --format sarif       # SARIF 2.1.0 for GitHub Code Scanning
agentmesh scan --threshold 70       # Exit 1 if score < 70
agentmesh scan --fail-on critical   # Exit 1 on any critical finding
agentmesh scan --diff HEAD~1        # Only scan changed files
agentmesh scan --details            # Full report with code snippets and fixes
```
---

## What the Scan Detects

34 deterministic rules across 7 categories. Same code always produces the same score.

| ID | Severity | What it detects |
|---------|----------|------|
| **Security** | | |
| SEC-001 | CRITICAL | API key hardcoded in source code |
| SEC-002 | CRITICAL | Secrets in prompts or configuration |
| SEC-005 | CRITICAL | Arbitrary code execution in tool |
| SEC-007 | HIGH | Prompt injection vulnerability |
| SEC-003 | HIGH | Unrestricted filesystem access in tool |
| SEC-004 | HIGH | Unrestricted network access in tool |
| **Governance** | | |
| GOV-006 | CRITICAL | Agent can modify its own system prompt |
| GOV-004 | HIGH | No human-in-the-loop for destructive actions |
| GOV-001 | HIGH | No audit logging configured |
| **Compliance** | | |
| COM-001 | HIGH | No automatic logging (EU AI Act Art. 12) |
| COM-002 | HIGH | No human oversight mechanism (EU AI Act Art. 14) |
| **Operational** | | |
| ODD-001 | CRITICAL | No operational boundary definition |
| MAG-001 | CRITICAL | No spend cap defined |
| ID-001 | CRITICAL | Static credentials in agent code |

Plus 20 more rules covering rate limits, input validation, circuit breakers, documentation, testing, credential sharing, framework hygiene, and CI/CD gates. 

**Scoring:**

```
Start at 100. Deduct per finding (with caps to prevent one category from dominating):
  CRITICAL: -15 each (cap -60)  │  HIGH: -8 each (cap -40)
  MEDIUM:   -3 each (cap -20)   │  LOW:  -1 each (cap -10)

Grades: A (90-100) │ B (75-89) │ C (60-74) │ D (40-59) │ F (0-39)
```

---

## Agent BOM (Bill of Materials)

AgentMesh walks your Python AST to build an inventory of every component in your agent project. No config files, no runtime agent, no network calls.

```
Component      Details
───────────    ──────────────────────────────────────────────
Agents         3 (researcher, writer, reviewer)
Tools          12 (web_search, file_reader, code_runner, ...)
Models         2 (gpt-4o, claude-3-sonnet)
MCP Servers    1
Prompts        4 system prompts detected
Permissions    filesystem, network, code_execution
Framework      crewai 0.86.0
```

Available in JSON via `agentmesh scan --format json`.

---

## Supported Frameworks

- **LangGraph**, **CrewAI**, **AutoGen** — AST-based discovery
- **LangChain**, **LlamaIndex**, **PydanticAI** — import/pattern detection

Framework detection is automatic. Override with `--framework crewai,langgraph` if needed.

---

## Output Formats

- **Terminal** (default) — Rich-formatted report. Use `--details` for code snippets and fix suggestions.
- **SARIF 2.1.0** — `agentmesh scan --format sarif`. GitHub Code Scanning compatible.
- **JSON** — `agentmesh scan --format json`. Schema v1.0.0. Includes full Agent BOM.
- **SVG Badge** — Upload results with `agentmesh scan --upload` to get an embeddable badge URL.

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
        with:
          python-version: "3.12"
      - run: pip install useagentmesh
      - run: agentmesh scan . --format sarif > results.sarif
      - run: agentmesh scan . --fail-on critical --threshold 70
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        if: always()
```

For PR-only scans: `agentmesh scan . --diff origin/main`

---

## Runtime Platform

The scan tells you what's wrong. The platform fixes it and keeps it fixed in production.

| Capability | What it does |
|------------|-------------|
| **DLP** | Presidio-based PII/PCI detection on every tool call payload, before it reaches downstream APIs. CRITICAL PII → action rejected. |
| **Trust Score** | Per-agent EigenTrust reputation (0–100), updated on every interaction, time-decayed. Agents earn or lose trust based on behavior. |
| **Circuit Breaker** | Auto-suspends agents (or individual tools) when trust drops below threshold or failure rate spikes. Partial degradation, not full shutdown. |
| **ODD Enforcement** | Operational Design Domain: define exactly which tools, APIs, data sources, and time windows each agent can operate in. Modes: audit, enforce, escalate. |
| **Magnitude Limits** | Pre-action validation: spend caps per action/session/day, data volume limits, blast radius constraints, compute guardrails. Blocks before execution. |
| **Agent Identity** | Managed credential lifecycle per agent: dynamic provisioning, automatic rotation with grace periods, instant revocation. No more shared static API keys across agents. |
| **Audit Trail** | SHA-256 hash chain with Ed25519 signatures. Every action logged with cryptographic integrity. Tamper-evident, exportable, regulator-ready. |
| **Compliance Reports** | EU AI Act Articles 9, 11, 12, 14 mapping. Generated from real scan data and runtime telemetry. Exportable PDF for auditors and regulators. |

```bash
export AGENTMESH_API_KEY=am_live_...
agentmesh init
```


* 🌐 **Landing Page**: [useagentmesh.com](https://useagentmesh.com)

---

## How It Works

1. **Discovery** — Reads `pyproject.toml` / `requirements.txt`, identifies framework via import analysis
2. **AST Parsing** — Parses every `.py` file. Extracts agents, tools, models, prompts, MCP servers, permissions
3. **Policy Evaluation** — Runs 34 rules against the BOM. Each rule is a Python class with an `evaluate()` method
4. **Scoring** — Deducts points per severity with caps. Range: 0-100
5. **Output** — Terminal (Rich), JSON, or SARIF 2.1.0

AgentMesh does not use AI to audit AI. Policy evaluation is deterministic — same code always produces the same score.

---
### Benchmark Results

All measurements taken with `time.perf_counter_ns()`, 10,000 iterations after 1,000 warmup. [Methodology & reproduction →](sdk/benchmarks/README.md)

**Policy Engine** (33 deterministic rules, zero LLMs):

| Scenario | P50 | P99 |
|---|---|---|
| Single rule evaluation | **0.031ms** | 0.08ms |
| Full scan (33 rules) | **1.84ms** | 3.2ms |
| Batch (100 tool calls) | **1.79ms** | 2.8ms |

> Governance overhead is **<0.2%** of a typical LLM call (~800ms).

**AST Framework Discovery:**

| Framework | Avg Latency |
|---|---|
| CrewAI | ~5ms |
| LangGraph | ~7ms |
| AutoGen | ~9ms |

---

## EU AI Act

The EU AI Act applies to high-risk AI systems starting August 2026. AgentMesh maps its scan rules to specific articles:

| Article | Requirement | Rules |
|---------|-------------|-------|
| Art. 9 | Risk management | COM-004 |
| Art. 11 | Technical documentation | COM-003 |
| Art. 12 | Record-keeping / logging | COM-001, GOV-001 |
| Art. 14 | Human oversight | COM-002, GOV-004 |

The runtime platform generates exportable compliance reports for these articles.

---

## License

BUSL-1.1 (Business Source License 1.1).

You can use AgentMesh freely in your own projects, including production. The one restriction: you cannot take this code and offer a competing hosted governance service.

Each version converts to Apache 2.0 four years after release. See [LICENSE](LICENSE).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and how to add new policy rules.
