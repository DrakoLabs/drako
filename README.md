<div align="center">
<a href="https://getdrako.com/">
<img width="1500" height="276" alt="drako1" src=".github/assets/drako1.jpg" />
</a> </div>

<h3 align="center">
  AI Agent Security & Governance Platform 🐉
</h3>
<div align="center">
  <strong>The governance platform for AI agents that doesn't use AI to decide.</strong>
  <br>
  Scans your codebase, scores your governance posture, flags what's reachable, connects findings to known advisories.
  Free, offline, no account required.
  <br />
 <strong>Full runtime enforcement when you're ready.</strong>
  <br /><br />
  Also scans the AI agents installed in <a href="#desktop-agent-scanning">Claude, Cursor, VS Code, and Windsurf.</a>
</div>
<br />
<p align="center">
  <a href="https://pypi.org/project/drako/">
    <img src="https://img.shields.io/pypi/v/drako?style=flat-square&color=3776AB&logo=pypi&logoColor=white" alt="PyPI">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=yellow" alt="Python 3.10+">
  </a>
  <a href="https://github.com/drakolabs/drako/actions">
    <img src="https://img.shields.io/badge/tests-1489%20passing-2ea44f.svg?style=flat-square&logo=github-actions&logoColor=white" alt="Tests">
  </a>
  <img src="https://img.shields.io/badge/rules-97-6366F1.svg?style=flat-square" alt="Rules">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-BUSL--1.1-6366F1.svg?style=flat-square&logo=opensourceinitiative&logoColor=white" alt="License: BUSL-1.1">
  </a>
  <img src="https://img.shields.io/badge/policy%20eval-%3C2ms-6366F1.svg?style=flat-square" alt="Performance">
</p>

```bash
pip install drako && drako scan .
```

---

## Scan for Free

<p align="center">
  <img src=".github/assets/drakoscanner.svg" alt="Drako – AI Agent Security & Governance" width="100%" style="max-width: 900px;">
</p>

Two scores, two audiences. **Governance** speaks to security teams — are your agents safe?
**Determinism** speaks to engineers — will they behave the same way twice?

**Reachability** separates real risks from theoretical ones: a dangerous tool no agent actually calls is flagged, not screamed at you.

```bash
drako scan .                       # Full scan, both scores
drako scan --details               # Code snippets + fix suggestions
drako scan --benchmark             # Compare against 100 scanned projects
drako scan --baseline              # Acknowledge existing issues, only show new ones
drako scan --format sarif          # GitHub Code Scanning
drako scan --fail-on critical      # CI gate
drako scan --share                 # Generate shareable score card
drako fix --dry-run                # Preview auto-fixes
drako scan --diff HEAD~1           # Only scan changed files
drako history                      # view policy snapshot history
drako diff v2 v3                   # compare policy versions
drako rollback v2                  # restore previous policy
```

---

## Agent BOM

Standalone inventory. No runtime, no network, pure AST.

```bash
drako bom .
```

<p align="center">
  <img src=".github/assets/agentbom.svg" alt="Drako – AI Agent Security & Governance" width="100%" style="max-width: 900px;">
</p>

Output formats: `--format text` (default) · `json` · `markdown`

---

## Rules

97 deterministic rules across 16 categories. No LLM in the evaluation loop. Same code, same result, every time. [Full rule reference →](docs/rules/index.md)

| Category | Rules | What it catches |
|----------|-------|-----------------|
| **Security** | SEC-001 → SEC-011 | Hardcoded keys, prompt injection, code execution, filesystem/network access |
| **Governance** | GOV-001 → GOV-011 | No audit logging, no HITL, self-modifying prompts, no fallback |
| **Compliance** | COM-001 → COM-005 | EU AI Act Art. 9, 11, 12, 14 gaps |
| **Determinism** | DET-001 → DET-007 | Temperature not set, no timeout, no retry, no iteration limit, no seed |
| **Vendor Concentration** | VCR-001 → VCR-003 | Same vendor across model + framework + cloud + governance layers |
| **Framework-Specific** | FW-001 → FW-010 | CrewAI delegation risks, AutoGen code exec defaults, LangGraph state issues |
| **Operational Boundaries** | ODD-001 → ODD-004 | No boundary definition, unrestricted tools, no spend cap |
| **Magnitude** | MAG-001 → MAG-003 | No spend cap, no rate limit, unclassified data access |
| **Identity** | ID-001 → ID-003 | Static credentials, shared credentials, no identity |
| **Multi-Agent** | MULTI-001 → MULTI-004 | No topology, circular deps, no conflict protection |
| **Hooks** | HOOK-001 → HOOK-003 | No pre-action validation, no session-end gate |
| **Versioning** | CV-001 → CV-002 | No policy versioning, no audit policy reference |
| **FinOps** | FIN-001 → FIN-003 | No cost tracking, single model for all tasks, no cache |
| **Resilience** | RES-001 → RES-002 | No fallback for critical ops, no state preservation |
| **A2A** | A2A-001 → A2A-003 | No A2A auth, unvalidated inter-agent input |
| **Best Practices** | BP-001 → BP-005 | Outdated framework, no tests, too many tools |

**Vendor Concentration** rules detect when your model, framework, and governance stack come from the same vendor — flagging audit independence risk that vendor-affiliated tools have no incentive to report.

**Framework-Specific** rules detect known governance gaps in the frameworks you use, including default configurations that ship insecure.

Scoring: start at 100, deduct per finding with caps per category. Grades: **A** (90-100) · **B** (75-89) · **C** (60-74) · **D** (40-59) · **F** (0-39)

> **TypeScript/JavaScript:** 17 additional rules (SEC, GOV, COM, DET, ODD) apply when scanning TS/JS projects.

> Install: `pip install drako[typescript]`

---

## Advisories

Drako ships with 25 security advisories in the **DRAKO-ABSS** format (Agent Behavioral Security Standard) — covering OWASP Top 10 for LLMs, MITRE ATLAS techniques, and real CVEs from CrewAI, LangChain, and AutoGen.

Advisories appear inline in scan findings:

```
SEC-007  Prompt injection vulnerability       (agents/researcher.py)
         Related: DRAKO-ABSS-2026-001 — System Prompt Extraction
         Ref: OWASP LLM01:2025, MITRE AML.T0051
```

Each advisory includes: affected configurations, IOC pattern hashes for runtime matching, taint paths, and remediation mapped to Drako rules.

📄 [Browse advisories →](src/drako/data/advisories/) · [ABSS format spec →](docs/abss-format.md)

---

## Baseline

Existing projects get 40+ findings on first scan. The baseline lets teams acknowledge known issues and focus only on **new** ones.

```bash
drako scan . --baseline            # save current state
drako scan .                       # only NEW findings from now on
drako baseline show                # what's baselined
drako baseline reset               # start fresh
```

- Score always reflects **all** findings — real posture, not a filtered view
- CI pass/fail is based on **new findings only**
- SARIF marks baselined findings as `"baselineState": "unchanged"`
- Baseline file commits to your repo — shared across the team

---

## Observability Dashboard

Drako ships with a **built-in observability dashboard** at [getdrako.com/dashboard](https://getdrako.com/dashboard).
No external tooling required.

<!-- TODO: Replace with actual screenshot -->
<!-- Screenshot: /dashboard showing MetricCards, quota bar, governance score trend, tool health grid -->

The command center gives you your full governance posture at a glance — audit entries, verified agents,
policy blocks, and quota usage — with real-time auto-refresh.

Every agent run produces signals across four dimensions. Drako surfaces them as actionable intelligence,
not raw logs:

<!-- TODO: Replace with actual screenshot -->
<!-- Screenshot: /observability showing metrics tab with charts -->

| Dimension | What Drako shows you |
|---|---|
| **Health Grade** | Unified A–F score combining latency, error rate, and governance overhead |
| **Latency** | P50 / P95 / P99 percentiles with full time-series visualization |
| **Violation Heatmap** | Hour-by-day grid that reveals where and when violations cluster |
| **Drift Detection** | Automatic identification of behavioral drift across your agent fleet |
| **Alert Rules** | Configurable thresholds with test-fire capability before going live |


### FinOps

Track and optimize your AI spend with per-model and per-agent cost breakdowns.

<!-- TODO: Replace with actual screenshot -->
<!-- Screenshot: /finops showing cost donut chart and budget tracking -->

**What you get:**
- **Cost by Model** — See exactly how much each LLM model costs you
- **Cost by Agent** — Identify your most expensive agents
- **Budget Tracking** — Set monthly budgets and track burn rate
- **Cache Hit Rate** — Monitor how effectively your cache reduces costs

> **Deep dive:** See [docs/observability.md](docs/observability.md) for the full architecture, all available metrics, and integration guide.

---


## Desktop Agent Scanning

Scans the MCP servers declared in your AI coding tools — Claude Desktop, 
Cursor, VS Code, Windsurf, Claude Code, Codex CLI, Gemini CLI, and Kiro.
```bash
drako desktop scan          # Discover + scan all installed AI clients
drako desktop bom           # Export the BOM from the desktop agents
drako desktop govern        # Scan + activate proxy protection
```

8 deterministic rules covering shell/exec capabilities, plaintext credentials, 
unencrypted transport, elevated privileges, and unrestricted filesystem access. 
Fully offline and 100% deterministic. No network requests during scanning.

📄 **[Desktop scanning docs →](docs/desktop-scanning.md) View the complete documentation here**

---

## Configure

```bash
drako init                         # generate .drako.yaml from your scan
```

```yaml
# .drako.yaml — pre-filled with YOUR agents and tools
governance_level: autopilot        # autopilot | balanced | strict

agents:
  researcher:
    source: agents/researcher.py
tools:
  web_search:
    type: read
  code_runner:
    type: execute                  # ⚠ flagged CRITICAL by scan

policies:
  odd:
    researcher:
      permitted_tools: [web_search, file_reader]
      forbidden_tools: [code_runner]
  dlp:
    mode: enforce
  circuit_breaker:
    failure_threshold: 5
  hitl:
    triggers:
      tool_types: [write, execute, payment]
      spend_above_usd: 100.00
```

**Autopilot** reads your scan, generates the config, starts in audit mode. When ready: `drako upgrade --balanced` enables enforcement.

Industry templates: `drako init --template fintech` · `healthcare` · `eu-ai-act` · `startup` · `enterprise`

📄 [Full config reference →](docs/config.md) · [Policy templates →](docs/policy-templates.md)

---

## Runtime Enforcement

One line to protect agents in production:

```python
from drako import govern
crew = govern(crew)    # every tool call passes through enforcement
```

Every tool call goes through a 13-stage pipeline before executing. If a tool is forbidden, carries PII, exceeds spend caps, matches a known threat, or needs human approval — blocked before it runs.

### Key capabilities

- 🔒 **DLP** — Presidio-based PII/PCI scanning. Critical PII blocked before reaching downstream APIs.
- 👤 **Human-in-the-Loop** — Agent pauses on high-risk actions, escalates to human. Configurable triggers. EU AI Act Art. 14.
- ⚡ **Circuit Breaker** — Per-agent AND per-tool. One failing tool doesn't kill the whole agent.
- 📋 **Audit Trail** — SHA-256 hash chain with Ed25519 signatures. Tamper-evident, exportable, regulator-ready.
- 🌐 **Collective Intelligence** — Anonymous IOC sharing across deployments. One detection protects everyone. Sub-5s propagation.

📄 [Full runtime docs →](docs/runtime-capabilities.md) — covers all 20 capabilities including Trust Score, Intent Fingerprinting, ODD Enforcement, Magnitude Limits, FinOps, Secure A2A, Topology Monitoring, Chaos Engineering, Observability, Alerting, and OTEL/SIEM Export.

---

## Out-of-process proxy

Zero code changes. The agent can't bypass what doesn't run in its process.

```bash
drako proxy start
export OPENAI_BASE_URL=http://localhost:8990/openai/v1
```

📄 [Proxy docs →](docs/proxy-mode.md) · [Docker + Helm →](deploy/)

---

## Autopilot Mode

Zero-config governance. One command, smart defaults from your scan.

```bash
drako init                     # autopilot (default) — audit-first
drako init --balanced          # enforcement active with escape hatches
drako init --strict            # maximum governance for enterprise
drako init --manual            # full YAML with all sections
drako init --template fintech  # start from industry template
```

Autopilot analyzes your project and generates a `.drako.yaml` pre-configured with:

- **ODD**: Each agent locked to its discovered tools
- **DLP**: Audit mode (logging PII, not blocking yet)
- **Circuit Breaker**: Threshold 5 failures / 60s window
- **HITL**: Active for write/execute tools (auto-allow on timeout)
- **FinOps**: Cost tracking enabled

Everything starts in audit mode. When you're ready for enforcement:

```bash
drako upgrade --balanced    # DLP enforce, ODD enforce, HITL reject on timeout
drako upgrade --strict      # + intent verification, cryptographic audit, magnitude enforce
```

---


## CI/CD

### GitHub Action

The [Drako GitHub Action](.github/actions/drako-scan/) posts inline PR comments on the exact lines where issues are found, uploads SARIF to Code Scanning, and gates merges on governance score.

```yaml
# .github/workflows/drako.yml
name: Drako Governance
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install drako
      - run: drako scan . --format sarif > results.sarif
      - run: drako scan . --fail-on critical --threshold 70
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
        if: always()
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/DrakoLabs/Drako
  hooks:
    - id: drako-scan
```

---

## Ecosystem Ratings

Drako scans popular frameworks, MCP servers, and open-source projects — and publishes the results.

- 🏆 [**Framework Security Ratings**](https://getdrako.com/ratings) — Governance grades for CrewAI, LangGraph, AutoGen, Semantic Kernel, PydanticAI, Google ADK, OpenAI Agents SDK
- 🔌 [**MCP Server Directory**](https://getdrako.com/mcp-directory) — Permission scope, input validation, and governance assessment for popular MCP servers
- 📊 [**AI Agent Governance Index**](https://getdrako.com/governance-index) — Aggregate governance stats from 100 open-source AI agent projects (the data behind `--benchmark`)

---
## Supported Frameworks

| Framework | Detection | Specific Rules |
|-----------|-----------|----------------|
| **CrewAI** | AST | FW-001 → FW-003 (code exec, memory isolation, delegation) |
| **LangGraph** | AST | FW-004 → FW-005 (unrestricted ToolNode, no checkpointing) |
| **AutoGen** | AST | FW-006 → FW-007 (LocalCommandLineCodeExecutor, no output validation) |
| **Semantic Kernel** | AST | FW-008 → FW-009 (auto-imported plugins, no cost guard) |
| **PydanticAI** | Import | FW-010 (untyped tool returns) |
| **LlamaIndex** | Import | General rules |
| **LangChain** | Import | General rules |
| **TypeScript/JavaScript** | Tree-sitter | LangChain.js, Vercel AI SDK, Mastra, AutoGen.js (`pip install drako[typescript]`) |

---

## EU AI Act

High-risk system rules take effect **August 2, 2026**.

| Article | Requirement | How Drako covers it |
|---------|-------------|---------------------|
| Art. 9 | Risk management | 97 scan rules, ODD enforcement, magnitude limits |
| Art. 11 | Technical documentation | Agent BOM, compliance reports, context versioning |
| Art. 12 | Record-keeping | Cryptographic audit trail with policy snapshot references |
| Art. 14 | Human oversight | HITL checkpoints, programmable hooks, escalation policies |

📄 [Compliance report generation →](docs/compliance.md)

---

## Performance

97 rules, 10,000 iterations, `time.perf_counter_ns()`, after 1,000 warmup:

| Scenario | P50 | P99 |
|---|---|---|
| Single rule | **0.031ms** | 0.08ms |
| Full scan (97 rules) | **2.1ms** | 3.8ms |
| Batch (100 tool calls) | **1.79ms** | 2.8ms |

Governance overhead: **<0.3%** of a typical LLM call.

---

## Policy Templates

Industry-specific governance presets. Start from a template, override what you need.

```bash
drako templates list              # show available templates
drako templates show fintech      # preview a template
drako init --template healthcare  # init with template
```

Available templates:

| Template | Focus |
|----------|-------|
| **base** | Sensible defaults for any project |
| **fintech** | PCI compliance, spend caps, strict DLP |
| **healthcare** | HIPAA alignment, PHI detection, audit trails |
| **eu-ai-act** | EU AI Act Articles 9, 11, 12, 14 compliance |
| **startup** | Lightweight audit-first governance |
| **enterprise** | Maximum governance, intent verification, A2A security |

Templates support inheritance via `extends:`:

```yaml
# .drako.yaml
extends: fintech
governance_level: balanced
# Your overrides here — template provides the base
```

---

## See It in Action

```bash
git clone https://github.com/drakolabs/drako.git
cd drako/examples/demo-crewai
pip install drako
drako scan .
```

The demo project has intentional governance gaps and scores ~35 (Grade F). See what Drako finds.

---

## Roadmap

- **Beyond Python** — Go SDK next. TypeScript/JavaScript already supported. If it makes a tool call, Drako governs it.
- **Compliance packages** — SOC 2 Type II audit evidence, ISO 42001 templates.

**Drako is actively developed and moving fast.** If you're
deploying AI agents to production,
[watch the repo](https://github.com/drakolabs/drako)
— or better, run the scan and see what it finds.
📄 [Full roadmap →](ROADMAP.md)

---

## License

BUSL-1.1. Free to use in production. Cannot offer governance capabilities as a competing hosted service. Converts to Apache 2.0 four years after release. See [LICENSE](LICENSE).

---

## Contributing

Every rule requires a positive fixture, a negative fixture, and a standard reference. See [CONTRIBUTING.md](CONTRIBUTING.md).
