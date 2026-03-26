# Compliance Reports

Drako maps scan findings to EU AI Act articles and generates structured compliance gap reports. The compliance report shows which regulatory requirements your AI system satisfies and which need remediation.

---

## Generating a Compliance Report

```bash
# Terminal output (default)
drako scan .

# JSON — machine-readable, includes compliance fields
drako scan . --format json

# SARIF — GitHub Code Scanning compatible
drako scan . --format sarif > results.sarif

# Compliance summary only (terminal)
drako scan . --details
```

The compliance rules (COM-001 through COM-006) are included in every scan. The terminal report surfaces them alongside security and governance findings, with EU AI Act article references and fix snippets.

---

## Compliance Rules

### COM-001 — No Automatic Logging

**Severity:** HIGH
**EU AI Act:** Article 12 (Record-keeping)
**Article summary:** High-risk AI systems must keep logs automatically. Logs must be retained for at least 6 months unless other law requires longer retention.

**What Drako checks:** Scans Python source files for logging infrastructure patterns:
- `audit_log`, `audit_trail`, `with_compliance`, `drako`
- `GovernanceMiddleware`, `ComplianceMiddleware`, `log_action`
- `structlog`, `logging.getLogger`

**Fails when:** No logging infrastructure is detected in any Python source file.

**Regulatory exposure:** Fines up to €15M or 3% of worldwide annual revenue.

**Fix:**
```python
from drako import with_compliance

# Drako middleware provides EU AI Act compliant audit logging automatically.
# All agent actions, decisions, and tool calls are logged.
crew = with_compliance(my_crew)
```

---

### COM-002 — No Human Oversight Mechanism

**Severity:** HIGH
**EU AI Act:** Article 14 (Human oversight)
**Article summary:** High-risk AI systems must be designed to allow effective human oversight. Humans must be able to intervene and override decisions.

**What Drako checks:** Scans Python source files for human oversight patterns:
- `human_in_the_loop`, `hitl`, `require_approval`, `human_approval`
- `ask_human`, `confirm_action`, `manual_review`, `human_oversight`
- `supervisor`, `review_queue`

**Fails when:** Agents exist in the project but no human oversight mechanism is detected.

**Regulatory exposure:** Fines up to €15M. Enforcement action if an AI system causes harm without human oversight.

**Fix:**
```python
from drako import with_compliance

crew = with_compliance(my_crew, config_path=".drako.yaml")
```

```yaml
# .drako.yaml — configure HITL policies
policies:
  hitl:
    mode: enforce
    triggers:
      tool_types: [write, execute, payment]
```

---

### COM-003 — No Technical Documentation

**Severity:** MEDIUM
**EU AI Act:** Article 11 (Technical documentation)
**Article summary:** Before a high-risk AI system is placed on the market, providers must draw up technical documentation demonstrating the system meets requirements.

**What Drako checks:** Looks for documentation indicators:
- `docs/` directory (non-empty)
- `doc/` or `documentation/` directory (non-empty)
- `README.md` or `README.rst` containing references to "agent", "ai", "llm", or "model"
- `ARCHITECTURE.md`

**Fails when:** None of the above exist or the README doesn't mention AI components.

**Fix:** Create a `docs/` directory with at minimum:

```bash
mkdir -p docs
# docs/architecture.md   — System design and component overview
# docs/agents.md         — Agent inventory, capabilities, and limitations
# docs/risk-assessment.md — Risk analysis (required by Art. 9)
```

The Agent BOM (`drako bom .`) can generate the agent inventory section automatically.

---

### COM-004 — No Risk Management Documentation

**Severity:** MEDIUM
**EU AI Act:** Article 9 (Risk management system)
**Article summary:** Providers of high-risk AI systems must implement a risk management system covering the entire lifecycle of the system.

**What Drako checks:** Looks for risk assessment files:
- `RISK_ASSESSMENT.md`
- `risk_assessment.md`
- `docs/risk-assessment.md`
- `docs/risk_assessment.md`
- `docs/risks.md`

Also checks config/doc content for: `risk_assessment`, `risk_management`, `risk_level`, `threat_model`.

**Fails when:** No risk documentation file exists and no risk management references are found.

**Fix:** Create `RISK_ASSESSMENT.md` covering:

1. Identification of known and foreseeable risks (misuse, technical failures, safety)
2. Risk estimation and evaluation
3. Risk mitigation measures
4. Residual risk evaluation after mitigation
5. Agent-specific risks (tool access, data handling, autonomous decisions)

---

### COM-005 — No Agent BOM / Inventory

**Severity:** MEDIUM
**Reference:** OWASP LLM Top 10
**Article summary:** Without a component inventory, you cannot track which AI models, tools, and permissions your agents use — making vulnerability response impossible.

**What Drako checks:** Looks for BOM files:
- `.drako.yaml` or `drako.yaml`
- `agent-bom.json` or `agent_bom.json`
- `AGENT_BOM.md`

**Fails when:** None of the above exist.

**Fix:**
```bash
pip install drako
drako init

# This creates .drako.yaml with:
# - Agent inventory (discovered via AST)
# - Tool registry with types
# - Model usage tracking
# - Governance policies
```

Run `drako bom .` to generate a standalone BOM in text, JSON, or Markdown format.

---

### COM-006 — No HITL for High-Risk Actions

**Severity:** CRITICAL
**EU AI Act:** Article 14 (Human oversight)
**Article summary:** Humans must retain meaningful control over high-risk AI decisions. Autonomous execution of destructive actions without a checkpoint is a direct Art. 14 violation.

**What Drako checks:**
1. Identifies tools with side-effect names: `delete`, `write`, `remove`, `send`, `pay`, `transfer`, `execute`, `deploy`, `publish`, `drop`, `post`, `push`, `submit`, `update`, `modify`, `create`, `insert`
2. If such tools exist, checks for HITL configuration in `.drako.yaml` or HITL patterns in Python source

**Fails when:** Side-effect tools exist but no HITL checkpoint is configured.

**Regulatory exposure:** Liability for autonomous AI harm. Enforcement actions under EU AI Act.

**Fix:**
```yaml
# .drako.yaml
policies:
  hitl:
    mode: enforce
    triggers:
      tool_types:
        - write
        - execute
        - payment
      trust_score_below: 60
      spend_above_usd: 100.00
    approval_timeout_minutes: 30
    timeout_action: reject
```

---

## Compliance Score and Grading

The compliance rules contribute to the overall governance score:

| Severity | Score Deduction |
|----------|----------------|
| CRITICAL | 20 points |
| HIGH | 10 points |
| MEDIUM | 5 points |
| LOW | 2 points |

**Letter grades:**

| Grade | Score |
|-------|-------|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | 0–39 |

A project failing COM-001 (HIGH) and COM-006 (CRITICAL) loses 30 points before counting any security or governance findings.

---

## CI/CD Integration

Gate deployments on compliance status:

```bash
# Fail on any critical findings (including COM-006)
drako scan . --fail-on critical

# Fail if governance score drops below 70
drako scan . --threshold 70

# Both — fail on critical OR low score
drako scan . --fail-on critical --threshold 70
```

Export for regulators:

```bash
# SARIF — for GitHub Code Scanning and security tooling
drako scan . --format sarif > compliance-report.sarif

# JSON — for custom dashboards and automated pipelines
drako scan . --format json > compliance-report.json
```

The JSON output includes a `compliance` field with per-article status:

```json
{
  "score": 72,
  "grade": "C",
  "compliance": {
    "eu_ai_act": {
      "art_9": "FAIL",
      "art_11": "PASS",
      "art_12": "FAIL",
      "art_14": "FAIL"
    }
  },
  "findings": [...]
}
```

---

## Policy Templates for Compliance

The `eu-ai-act` template pre-configures all four Article requirements:

```bash
drako init --template eu-ai-act
```

This sets:
- `audit.cryptographic: true` + `retention_days: 3650` (Art. 12 — 10 years)
- `hitl.mode: enforce` + `timeout_action: reject` (Art. 14)
- `dlp.mode: enforce` (Art. 9 risk management)
- `odd.enforcement_mode: enforce` (Art. 9 operational boundaries)

See [Policy Templates →](policy-templates.md) for the full template configuration.

---

## Baseline Workflow for Compliance

For existing projects with pre-existing compliance gaps:

```bash
# Save current state as baseline (known gaps)
drako scan . --baseline

# From now on, only new gaps are flagged in CI
drako scan .

# Governance score still reflects ALL findings — real posture, not filtered
```

Use the baseline to focus remediation efforts on new issues while working through the backlog systematically.
