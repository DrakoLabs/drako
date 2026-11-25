# Compliance Reports (EU AI Act & Digital Omnibus)

Drako maps static scan findings and local cryptographic Ed25519 receipts (`.drako/receipts.jsonl`) to EU AI Act articles (Regulation 2024/1689, aligned with the EU AI Act Digital Omnibus schedule) and generates structured offline compliance bundles.

- **Article 50 transparency:** active `2026-08-02` (Article 50(2) watermarking grace period ending `2026-12-02`)
- **Annex III high-risk systems:** `2027-12-02`
- **Annex I embedded high-risk systems:** `2028-08-02`

---

## Generating a Compliance Report

```bash
# Terminal output (default — 100% offline, read-only)
drako scan .

# JSON — machine-readable, includes compliance fields
drako scan . --format json

# SARIF 2.1.0 — GitHub Code Scanning compatible
drako scan . --format sarif > results.sarif

# Detailed compliance & impact breakdown
drako scan . --details

# Generate EU AI Act compliance evidence bundle (requires `pip install 'drako[comply]'`)
drako comply generate --all
```

The compliance rules (`COM-001` through `COM-006`) run in every offline scan alongside security, governance, and framework rules.

---

## Compliance Rules

### COM-001 — No Automatic Logging

**Severity:** HIGH  
**EU AI Act:** Article 12 (Record-keeping)  
**Requirement:** High-risk AI systems must automatically record events for traceability across their operational lifetime.

**What Drako checks:** Scans Python source files for local audit logging or v4 Authority Kernel usage (`guard`, `build_host`, `wrap_*`, `AuthorityKernel`, `ReceiptStore`, `audit_log`, `structlog`, `logging.getLogger`) and `.drako.yaml` (`audit.enabled: true` / `receipt_store:`).

**Fix:**
```python
from drako import guard

# Record tamper-evident Ed25519 hash-chained receipts locally (EU AI Act Art. 12)
safe_agent = guard(my_agent, allow=["search_*"], receipts=".drako/receipts.jsonl")
```

Verify recorded receipts offline at any time:
```bash
drako verify .drako/receipts.jsonl --pubkey-file .drako/keys/host.pub
```

---

### COM-002 — No Human Oversight Mechanism

**Severity:** HIGH  
**EU AI Act:** Article 14 (Human oversight)  
**Requirement:** High-risk AI systems must enable effective human intervention and override before irreversible actions execute.

**What Drako checks:** Scans Python source files for human oversight / consent gates (`approval_required`, `ConsentToken`, `sign_consent_token`, `human_in_the_loop`, `hitl`, `require_approval`, `drako.guard`, `build_host`) and `.drako.yaml` / `drako-policy.yaml` (`hitl.mode: enforce` or `tiers.irreversible: consent`).

**Fix:**
```python
from drako import guard

# Require operator-signed Ed25519 ConsentToken before high-impact tools execute
safe_agent = guard(
    my_agent,
    allow=["search_*"],
    approval_required=["write_file", "send_email"],
)
```

```yaml
# .drako.yaml — flat v4 top-level schema
hitl:
  mode: enforce
  triggers:
    tool_types: [write, execute, payment]
  approval_timeout_minutes: 30
  timeout_action: reject
```

---

### COM-003 — No Technical Documentation

**Severity:** MEDIUM  
**EU AI Act:** Article 11 (Technical documentation)

**What Drako checks:** Presence of a non-empty `docs/`, `doc/`, or `documentation/` directory, `ARCHITECTURE.md`, or a `README.md` / `README.rst` referencing AI/agent components.

**Fix:**
```bash
mkdir -p docs
# docs/architecture.md     — System design and component overview
# docs/agents.md           — Agent inventory (generate via `drako bom . --format markdown`)
# docs/risk-assessment.md  — Risk analysis (Art. 9)
```

---

### COM-004 — No Risk Management Documentation

**Severity:** MEDIUM  
**EU AI Act:** Article 9 (Risk management system)

**What Drako checks:** Presence of `RISK_ASSESSMENT.md`, `risk_assessment.md`, `docs/risk-assessment.md`, `docs/risk_assessment.md`, or `docs/risks.md`, or risk management metadata in configuration files.

**Fix:** Document known and foreseeable agent risks, tool access boundaries, data handling controls, and residual risk acceptance criteria in `docs/risk-assessment.md`.

---

### COM-005 — No Agent BOM / Inventory

**Severity:** MEDIUM  
**EU AI Act:** Article 11 / OWASP Agentic Top 10

**What Drako checks:** Presence of `.drako.yaml`, `drako.yaml`, `agent-bom.json`, `agent_bom.json`, or `AGENT_BOM.md`.

**Fix:**
```bash
pip install drako
drako init
drako bom . --format cyclonedx > agent-bom.cdx.json
```

---

### COM-006 — No HITL Checkpoint for High-Risk Actions

**Severity:** CRITICAL  
**EU AI Act:** Article 14 (Human oversight)

**What Drako checks:** Identifies tools with destructive or side-effect names (`delete`, `write`, `remove`, `send`, `pay`, `transfer`, `execute`, `deploy`, `publish`, `drop`, etc.) and verifies that HITL enforcement (`hitl:` or `irreversible: consent`) or code-level oversight exists.

**Fix:**
```yaml
# .drako.yaml
hitl:
  mode: enforce
  triggers:
    tool_types:
      - write
      - execute
      - payment
    trust_score_below: 60
    spend_above_usd: 100.0
  approval_timeout_minutes: 30
  timeout_action: reject
```

---

## CI/CD Gating

Gate pull requests offline on severity and determinism thresholds:

```bash
# Fail on any critical finding (including COM-006)
drako scan . --fail-on critical

# Fail on high or critical findings
drako scan . --fail-on high

# Fail if determinism score drops below 70
drako scan . --fail-on critical --threshold-det 70

# Export SARIF for GitHub Code Scanning
drako scan . --format sarif --fail-on critical > compliance-report.sarif

# Export JSON for audit pipelines
drako scan . --format json > compliance-report.json
```

---

## Policy Templates for Compliance

Initialize directly from the `eu-ai-act` v4 template:

```bash
drako init --template eu-ai-act
drako validate .drako.yaml
```

This applies:
- `kernel.default_effect: deny` with `tiers.irreversible: consent`
- `audit.cryptographic: true` + `retention_days: 3650` (Art. 12 — 10 years)
- `hitl.mode: enforce` + `timeout_action: reject` (Art. 14)
- `dlp.mode: enforce` + `intent_verification.mode: enforce` (Art. 9)
- `a2a.mode: enforce` + `require_signed_cards: true`

See [Policy Templates →](policy-templates.md) for all six presets.

---

## Baseline Workflow

For existing repositories with known compliance debt:

```bash
# Save acknowledged findings as baseline
drako scan . --baseline

# Subsequent scans flag only newly introduced gaps in CI
drako scan . --fail-on high
```
