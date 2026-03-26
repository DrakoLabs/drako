# Policy Templates

Drako ships six industry-specific governance presets. Start from a template and override only what you need.

```bash
drako templates list              # show available templates
drako templates show fintech      # preview full template YAML
drako init --template healthcare  # init with template
```

Templates are applied via the `extends` field in `.drako.yaml`. All templates support inheritance — you can extend a built-in template and layer your overrides on top.

```yaml
# .drako.yaml
extends: fintech
governance_level: balanced

# Override only this:
policies:
  hitl:
    approval_timeout_minutes: 60
```

---

## `base` — Recommended Defaults

The foundation. Every other template extends this. Use it for projects that don't fit a specific industry vertical.

**Governance level:** `autopilot`
**Posture:** Audit-first. Nothing is blocked by default.

```yaml
governance_level: autopilot

policies:
  odd:
    enforcement_mode: audit
    default_policy: allow

  magnitude:
    max_spend_per_action_usd: 10.00
    max_spend_per_session_usd: 50.00
    max_records_per_action: 100

  dlp:
    mode: audit

  hitl:
    mode: audit
    triggers:
      tool_types: [write, execute, payment]
    timeout_action: allow
    approval_timeout_minutes: 30

  intent_verification:
    mode: "off"

  circuit_breaker:
    agent_level:
      failure_threshold: 5
      time_window_seconds: 60
      recovery_timeout_seconds: 30

  audit:
    enabled: true
    retention_days: 7
```

**Key design decisions:**
- HITL in `audit` mode: it logs that approval would be needed but doesn't pause execution
- DLP in `audit` mode: PII is logged but not blocked
- Short audit retention (7 days) — extend for compliance requirements
- Generous per-action spend limit ($10) — tighten for production

---

## `startup` — Balanced for Speed + Safety

For startups that need to move fast without breaking compliance. More permissive than enterprise, more structured than base.

**Governance level:** `balanced`
**Compliance references:** None specific
**Posture:** Audit-first with slightly more generous limits.

```yaml
governance_level: balanced

policies:
  odd:
    enforcement_mode: audit
    default_policy: allow

  magnitude:
    max_spend_per_action_usd: 20.00
    max_spend_per_session_usd: 100.00
    max_records_per_action: 200

  dlp:
    mode: audit

  hitl:
    mode: audit
    triggers:
      tool_types: [payment, execute]  # Only the riskiest types
    timeout_action: allow
    approval_timeout_minutes: 60

  intent_verification:
    mode: "off"

  circuit_breaker:
    agent_level:
      failure_threshold: 10           # More tolerant than enterprise
      time_window_seconds: 120
      recovery_timeout_seconds: 30

  audit:
    enabled: true
    retention_days: 30
```

**What's different from base:**
- HITL only triggers for `payment` and `execute` (not `write`)
- Higher magnitude limits per session ($100, 200 records)
- Longer circuit breaker tolerance (10 failures vs. 5)
- 30-day audit retention

**When to upgrade:** Run `drako upgrade --balanced` to enable DLP enforcement and ODD enforcement once you've reviewed the audit logs and tuned your permitted tools.

---

## `fintech` — Financial Services

For payment platforms, trading systems, and financial data processors.

**Governance level:** `strict`
**Compliance references:** MiFID II, PSD2, SOX, SEC Rule 15c3-5
**Posture:** Enforcement active. Default-deny for ODD. Cryptographic audit trail.

```yaml
governance_level: strict

policies:
  odd:
    enforcement_mode: enforce
    default_policy: deny          # Block unknown tools

  magnitude:
    max_spend_per_action_usd: 100.00
    max_spend_per_session_usd: 500.00
    max_records_per_action: 50

  dlp:
    mode: enforce
    sensitivity: high

  hitl:
    mode: enforce
    triggers:
      tool_types: [payment, write, execute]
      spend_above_usd: 50.00
      trust_score_below: 70
    timeout_action: reject        # Reject on timeout (safe default)
    approval_timeout_minutes: 15

  intent_verification:
    mode: enforce
    required_for:
      tool_types: [payment, write]
    anti_replay: true

  circuit_breaker:
    agent_level:
      failure_threshold: 3
      time_window_seconds: 60
      recovery_timeout_seconds: 120

  audit:
    enabled: true
    cryptographic: true           # SHA-256 hash chain + signatures
    retention_days: 365           # MiFID II: 5 years, SOX: 7 years — extend as needed
```

**Key design decisions:**
- `default_policy: deny` — agents can only use explicitly permitted tools
- Intent verification for all payment and write operations (anti-replay enabled)
- HITL triggers when session spend exceeds $50 or trust score drops below 70
- Cryptographic audit trail required for SOX/MiFID II evidence
- 15-minute approval window (short for financial operations)

**Compliance notes:**
- **MiFID II Art. 16**: Recordkeeping — covered by cryptographic audit trail
- **PSD2 SCA**: Strong Customer Authentication — configure HITL for payment tools
- **SOX Sec. 404**: Internal controls — ODD + HITL provide the control layer

---

## `healthcare` — HIPAA-Aligned

For healthcare applications processing Protected Health Information (PHI).

**Governance level:** `strict`
**Compliance references:** HIPAA Privacy Rule, HIPAA Security Rule, HITECH Act
**Posture:** Maximum DLP enforcement. Conservative trust thresholds. 6-year audit retention.

```yaml
governance_level: strict

policies:
  odd:
    enforcement_mode: enforce
    default_policy: deny

  magnitude:
    max_spend_per_action_usd: 50.00
    max_spend_per_session_usd: 200.00
    max_records_per_action: 25    # PHI minimum-necessary principle

  dlp:
    mode: enforce
    sensitivity: high

  hitl:
    mode: enforce
    triggers:
      tool_types: [write, execute]
      trust_score_below: 80       # Higher trust bar for PHI
    timeout_action: reject
    approval_timeout_minutes: 10  # Shorter window for PHI access

  intent_verification:
    mode: enforce
    required_for:
      tool_types: [write, execute]
    anti_replay: true

  circuit_breaker:
    agent_level:
      failure_threshold: 3
      time_window_seconds: 60
      recovery_timeout_seconds: 120

  audit:
    enabled: true
    cryptographic: true
    retention_days: 2190          # 6 years (HIPAA requirement)
```

**Key design decisions:**
- `max_records_per_action: 25` — enforces HIPAA minimum-necessary principle
- 6-year audit retention (2190 days) — HIPAA requires 6 years from creation or last effective date
- HITL trust threshold at 80 (higher than fintech) — PHI access requires higher confidence
- 10-minute HITL window — faster than financial (urgency in clinical contexts)
- Intent verification required for all write/execute operations

**Compliance notes:**
- **HIPAA § 164.312(b)**: Audit controls — covered by cryptographic audit trail
- **HIPAA § 164.502(b)**: Minimum necessary — covered by `max_records_per_action`
- **HIPAA § 164.308(a)(5)**: Training and access controls — covered by ODD + HITL
- **HITECH Act**: Breach notification readiness — audit trail provides evidence chain

---

## `eu-ai-act` — EU AI Act High-Risk Compliance

For AI systems classified as high-risk under EU AI Act (Regulation 2024/1689). High-risk rules take effect **August 2, 2026**.

**Governance level:** `strict`
**Compliance references:** EU AI Act Art. 9, 11, 12, 14; ISO 42001
**Posture:** Full enforcement. 10-year audit retention. All four Act articles covered.

```yaml
governance_level: strict

policies:
  odd:
    enforcement_mode: enforce
    default_policy: deny

  magnitude:
    max_spend_per_action_usd: 50.00
    max_spend_per_session_usd: 200.00
    max_records_per_action: 50

  dlp:
    mode: enforce
    sensitivity: high

  hitl:
    mode: enforce
    triggers:
      tool_types: [write, execute, payment]
      trust_score_below: 70
    timeout_action: reject
    approval_timeout_minutes: 30

  intent_verification:
    mode: enforce
    required_for:
      tool_types: [payment, write, execute]
    anti_replay: true

  circuit_breaker:
    agent_level:
      failure_threshold: 3
      time_window_seconds: 60
      recovery_timeout_seconds: 60

  audit:
    enabled: true
    cryptographic: true
    retention_days: 3650          # 10 years (EU AI Act Art. 12)
```

**EU AI Act Article Coverage:**

| Article | Requirement | Drako Implementation |
|---------|-------------|---------------------|
| Art. 9 | Risk management system | 80 scan rules, ODD enforcement, magnitude limits |
| Art. 11 | Technical documentation | Agent BOM, compliance reports, context versioning |
| Art. 12 | Record-keeping (10 years) | Cryptographic audit trail (`retention_days: 3650`) |
| Art. 14 | Human oversight | HITL checkpoints (`mode: enforce`, `timeout_action: reject`) |

Run `drako scan . --format compliance` to get a gap report against these four articles.

---

## `enterprise` — Maximum Governance

For large organizations with the strictest internal compliance posture. Includes A2A authentication and topology monitoring.

**Governance level:** `strict`
**Posture:** Everything enforced. Zero default-allow. Cryptographic trail. A2A secured.

```yaml
governance_level: strict

policies:
  odd:
    enforcement_mode: enforce
    default_policy: deny

  magnitude:
    max_spend_per_action_usd: 25.00
    max_spend_per_session_usd: 100.00
    max_records_per_action: 25
    enforcement_mode: enforce

  dlp:
    mode: enforce
    sensitivity: high

  hitl:
    mode: enforce
    triggers:
      tool_types: [write, execute, payment, network]
      trust_score_below: 80
      spend_above_usd: 10.00
    timeout_action: reject
    approval_timeout_minutes: 15

  intent_verification:
    mode: enforce
    required_for:
      tool_types: [payment, write, execute]
    anti_replay: true
    intent_ttl_seconds: 120       # Shorter token TTL

  circuit_breaker:
    agent_level:
      failure_threshold: 3
      time_window_seconds: 60
      recovery_timeout_seconds: 180

  audit:
    enabled: true
    cryptographic: true
    retention_days: 365

  a2a:
    mode: enforce
    auth:
      method: did_exchange
      auto_rotate: true
      rotation_hours: 12           # Rotate credentials every 12h

  topology:
    enabled: true
```

**What's unique to enterprise:**
- HITL triggers for `network` tool type (not just write/execute/payment)
- A2A authentication enforced (DID-based credential exchange)
- Credential auto-rotation every 12 hours
- Topology monitoring enabled (circular dependency, resource contention detection)
- Shorter intent TTL (120s vs. 300s)
- HITL spend trigger at $10 (very tight)

---

## Template Inheritance

Templates support layering. You can extend a template and then override specific sections:

```yaml
# Start from healthcare, but relax the audit retention for dev environments
extends: healthcare
governance_level: balanced

policies:
  audit:
    retention_days: 30    # Override: healthcare default is 2190

  hitl:
    mode: audit           # Override: healthcare default is enforce
```

Deep-merge rules:
- Scalar values (`mode`, `retention_days`) are replaced by your override
- Lists (`permitted_tools`, `trigger_types`) are replaced entirely — not appended
- Nested objects are merged recursively

To see the resolved config after inheritance:

```bash
drako templates show healthcare   # Raw template
drako config show                 # Your resolved .drako.yaml after inheritance
```
