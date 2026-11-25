# Policy Templates

Drako v4 ships six local-first, flat-schema governance presets. Start from a template and override only what your project needs.

```bash
drako templates                   # list available templates (alias for `drako templates list`)
drako templates show fintech      # preview full v4 template YAML
drako init --template healthcare  # initialize .drako.yaml inheriting a template
drako validate .drako.yaml        # resolve `extends:` and validate merged config
```

Templates use flat top-level v4 keys matching `DrakoConfig`. Layer your overrides directly at the top level:

```yaml
# .drako.yaml
version: "4.0"
project_id: payments-agent
extends: fintech

# Override only this field:
hitl:
  approval_timeout_minutes: 30
```

---

## Summary Matrix

| Template | Posture | `kernel.default_effect` | `dlp.mode` | `hitl.mode` | `a2a.mode` | `audit.retention_days` |
|---|---|---|---|---|---|---|
| `base` | `autopilot` | `permit` | `audit` | `audit` | `audit` | `7` |
| `startup` | `balanced` | `deny` | `audit` | `audit` | `audit` | `30` |
| `fintech` | `strict` | `deny` | `enforce` | `enforce` | `enforce` | `365` |
| `healthcare` | `strict` | `deny` | `enforce` | `enforce` | `enforce` | `2190` (6 yrs) |
| `eu-ai-act` | `strict` | `deny` | `enforce` | `enforce` | `enforce` | `3650` (10 yrs) |
| `enterprise` | `strict` | `deny` | `enforce` | `enforce` | `enforce` | `365` |

---

## `base` — Recommended Defaults

Audit-first starter baseline for exploration or initial rollout.

- `governance_level: autopilot`, `kernel.default_effect: permit`
- `dlp.mode: audit`, `hitl.mode: audit` (`timeout_action: allow`, `approval_timeout_minutes: 30`)
- `loop_breaker.trip_threshold: 15`, `finops.budgets.daily_usd: 50.0`
- `audit.cryptographic: true`, `retention_days: 7`
- `mcp.enforce_pin: true`, `a2a.require_signed_cards: true`

---

## `startup` — Balanced for Speed + Safety

Fail-closed kernel defaults with low-friction HITL triggers (`payment`, `execute`).

- `governance_level: balanced`, `kernel.default_effect: deny`
- `dlp.mode: audit`, `hitl.mode: audit` (`tool_types: [payment, execute]`, `approval_timeout_minutes: 60`)
- `loop_breaker.trip_threshold: 10`, `finops.budgets.daily_usd: 100.0`
- `audit.cryptographic: true`, `retention_days: 30`

Upgrade to strict enforcement at any time with `drako upgrade --strict`.

---

## `fintech` — Financial Services

Aligned with MiFID II, PSD2, SOX, and SEC Rule 15c3-5 controls.

- `governance_level: strict`, `kernel.default_effect: deny` (`write`, `external_comms`, `irreversible` require `consent`)
- `dlp.mode: enforce`, `hitl.mode: enforce` (`tool_types: [payment, write, execute]`, `spend_above_usd: 50.0`, `trust_score_below: 70`, `timeout_action: reject`, `approval_timeout_minutes: 15`)
- `intent_verification.mode: enforce` (`anti_replay: true`)
- `a2a.mode: enforce` (`require_signed_cards: true`, `worm_detection.enabled: true`)
- `audit.cryptographic: true`, `retention_days: 365`, `finops.budgets.daily_usd: 100.0`

---

## `healthcare` — HIPAA-Aligned

Aligned with the HIPAA Privacy Rule, Security Rule, and HITECH Act.

- `governance_level: strict`, `kernel.default_effect: deny`
- `dlp.mode: enforce`, `hitl.mode: enforce` (`tool_types: [write, execute]`, `trust_score_below: 80`, `records_above: 25`, `approval_timeout_minutes: 10`, `timeout_action: reject`)
- `intent_verification.mode: enforce` (`anti_replay: true`)
- `audit.cryptographic: true`, `retention_days: 2190` (6-year HIPAA retention)
- `a2a.mode: enforce` (`require_signed_cards: true`, `worm_detection.enabled: true`)

---

## `eu-ai-act` — EU AI Act High-Risk Compliance

Aligned with EU AI Act (Regulation 2024/1689), Digital Omnibus enforcement dates (`2026-08-02` Art. 50 transparency, `2027-12-02` Annex III, `2028-08-02` Annex I), and ISO 42001.

- `governance_level: strict`, `kernel.default_effect: deny`
- `dlp.mode: enforce`, `hitl.mode: enforce` (`tool_types: [write, execute, payment]`, `trust_score_below: 70`, `timeout_action: reject`)
- `intent_verification.mode: enforce` (`anti_replay: true`)
- `audit.cryptographic: true`, `retention_days: 3650` (10-year Art. 12 recordkeeping)
- `a2a.mode: enforce` (`require_signed_cards: true`, `worm_detection.enabled: true`)

Generate an offline compliance evidence bundle with `drako comply generate --all`.

---

## `enterprise` — Maximum Governance

Strictest local-first posture across all enforcement surfaces:

- `governance_level: strict`, `kernel.default_effect: deny`
- `dlp.mode: enforce`, `hitl.mode: enforce` (`tool_types: [write, execute, payment, network]`, `spend_above_usd: 10.0`, `trust_score_below: 80`, `records_above: 25`, `timeout_action: reject`)
- `intent_verification.mode: enforce` (`intent_ttl_seconds: 120`, `anti_replay: true`)
- `a2a.mode: enforce` (`require_signed_cards: true`, `worm_detection.block_suspicious: true`)
- `mcp.enforce_pin: true`, `mcp.allow_auto_install: false`
- `loop_breaker.trip_threshold: 5`, `audit.cryptographic: true`, `retention_days: 365`

---

## Template Inheritance

Deep-merge rules when `DrakoConfig.load()` or `drako validate` resolves `extends:`:

- Scalar fields (`mode`, `retention_days`, `default_effect`) are replaced by your override.
- Lists (`tool_types`, `allowed_domains`) are replaced by your override.
- Nested mappings (`hitl`, `kernel`, `audit`, `a2a`) are merged recursively.

Inspect raw presets and validate your merged config offline:

```bash
drako templates show healthcare
drako validate .drako.yaml
```
