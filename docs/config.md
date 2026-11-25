# Configuration Reference (`.drako.yaml` v4)

Drako v4 is configured via a flat, local-first `.drako.yaml` file in your repository root and an optional ACS policy profile (`drako-policy.yaml`, spec pin `AGENT-HOOKS-0.1`). Everything runs 100% offline with zero network calls and zero API keys.

Generate an initial configuration automatically from live offline discovery:

```bash
drako init                          # balanced (fail-closed defaults)
drako init --level autopilot        # audit-first starter posture
drako init --level strict           # maximum fail-closed governance
drako init --template fintech       # inherit from an industry preset
drako validate .drako.yaml          # verify schema, template inheritance, and ACS profile
```

See [Policy Templates →](policy-templates.md) for all six built-in presets, and `schema/drako-config.schema.json` for the generated JSON Schema.

---

## Top-Level Fields

```yaml
version: "4.0"                      # Config schema version
project_id: my-agent-service        # Local project identifier
governance_level: balanced          # autopilot | balanced | strict | custom
extends: fintech                    # Optional policy template to inherit
framework: langgraph                # Detected or declared framework
```

### `governance_level`

Controls default enforcement posture and `drako upgrade` transitions:

| Level | Behavior |
|-------|----------|
| `autopilot` | Audit-first starter posture (`kernel.default_effect: permit`). |
| `balanced` | Fail-closed default (`kernel.default_effect: deny`), consent tier for irreversible tools. |
| `strict` | Full fail-closed enforcement: DLP enforce, HITL reject on timeout, intent anti-replay, signed A2A cards, cryptographic receipts. |
| `custom` | User-managed configuration with no automatic posture changes. |

### `extends`

Inherit all top-level v4 settings from a built-in template, then override only what you need:

```yaml
version: "4.0"
project_id: payments-agent
extends: fintech

# Override a single field cleanly (no `policies:` wrapper in v4):
hitl:
  approval_timeout_minutes: 30
```

Available templates: `base` · `startup` · `fintech` · `healthcare` · `eu-ai-act` · `enterprise`.

---

## `kernel` — Authority Kernel (`AGENT-HOOKS-0.1`)

Configures deterministic local enforcement, ACS profile loading, operator consent verification, and hash-chained Ed25519 receipts.

```yaml
kernel:
  spec_pin: AGENT-HOOKS-0.1
  default_effect: deny              # deny (fail-closed) | permit
  profile_path: drako-policy.yaml   # External ACS policy profile
  receipt_store: .drako/receipts.jsonl
  operator_pubkey_path: .drako/keys/op.pub
  tiers:
    read: auto
    write: audit
    external_comms: audit
    irreversible: consent
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec_pin` | `string` | `AGENT-HOOKS-0.1` | Conformance specification pin |
| `default_effect` | `string` | `deny` | `deny` (fail-closed) or `permit` |
| `profile_path` | `string\|null` | `null` | Path to `drako-policy.yaml` compiled by `guardian_from_yaml()` |
| `receipt_store` | `string` | `.drako/receipts.jsonl` | Local append-only Ed25519 receipt log |
| `operator_pubkey_path` | `string\|null` | `null` | Operator public key PEM used to verify `ConsentToken` signatures |
| `tiers` | `dict[str, str]` | read/write/external_comms/irreversible | Default authority tier per side-effect class |

---

## `loop_breaker` — Runaway Repetition Circuit-Breaker

Protects against infinite tool loops and prompt-induced amplification (OWASP ASI08 / ASI10).

```yaml
loop_breaker:
  enabled: true
  trip_threshold: 10
  window_seconds: 300.0
```

---

## `mcp` — MCP Supply-Chain & Runtime Guard

Controls `mcp.lock` hash-pinning (`drako mcp pin`, `drako mcp audit`) and stateless MCP `2026-07-28` GA client posture.

```yaml
mcp:
  lockfile: mcp.lock
  enforce_pin: true
  env_allowlist: []
  allow_auto_install: false
  protocol_version: "2026-07-28"
```

---

## `egress` — Outbound Network SSRF Guard

Enforced by `drako.kernel.egress.assert_public_url()` across MCP clients, A2A Agent Card fetches, and the local proxy. Private, loopback, and link-local ranges are always denied fail-closed.

```yaml
egress:
  allowed_domains:
    - api.openai.com
    - api.anthropic.com
```

---

## `a2a` — Agent-to-Agent Communication (A2A v1.0 JWS)

Authenticates inter-agent delegation with detached RFC 7515 EdDSA JWS signatures (`drako a2a sign` / `drako a2a verify`) and constrains inter-agent channels.

```yaml
a2a:
  mode: enforce                     # audit | enforce | off
  require_signed_cards: true
  trusted_pubkeys_dir: .drako/keys/peers
  channels:
    - from: researcher
      to: writer
      allowed_message_types: [task_result, context_update]
      max_payload_size_kb: 500
      require_intent_verification: false
    - from: "*"
      to: payment_agent
      policy: deny
  worm_detection:
    enabled: true
    scan_inter_agent_messages: true
    max_propagation_depth: 3
    circular_reference_block: true
    block_suspicious: false
```

---

## `proxy` — Local Enforcement Proxy

Configures default bind address and CORS allowlist for `drako proxy start` / `python -m drako.proxy`.

```yaml
proxy:
  host: 127.0.0.1                   # Loopback-only by default
  port: 8990
  cors_origins:
    - http://localhost:3000
```

Evidence endpoints (`/status`, `/audit`) require `DRAKO_PROXY_TOKEN` bearer authentication. See [Proxy Mode →](proxy-mode.md).

---

## `audit` — Cryptographic Audit Trail

```yaml
audit:
  enabled: true
  cryptographic: true               # SHA-256 hash chain + Ed25519 signatures
  receipt_store: .drako/receipts.jsonl
  retention_days: 90
```

Verify offline with `drako verify .drako/receipts.jsonl --pubkey-file <pub.pem>`.

---

## `dlp` — Data Loss Prevention

```yaml
dlp:
  mode: enforce                     # audit | enforce | off
```

---

## `hitl` — Human-in-the-Loop Oversight (EU AI Act Art. 14)

```yaml
hitl:
  mode: enforce                     # audit | enforce | off
  triggers:
    tool_types: [write, execute, payment]
    tools: [delete_database, send_wire_transfer]
    trust_score_below: 70
    spend_above_usd: 100.0
    records_above: 1000
    first_time_tool: false
    first_time_action: false
  approval_timeout_minutes: 30
  timeout_action: reject            # reject | allow
```

---

## `intent_verification` — Anti-Replay Protection

```yaml
intent_verification:
  mode: enforce                     # audit | enforce | off
  required_for:
    tool_types: [payment, write, execute]
    tools: [delete_record]
  anti_replay: true
  intent_ttl_seconds: 300
```

---

## `circuit_breaker` — Per-Agent Fault Isolation

```yaml
circuit_breaker:
  agent_level:
    failure_threshold: 5
    time_window_seconds: 300
    recovery_timeout_seconds: 60
```

---

## `finops` — Cost Tracking & Budgets

```yaml
finops:
  tracking:
    enabled: true
    model_costs:
      gpt-4o:
        input: 0.0025
        output: 0.01
  budgets:
    daily_usd: 50.0
    weekly_usd: 250.0
    monthly_usd: 1000.0
    alert_at_percent: [50, 80, 95]
```

---

## `hooks` — Programmable Lifecycle Hooks

```yaml
hooks:
  pre_action:
    - name: validate_input
      condition: "tool_type == 'execute'"
      script: scripts/validate.py
      timeout_ms: 5000
      action_on_fail: block         # block | allow
      priority: 0
  post_action:
    - name: export_receipt
      script: scripts/export.py
  on_error: []
  on_session_end:
    - name: verify_receipts
      script: scripts/verify.py
      timeout_ms: 10000
      action_on_fail: block
```

---

## `fallback` — Deterministic Fallback

```yaml
fallback:
  mode: enforce                     # audit | enforce | off
  tools:
    web_search:
      fallback_agent: researcher_backup
      fallback_action: escalate_human
      triggers: [circuit_breaker_open]
  default:
    fallback_action: escalate_human
    preserve_state: true
    state_ttl_hours: 24
```

---

## `agents` and `detected_tools`

Populated automatically by `drako init` from live offline AST discovery:

```yaml
agents:
  researcher:
    source: agents/researcher.py
    description: "Searches documentation and summarizes findings"

detected_tools:
  search_docs:
    source: tools/search.py
    type: read                      # read | write | execute | network | payment
  write_report:
    source: tools/fs.py
    type: write
```

---

## Migrating from v3

If your repository still has legacy v3 keys (`api_key`, `api_key_env`, `endpoint`, `governance`, `bft`, `chaos`, `topology`), run the idempotent offline migrator:

```bash
drako upgrade --v4
drako validate .drako.yaml
```
