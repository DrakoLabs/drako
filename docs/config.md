# Configuration Reference

Drako is configured via a `.drako.yaml` file in your project root. Generate an initial config from your scan results:

```bash
drako init                         # autopilot (audit-first, smart defaults)
drako init --balanced              # enforcement active
drako init --strict                # maximum governance
drako init --template fintech      # start from an industry template
```

See [Policy Templates →](policy-templates.md) for available industry presets.

---

## Top-Level Fields

```yaml
version: "1.0"                     # Config schema version
governance_level: autopilot        # autopilot | balanced | strict | custom
extends: fintech                   # Inherit from a policy template (optional)
tenant_id: your_tenant_id          # Required for runtime enforcement
api_key_env: DRAKO_API_KEY         # Env var name for the API key (default: DRAKO_API_KEY)
endpoint: https://api.getdrako.com # Drako API endpoint
framework: crewai                  # crewai | langgraph | autogen | generic
```

### `governance_level`

Controls how Drako upgrades during `drako upgrade`:

| Level | Behavior |
|-------|----------|
| `autopilot` | Audit mode. Logs all violations, blocks nothing. Upgrade path: → balanced → strict |
| `balanced` | DLP enforce, ODD enforce, HITL rejects on timeout |
| `strict` | + intent verification, cryptographic audit, magnitude enforce |
| `custom` | No managed upgrade path. You control every field. |

### `extends`

Inherit all policy settings from a named template, then override only what you need:

```yaml
extends: fintech
governance_level: balanced

# Override just this one setting:
policies:
  hitl:
    approval_timeout_minutes: 60
```

Available templates: `base` · `startup` · `fintech` · `healthcare` · `eu-ai-act` · `enterprise`

### API Key Resolution

Priority order:
1. Environment variable named by `api_key_env` (default: `DRAKO_API_KEY`)
2. `api_key` field stored directly in `.drako.yaml`

For CI/CD, set `DRAKO_API_KEY` as a secret and leave `api_key` out of the YAML.

---

## `agents`

Declare the agents in your project. Populated automatically by `drako init`:

```yaml
agents:
  researcher:
    source: agents/researcher.py
    description: "Searches the web and reads documents"
  writer:
    source: agents/writer.py
    description: "Drafts reports and sends emails"
```

| Field | Type | Description |
|-------|------|-------------|
| `source` | `string` | Path to the agent's source file |
| `description` | `string` | Human-readable description (optional) |

---

## `tools`

Declare tools and their access types. Used for ODD enforcement and scan reporting:

```yaml
tools:
  web_search:
    type: read
  file_reader:
    type: read
  send_email:
    type: write
  code_runner:
    type: execute
  pay_invoice:
    type: payment
```

| Type | Risk Level | Description |
|------|-----------|-------------|
| `read` | Low | Read-only operations |
| `write` | Medium | Creates or modifies data |
| `execute` | High | Runs code or shell commands |
| `network` | Medium | Makes external HTTP calls |
| `payment` | Critical | Initiates financial transactions |

---

## `policies`

### `odd` — Operator-Defined Domains

Restrict which tools each agent can use.

```yaml
policies:
  odd:
    enforcement_mode: audit      # audit | enforce | off
    default_policy: allow        # allow | deny (applies when no agent rule matches)
    agents:
      researcher:
        permitted_tools: [web_search, file_reader]
        forbidden_tools: [code_runner, send_email]
      writer:
        permitted_tools: [send_email, file_reader]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enforcement_mode` | `string` | `audit` | `audit` logs violations; `enforce` blocks them |
| `default_policy` | `string` | `allow` | What to do when no agent rule matches |
| `agents.<name>.permitted_tools` | `list[string]` | `[]` | Whitelist — any tool not listed is blocked |
| `agents.<name>.forbidden_tools` | `list[string]` | `[]` | Blacklist — listed tools are always blocked |

If both `permitted_tools` and `forbidden_tools` are set, `forbidden_tools` takes precedence.

---

### `dlp` — Data Loss Prevention

Scan tool inputs and outputs for PII/PCI data.

```yaml
policies:
  dlp:
    mode: enforce        # audit | enforce | off
    sensitivity: high    # low | medium | high
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `string` | `audit` | `audit` logs; `enforce` blocks the call |
| `sensitivity` | `string` | `medium` | DLP sensitivity level (affects false positive rate) |

Detected entity types (Presidio-based): SSN, credit card numbers, email addresses, phone numbers, passport numbers, and more.

---

### `circuit_breaker` — Per-Agent Fault Isolation

Prevents one failing agent from cascading failures to the rest of the system.

```yaml
policies:
  circuit_breaker:
    agent_level:
      failure_threshold: 5        # Open circuit after N failures
      time_window_seconds: 60     # Sliding window
      recovery_timeout_seconds: 30 # How long to wait before half-opening
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | `int` | `10` | Number of failures before opening the circuit |
| `time_window_seconds` | `int` | `300` | Sliding window for failure counting |
| `recovery_timeout_seconds` | `int` | `60` | Cooldown before allowing trial requests |

---

### `hitl` — Human-in-the-Loop

Pause agent execution and require human approval before proceeding. EU AI Act Art. 14.

```yaml
policies:
  hitl:
    mode: enforce                  # audit | enforce | off
    triggers:
      tool_types: [write, execute, payment]
      tools: [delete_database, send_wire_transfer]
      trust_score_below: 60
      spend_above_usd: 100.00
      records_above: 1000
      first_time_tool: false
      first_time_action: false
    notification:
      webhook_url: https://hooks.slack.com/...
      email: ops@yourcompany.com
    approval_timeout_minutes: 30
    timeout_action: reject         # reject | allow
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `string` | `off` | `enforce` pauses execution; `audit` logs without pausing |
| `triggers.tool_types` | `list[string]` | `[]` | Trigger HITL for any tool of these types |
| `triggers.tools` | `list[string]` | `[]` | Trigger HITL for specific named tools |
| `triggers.trust_score_below` | `float\|null` | `null` | Trigger when agent trust score drops below this value |
| `triggers.spend_above_usd` | `float\|null` | `null` | Trigger when session spend exceeds this amount |
| `triggers.records_above` | `int\|null` | `null` | Trigger when a tool accesses more than N records |
| `triggers.first_time_tool` | `bool` | `false` | Trigger on first-ever use of any tool |
| `triggers.first_time_action` | `bool` | `false` | Trigger on first action in a new session |
| `approval_timeout_minutes` | `int` | `30` | How long to wait for human response |
| `timeout_action` | `string` | `reject` | What to do if no response: `reject` (safe) or `allow` (permissive) |

---

### `magnitude` — Spend and Action Limits

Cap how much an agent can do in a single action or session.

```yaml
policies:
  magnitude:
    max_spend_per_action_usd: 10.00
    max_spend_per_session_usd: 100.00
    max_records_per_action: 50
    enforcement_mode: enforce       # audit | enforce
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_spend_per_action_usd` | `float` | — | Max cost of a single tool call |
| `max_spend_per_session_usd` | `float` | — | Max cumulative session spend |
| `max_records_per_action` | `int` | — | Max records returned by a single tool call |
| `enforcement_mode` | `string` | `audit` | `enforce` blocks calls that exceed limits |

---

### `audit` — Audit Trail

Configure the tamper-evident audit log.

```yaml
policies:
  audit:
    enabled: true
    cryptographic: true            # SHA-256 hash chain + Ed25519 signatures
    retention_days: 365
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable audit logging |
| `cryptographic` | `bool` | `false` | Enable SHA-256 hash chain + digital signatures |
| `retention_days` | `int` | `7` | How long to retain audit records |

---

### `intent_verification` — Anti-Replay Protection

Require a signed intent token before allowing high-risk tool calls. Prevents prompt injection from hijacking approved actions.

```yaml
policies:
  intent_verification:
    mode: enforce                  # audit | enforce | off
    required_for:
      tool_types: [payment, write, execute]
      tools: [delete_record]
    anti_replay: true
    intent_ttl_seconds: 300
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `string` | `off` | `enforce` blocks calls without valid intent token |
| `required_for.tool_types` | `list[string]` | `[payment, write, execute]` | Tool types that require intent tokens |
| `anti_replay` | `bool` | `true` | Reject reused intent tokens |
| `intent_ttl_seconds` | `int` | `300` | Token validity window |

---

### `hooks` — Programmable Hooks

Run custom scripts at governance checkpoints.

```yaml
policies:
  hooks:
    pre_action:
      - name: validate_input
        condition: "tool_type == 'execute'"
        script: scripts/validate.py
        timeout_ms: 5000
        action_on_fail: block   # block | allow
        priority: 0
    post_action:
      - name: log_to_siem
        script: scripts/siem_export.py
    on_error:
      - name: alert_oncall
        script: scripts/alert.py
    on_session_end:
      - name: cost_report
        script: scripts/cost_report.py
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | — | Hook identifier |
| `condition` | `string\|null` | `null` | Expression that must be true to trigger the hook |
| `script` | `string\|null` | `null` | Path to the hook script |
| `timeout_ms` | `int` | `5000` | Max execution time before the hook is skipped |
| `action_on_fail` | `string` | `allow` | `block` or `allow` when hook fails or times out |
| `priority` | `int` | `0` | Execution order when multiple hooks match (lower runs first) |

---

### `finops` — Agentic Cost Management

Track, route, cache, and budget LLM spending.

```yaml
policies:
  finops:
    tracking:
      enabled: true
      model_costs:
        gpt-4o:
          input: 0.0025
          output: 0.01
    routing:
      enabled: true
      default_model: gpt-4o
      rules:
        - condition: "task_complexity == 'low'"
          model: gpt-4o-mini
          reason: "Use cheaper model for simple tasks"
    cache:
      enabled: true
      similarity_threshold: 0.92
      ttl_hours: 24
    budgets:
      daily_usd: 50.00
      weekly_usd: 250.00
      monthly_usd: 1000.00
      alert_at_percent: [50, 80, 95]
```

---

### `a2a` — Secure Agent-to-Agent Communication

Authenticate and authorize inter-agent message passing. Enterprise feature.

```yaml
policies:
  a2a:
    mode: enforce                  # audit | enforce | off
    auth:
      method: did_exchange         # did_exchange | mtls | shared_secret
      auto_rotate: true
      rotation_hours: 24
    channels:
      - from: researcher
        to: writer
        allowed_message_types: [task_result, context_update]
        max_payload_size_kb: 500
        require_intent_verification: false
      - from: "*"
        to: payment_agent
        policy: deny               # Explicit deny rule
    worm_detection:
      enabled: true
      scan_inter_agent_messages: true
      max_propagation_depth: 3
      circular_reference_block: true
```

---

### `topology` — Multi-Agent Topology Monitoring

Detect dangerous interaction patterns between agents. Enterprise feature.

```yaml
policies:
  topology:
    enabled: true
    conflict_detection:
      resource_contention: true
      contradictory_actions: true
      cascade_amplification: true
      resource_exhaustion: true
    alert_on:
      - circular_dependency
      - resource_contention
```

---

### `fallback` — Deterministic Fallback

Define what to do when a tool fails or a circuit breaker opens.

```yaml
policies:
  fallback:
    mode: enforce                  # audit | enforce | off
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

### `chaos` — Chaos Engineering

Inject controlled failures to test fallback and recovery behavior. Enterprise feature.

```yaml
policies:
  chaos:
    safety:
      max_blast_radius: 1
      auto_rollback_on_failure: true
      require_approval: true
    experiments:
      - name: web_search_latency
        description: "Simulate slow search API"
        target_tool: web_search
        fault_type: latency
        latency_ms: 2000
        duration_seconds: 60
      - name: deny_code_runner
        target_tool: code_runner
        fault_type: tool_deny
        duration_seconds: 120
```

---

## Complete Example

```yaml
version: "1.0"
governance_level: balanced
tenant_id: ten_abc123
api_key_env: DRAKO_API_KEY
framework: crewai

agents:
  researcher:
    source: agents/researcher.py
  writer:
    source: agents/writer.py

tools:
  web_search:
    type: read
  file_reader:
    type: read
  send_email:
    type: write
  code_runner:
    type: execute

policies:
  odd:
    enforcement_mode: enforce
    default_policy: deny
    agents:
      researcher:
        permitted_tools: [web_search, file_reader]
      writer:
        permitted_tools: [send_email, file_reader]

  dlp:
    mode: enforce

  hitl:
    mode: enforce
    triggers:
      tool_types: [write, execute, payment]
      spend_above_usd: 100.00
    timeout_action: reject
    approval_timeout_minutes: 30

  circuit_breaker:
    agent_level:
      failure_threshold: 5
      time_window_seconds: 60
      recovery_timeout_seconds: 30

  audit:
    enabled: true
    cryptographic: true
    retention_days: 90

  finops:
    tracking:
      enabled: true
    budgets:
      daily_usd: 20.00
      alert_at_percent: [80, 95]
```
