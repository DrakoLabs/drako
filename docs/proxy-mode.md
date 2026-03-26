# Proxy Mode

The Drako proxy is an out-of-process enforcement layer. It intercepts LLM API calls at the network level — before they reach OpenAI or Anthropic — and runs the governance pipeline without any changes to your agent code.

Because the proxy runs as a separate process, the agent cannot bypass it by modifying its own code at runtime.

---

## How It Works

```
Agent process
  └─ makes HTTP call to OpenAI/Anthropic
       └─ intercepted by Drako Proxy (localhost:8990)
            ├─ 1. Resolve target API (openai / anthropic)
            ├─ 2. Parse request body
            ├─ 3. Extract agent ID + tool name from headers/body
            ├─ 4. Run governance pipeline:
            │     ├─ ODD check  (forbidden/permitted tools)
            │     ├─ Magnitude  (rate limiting per agent)
            │     ├─ DLP        (PII/PCI scanning)
            │     └─ HITL       (human approval gate)
            ├─ 5. Forward to real API (if allowed)
            ├─ 6. Track cost from response usage
            └─ 7. Return response + governance headers
```

Blocked requests never reach the upstream API. The proxy returns a `403` (ODD/DLP violation), `429` (magnitude exceeded), or `202` (HITL pending approval).

---

## Quick Start

```bash
# Install proxy extras
pip install 'drako[proxy]'

# Start the proxy (default port 8990)
drako proxy start

# Point your agent at the proxy
export OPENAI_BASE_URL=http://localhost:8990/openai/v1
export ANTHROPIC_BASE_URL=http://localhost:8990/anthropic/v1
```

That's it. No code changes in your agent. All existing OpenAI/Anthropic SDK calls route through the proxy automatically when the base URL is set.

### Custom Port

```bash
drako proxy start --port 9000
export OPENAI_BASE_URL=http://localhost:9000/openai/v1
```

---

## Supported Backends

| Backend | Env Var | Proxy Path Prefix |
|---------|---------|-------------------|
| OpenAI | `OPENAI_BASE_URL` | `/openai/` |
| Anthropic | `ANTHROPIC_BASE_URL` | `/anthropic/` |

Any path not matching a known prefix returns HTTP 400.

---

## Agent Identity

The proxy reads the `X-Drako-Agent` request header to identify which agent is making the call. This is required for ODD (per-agent tool permissions) and per-agent magnitude limits.

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8990/openai/v1",
    default_headers={"X-Drako-Agent": "researcher"},
)
```

If the header is absent, the proxy logs as `agent=unknown` and ODD checks are skipped (since no agent-specific rules apply).

---

## Governance Pipeline

### ODD (Operator-Defined Domains)

Checks whether the tool being called is permitted for this agent, based on `.drako.yaml`:

```yaml
policies:
  odd:
    enforcement_mode: enforce   # audit | enforce | off
    agents:
      researcher:
        permitted_tools: [web_search, file_reader]
        forbidden_tools: [code_runner, shell_exec]
```

- `enforcement_mode: audit` — logs violations, allows the call
- `enforcement_mode: enforce` — blocks the call, returns HTTP 403

The tool name is extracted from the request body (`function_call`, `tool_choice`, or `tool_calls` in the last assistant message).

### Magnitude (Rate Limiting)

Tracks actions per agent per minute:

```yaml
policies:
  magnitude:
    max_actions_per_minute: 60
    enforcement_mode: enforce   # audit | enforce
```

Exceeding the limit returns HTTP 429.

### DLP (Data Loss Prevention)

Scans the request payload (all messages) for PII patterns:

| Pattern | What It Detects |
|---------|----------------|
| `SSN` | `\d{3}-\d{2}-\d{4}` |
| `credit_card` | 16-digit card numbers (with spaces/dashes) |
| `email_pii` | Email addresses |

```yaml
policies:
  dlp:
    mode: enforce   # audit | enforce | off
```

- `mode: audit` — logs PII detection, forwards the call
- `mode: enforce` — blocks the call, returns HTTP 403

### HITL (Human-in-the-Loop)

Holds specific tool calls for human approval:

```yaml
policies:
  hitl:
    mode: enforce
    triggers:
      tools: [delete_file, send_email, execute_payment]
    timeout_action: reject   # reject | allow
    approval_timeout_minutes: 30
```

When a matching tool call arrives, the proxy returns HTTP 202 with an `approval_id`. The agent must poll the approval endpoint or implement a callback.

---

## Configuration

The proxy reads `.drako.yaml` at startup. It searches the current directory and walks up to the filesystem root until it finds the file.

```yaml
# .drako.yaml
governance_level: balanced

policies:
  odd:
    enforcement_mode: enforce
    agents:
      researcher:
        permitted_tools: [web_search, file_reader]
  dlp:
    mode: enforce
  magnitude:
    max_actions_per_minute: 120
    enforcement_mode: audit
  hitl:
    mode: off
```

Changes to `.drako.yaml` require a proxy restart.

---

## Monitoring Endpoints

The proxy exposes three read-only HTTP endpoints:

### `GET /health`

```json
{
  "status": "healthy",
  "governance_level": "balanced",
  "targets": ["openai", "anthropic"],
  "audit_entries": 42
}
```

### `GET /status`

Detailed proxy status including session statistics (per-agent cost totals, action counts).

### `GET /audit`

Last 100 audit log entries:

```json
{
  "entries": [
    {
      "timestamp": "2026-03-26T10:00:00Z",
      "agent_id": "researcher",
      "tool_name": "web_search",
      "model": "gpt-4o",
      "decision": "allowed",
      "reason": null,
      "latency_ms": 1.2,
      "cost_usd": 0.000031,
      "upstream_status": 200
    }
  ]
}
```

Decisions: `allowed` · `rejected` · `pending_approval`

### Response Headers

Every proxied response includes:

| Header | Value |
|--------|-------|
| `X-Drako-Proxy` | `true` |
| `X-Drako-Latency-Ms` | Round-trip latency in milliseconds |
| `X-Drako-Cost-USD` | Estimated cost (when model pricing is known) |

---

## Docker

```bash
docker run -d \
  -p 8990:8990 \
  -v $(pwd)/.drako.yaml:/app/.drako.yaml:ro \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  angelnicolasc/drako-proxy:latest
```

### docker-compose

```yaml
services:
  drako-proxy:
    image: angelnicolasc/drako-proxy:latest
    ports:
      - "8990:8990"
    volumes:
      - ./.drako.yaml:/app/.drako.yaml:ro
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

  my-agent:
    build: .
    environment:
      - OPENAI_BASE_URL=http://drako-proxy:8990/openai/v1
    depends_on:
      - drako-proxy
```

### Kubernetes / Helm

See [`deploy/helm/`](../deploy/) for the `drako-proxy` Helm chart. The chart deploys the proxy as a sidecar or standalone service with a ConfigMap for `.drako.yaml`.

---

## Cost Tracking

The proxy estimates cost from the `usage` field in each API response. Supported models:

**OpenAI**

| Model | Input ($/1K tokens) | Output ($/1K tokens) |
|-------|--------------------|--------------------|
| gpt-5.4 | $0.0025 | $0.015 |
| gpt-5.4-mini | $0.00075 | $0.0045 |
| gpt-5.4-nano | $0.0002 | $0.00125 |
| gpt-5.4-pro | $0.03 | $0.18 |

**Anthropic**

| Model | Input ($/1K tokens) | Output ($/1K tokens) |
|-------|--------------------|--------------------|
| claude-opus-4-6 | $0.005 | $0.025 |
| claude-sonnet-4-6 | $0.003 | $0.015 |
| claude-haiku-4-5 | $0.001 | $0.005 |

_Precios actualizados a marzo 2026. Pueden cambiar. El proxy usa siempre el campo `usage` que devuelve el proveedor._

Per-agent cumulative cost is tracked in memory for the session lifetime and visible at `GET /status`.

---

## Limitations

- **In-memory state only.** Audit log, session stats, and cost totals are reset on proxy restart. For persistent audit trails, use the SDK runtime middleware with a Drako account.
- **Proxy, not SDK.** HITL approvals in proxy mode require your own callback or polling implementation. The SDK middleware provides a built-in approval UI and webhook integration.
- **Single-process scope.** The proxy governs one agent process at a time (or multiple agents pointing to the same proxy instance). Multi-tenant scenarios require separate proxy instances.
- **Tool name extraction.** The proxy extracts tool names from the OpenAI `function_call` / `tool_calls` format. Custom tool invocation formats may not be detected.
- **No intent verification.** Intent fingerprinting (anti-replay, intent TTL) is available only via the SDK runtime, not the proxy.
