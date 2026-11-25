# Proxy Mode

The Drako Enforcement Proxy is a local, out-of-process HTTP enforcement layer backed by the v4 Authority Kernel, thread-safe `LoopBreaker`, and SSRF `EgressGuard`. It intercepts LLM API calls before they reach OpenAI, Anthropic, or Google without requiring code changes in your agent.

Because the proxy runs in a separate process, an agent cannot disable or rewrite its policies at runtime.

---

## How It Works

```text
Agent process
  └─ sends HTTP call to OpenAI / Anthropic / Google
       └─ intercepted by Drako Proxy (127.0.0.1:8990)
            ├─ 1. Resolve target API (/openai/, /anthropic/, /google/)
            ├─ 2. LoopBreaker check (OWASP ASI08 / ASI10 runaway repetition)
            ├─ 3. Authority Kernel check (drako-policy.yaml + Ed25519 receipt)
            ├─ 4. DLP & HITL checks from .drako.yaml
            ├─ 5. SSRF EgressGuard check (assert_public_url + egress.allowed_domains)
            ├─ 6. Forward to upstream API (if permitted)
            └─ 7. Track estimated cost and return response + governance headers
```

Blocked requests never reach the upstream provider:
- `403`: Authority Kernel deny, DLP violation, or SSRF egress block
- `429`: `LoopBreaker` tripped or rate limit exceeded
- `202`: HITL approval pending

---

## Quick Start

```bash
# Install proxy extras
pip install 'drako[proxy]'

# Initialize local config & ACS policy profile
drako init

# Set bearer token for /status and /audit evidence endpoints
export DRAKO_PROXY_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# Start the proxy (binds loopback 127.0.0.1:8990 by default)
drako proxy start

# Point your agent SDKs at the local proxy
export OPENAI_BASE_URL=http://127.0.0.1:8990/openai/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8990/anthropic/v1
```

Or run directly via the Python module entrypoint:

```bash
DRAKO_PROXY_HOST=127.0.0.1 DRAKO_PROXY_PORT=8990 DRAKO_CONFIG_PATH=.drako.yaml python -m drako.proxy
```

---

## Supported Upstream Targets

| Provider | Env Var | Proxy Path Prefix |
|----------|---------|-------------------|
| OpenAI | `OPENAI_BASE_URL` | `/openai/` |
| Anthropic | `ANTHROPIC_BASE_URL` | `/anthropic/` |
| Google Gemini | `GOOGLE_API_BASE` | `/google/` |

Any unknown path prefix returns HTTP `400`.

---

## Security Defaults

- **Loopback-only by default:** both `drako proxy start` and `python -m drako.proxy` bind `127.0.0.1:8990`. Bind `0.0.0.0` only inside an isolated container or behind an authenticated reverse proxy.
- **Authenticated evidence endpoints:** `GET /status` and `GET /audit` require `Authorization: Bearer $DRAKO_PROXY_TOKEN` (fail-closed `401` when unset). For ephemeral local development only, `DRAKO_DEV_UNSAFE=1` disables auth with a startup warning.
- **Strict CORS:** never sets `*`; defaults to `localhost:3000` / `localhost:5173` and is configurable via `cors_origins`.
- **SSRF EgressGuard:** every upstream request passes `drako.kernel.egress.assert_public_url()` with optional `egress.allowed_domains` pinning.

---

## Configuration (`.drako.yaml` + `drako-policy.yaml`)

The proxy reads `.drako.yaml` (resolving `extends:` if present) and loads `kernel.profile_path` (`drako-policy.yaml`) into a local `drako.kernel.Host`:

```yaml
# .drako.yaml (flat v4 schema)
version: "4.0"
project_id: my-proxy
governance_level: balanced

kernel:
  spec_pin: AGENT-HOOKS-0.1
  default_effect: deny
  profile_path: drako-policy.yaml
  receipt_store: .drako/receipts.jsonl

loop_breaker:
  enabled: true
  trip_threshold: 10
  window_seconds: 300.0

dlp:
  mode: enforce

hitl:
  mode: enforce
  triggers:
    tools: [delete_file, send_email, execute_payment]
  timeout_action: reject

egress:
  allowed_domains:
    - api.openai.com
    - api.anthropic.com
```

Optional Ed25519 receipt signing keys can be supplied via `DRAKO_SIGNING_KEY_FILE` and `DRAKO_SIGNING_PUBKEY_FILE`.

---

## Monitoring Endpoints

### `GET /health` (unauthenticated liveness probe)

```json
{
  "status": "healthy",
  "governance_level": "balanced",
  "targets": ["openai", "anthropic", "google"],
  "audit_entries": 42
}
```

### `GET /status` (requires `Authorization: Bearer $DRAKO_PROXY_TOKEN`)

Returns proxy version, loaded config status, target mappings, and per-agent session statistics.

### `GET /audit` (requires `Authorization: Bearer $DRAKO_PROXY_TOKEN`)

Returns the most recent 100 in-memory audit log entries. When `kernel.receipt_store` is configured, decisions are also persisted locally to `.drako/receipts.jsonl` as Ed25519 hash-chained receipts verifiable offline via `drako verify`.

### Response Headers

| Header | Value |
|--------|-------|
| `X-Drako-Proxy` | `true` |
| `X-Drako-Latency-Ms` | Round-trip latency in milliseconds |
| `X-Drako-Receipt-Id` | Ed25519 receipt ID (when kernel Host is active) |
| `X-Drako-Cost-USD` | Estimated request cost (when usage metadata is present) |

---

## Docker

Build from `src/drako/proxy/Dockerfile.proxy` or run the published container image (runs as non-root user `drako` with built-in Python `HEALTHCHECK`):

```bash
docker run -d \
  -p 127.0.0.1:8990:8990 \
  -v "$(pwd)/.drako.yaml:/app/.drako.yaml:ro" \
  -v "$(pwd)/drako-policy.yaml:/app/drako-policy.yaml:ro" \
  -e DRAKO_PROXY_TOKEN="$DRAKO_PROXY_TOKEN" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  ghcr.io/drakolabs/drako-proxy:4.0.0a1
```

### `docker-compose.yml`

```yaml
services:
  drako-proxy:
    image: ghcr.io/drakolabs/drako-proxy:4.0.0a1
    ports:
      - "127.0.0.1:8990:8990"
    volumes:
      - ./.drako.yaml:/app/.drako.yaml:ro
      - ./drako-policy.yaml:/app/drako-policy.yaml:ro
    environment:
      - DRAKO_PROXY_TOKEN=${DRAKO_PROXY_TOKEN}
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

See [`deploy/helm/drako-proxy/`](../deploy/helm/drako-proxy/) for the v4 Helm chart supporting `DRAKO_PROXY_TOKEN` secrets and ConfigMap mounts for `.drako.yaml` and `drako-policy.yaml`.

---

## Cost Tracking

The proxy estimates cost from the `usage` object returned by upstream providers using built-in fallback rates, which you can override per model in `.drako.yaml`:

```yaml
finops:
  tracking:
    enabled: true
    model_costs:
      gpt-4o:
        input: 0.0025
        output: 0.01
      claude-4-sonnet:
        input: 0.003
        output: 0.015
```

---

## Limitations

- **Tool extraction format:** extracts tool names from standard OpenAI `function_call` / `tool_calls` payloads. For in-process Python tool governance across LangGraph, OpenAI Agents SDK, MAF, Claude Agent SDK, ADK, or CrewAI, use `drako.guard()` or `drako.adapters`.
- **In-memory session state:** rate counters and `/audit` ring buffer reset on proxy restart; configure `kernel.receipt_store: .drako/receipts.jsonl` for persistent, tamper-evident Ed25519 receipts on disk.
