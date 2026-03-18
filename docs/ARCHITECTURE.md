# Architecture

Drako has two layers: a **scan engine** (runs offline in the SDK) and a **runtime enforcement platform** (runs server-side in production). This document covers the public interfaces of both.

---

## 1. Enforcement Pipeline

Every tool call intercepted by `govern()` passes through these stages in order. Each stage can **ALLOW**, **DENY**, **MODIFY**, or **ESCALATE**. The pipeline short-circuits on first DENY.

```python
"""Drako Enforcement Pipeline — SDK side.

The SDK sends evaluation requests to the Drako platform.
The platform runs the full pipeline server-side and returns
the decision. This ensures enforcement cannot be bypassed
by modifying the SDK.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    ESCALATE = "escalate"
    PENDING = "pending_approval"


@dataclass
class StageResult:
    decision: Decision
    reason: Optional[str] = None
    modified_args: Optional[dict] = None
    approval_id: Optional[str] = None


class EnforcementPipeline:
    """
    Executed on every tool call intercepted by govern().
    The SDK sends evaluation requests to the Drako platform.
    The platform runs the full pipeline server-side and returns
    the decision.
    """
    stages = [
        "pre_action_hooks",       # Custom developer scripts/conditions
        "identity_check",         # Verify agent DID + credentials
        "odd_check",              # Tool in permitted_tools? Time window OK?
        "magnitude_check",        # Spend/volume/scope within limits?
        "hitl_check",             # Does this action need human approval?
        "intent_gate_1",          # Fingerprint the decision (SHA-256 + Ed25519)
        "dlp_scan",               # PII/PCI in outbound payload?
        "injection_scan",         # Prompt injection in inbound data?
        "trust_check",            # Agent reputation above threshold?
        "ioc_check",              # Known threat pattern match?
        "circuit_breaker_check",  # Tool/agent healthy enough?
        "intent_gate_2",          # Verify decision not altered since Gate 1
    ]

    # Post-execution stages (run after tool completes):
    post_stages = [
        "post_action_hooks",      # Custom post-processing
        "topology_update",        # Log interaction edge for graph
        "cost_tracking",          # Record tokens, cost, model
        "audit_log",              # SHA-256 hash chain + snapshot ID
    ]
```

**Why server-side?** The enforcement pipeline runs on the Drako platform, not in the SDK. If enforcement ran client-side, any developer could bypass it by modifying the SDK. Server-side enforcement means the SDK is the integration layer — the platform is the policy engine.

---

## 2. AST Parser Heuristics

The scan engine discovers agents, tools, models, and prompts by parsing Python source files using `ast.parse()`. No code is executed. Detection is offline and deterministic.

### Framework Detection

Drako identifies the framework using a three-layer confidence system:

| Layer | Source | Confidence | Example |
|-------|--------|-----------|---------|
| Config files | Presence of framework-specific files | 1.0 | `crewai.yaml` |
| Dependencies | `requirements.txt`, `pyproject.toml`, `setup.py` | 0.9 | `crewai>=0.85` |
| AST imports | `import` / `from ... import` statements | 0.7 | `from crewai import Agent` |

Higher-confidence layers take priority. Confidence scores are merged — if a framework appears at multiple layers, the highest confidence wins.

**Framework package mapping:**

| Framework | Detection signals |
|-----------|-----------------|
| CrewAI | `crewai` package, `from crewai import Agent, Crew, Task` |
| LangGraph | `langgraph` package, `from langgraph.graph import StateGraph` |
| AutoGen | `autogen`, `pyautogen`, `ag2` packages, `from autogen import AssistantAgent` |
| LangChain | `langchain`, `langchain-core`, `langchain-community` packages |
| LlamaIndex | `llama-index`, `llama_index`, `llamaindex` packages |
| PydanticAI | `pydantic-ai`, `pydantic_ai` packages, `from pydantic_ai import Agent` |

### File Collection

The scanner walks the project directory with these constraints:

- **Max files:** 200 Python files per scan
- **Max file size:** 100 KB per file
- **Skipped directories:** `venv`, `.venv`, `node_modules`, `__pycache__`, `.git`, `dist`, `build`, `tests`, `test`, `fixtures`, and other common non-source directories
- **Config files collected:** `requirements.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `.drako.yaml`, `crewai.yaml`, `mcp.json`
- **Windows-safe:** Uses `os.walk` fallback to handle MAX_PATH (260 chars) and broken OneDrive symlinks

### Agent Discovery

For each framework, the parser walks the AST looking for class instantiations and function calls that create agents. Extracted fields: name, tools, model, system prompt, file path, line number.

### Tool Discovery

Tools are detected by analyzing:

1. **Direct tool list assignments:** `tools=[search, write]`
2. **Decorator patterns:** `@tool` from framework-specific decorators
3. **Class inheritance:** Subclasses of `BaseTool`, `StructuredTool`
4. **MCP server manifests:** `server.json`, `mcp.json` parsing

For each tool, the scanner determines capability flags:
- `has_filesystem_access` — calls to `open()`, `Path`, `read_text`, `write_text`, `unlink`
- `has_network_access` — calls to `requests`, `httpx`, `urllib`, `aiohttp`
- `has_code_execution` — calls to `exec()`, `eval()`, `subprocess`, `os.system`

### Handling Ambiguity

- **Dynamic imports:** If tools are imported from a variable (e.g., `tools = load_tools(config)`), the parser reports the tools as "dynamic" and flags GOV-003.
- **Multiple frameworks:** If a project imports both CrewAI and LangGraph, both are reported in the BOM. Rules are evaluated against each framework's components.
- **False positive mitigation:** The parser requires both import AND instantiation. Importing a framework without creating agents does not trigger findings.

---

## 3. Trust & Scoring Model

### Governance Score (Scan)

The scan score starts at 100 and deducts points per finding:

| Severity | Points | Category cap |
|----------|--------|-------------|
| CRITICAL | -15 each | -60 |
| HIGH | -8 each | -40 |
| MEDIUM | -3 each | -20 |
| LOW | -1 each | -10 |

Category caps prevent one domain from dominating the score. A project with 10 CRITICAL security issues but perfect governance scores no lower than 40 (60 from security cap + 0 from others).

**Grades:** A (90-100), B (75-89), C (60-74), D (40-59), F (0-39).

### Runtime Trust Score (Platform)

Each agent has a dynamic trust score (0-100) that evolves based on observed behavior:

- **Increases:** Successful tool calls, clean DLP scans, intent verification passes, human approvals confirmed
- **Decreases:** DLP violations, injection detections, intent mismatches, circuit breaker trips, HITL rejections
- **Time decay:** Trust scores decay toward a baseline over time without activity, preventing stale high scores

Trust scores feed into enforcement decisions: agents below a configurable threshold trigger HITL escalation or are suspended by the circuit breaker.

The specific algorithm, weights, and decay function are part of the platform's proprietary enforcement engine.
