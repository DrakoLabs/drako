# Roadmap

Drako ships governance for Python AI agents today. Here's where we're going.

## Q2 2026 (April - June)

**Full Dashboard Implementation** — A clean, intuitive, and organized dashboard that really helps you see what your agents are actually doing.

**TypeScript SDK** — Same enforcement pipeline, new language. `govern()` for Vercel AI SDK, LangChain.js, and any agent that makes tool calls over HTTP. The policy engine is language-agnostic; the SDK is the integration layer.

**MCP Tool Manifest Scanner** — Dedicated scanner for MCP server manifests. Detect excessive permissions, unauthenticated endpoints, and missing rate limits in MCP tool definitions before your agent connects to them.

**Plugin system for custom rules** — Write governance rules in Python, register them with Drako, and they run alongside the built-in 60. Your org's domain-specific policies enforced with the same engine.

## Q3 2026 (July - September)

**SOC 2 Type II audit packages** — Pre-built evidence packages generated from Drako audit trails, policy snapshots, and HITL logs. Mapped to SOC 2 trust service criteria. Exportable for your auditor.

**Agent BOM as OWASP standard** — Contributing the Agent Bill of Materials format to OWASP as a proposed standard for AI agent component inventory. Like SBOM but for agents.

**Governance-aware model routing** — The policy engine selects the model based on task risk profile. High-risk financial action routes to the most reliable model with full intent verification. Low-risk summarization routes to the cheapest model with audit-only.

## Q4 2026 (October - December)

**ISO 42001 certification templates** — Pre-mapped controls and evidence for AI Management System certification.

**Agent insurance scoring** — Quantified risk profiles for AI liability underwriting. Governance score + audit completeness + incident history = standardized package for insurers.

**Federated governance mesh** — Cross-organizational policy enforcement. When Company A's agent calls Company B's API, both governance policies apply. Cross-org audit trails, mutual trust verification, and regulatory reporting that spans supply chains.

---

Building in public. Priorities shift based on what users need. If something here matters to you, [open an issue](https://github.com/angelnicolasc/drako/issues) or email hello@drako.com.
