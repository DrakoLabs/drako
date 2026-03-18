"""Agentic FinOps policy rules (FIN-001, FIN-002, FIN-003)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class FIN001(BasePolicy):
    """FIN-001: No cost tracking on LLM calls."""
    policy_id = "FIN-001"
    category = "FinOps"
    severity = "HIGH"
    title = "No cost tracking on LLM calls"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.tools:
            return []

        # Look for LLM API calls in source files
        llm_patterns = [
            "openai.chat", "openai.ChatCompletion", "client.chat.completions",
            "anthropic.messages", "client.messages.create",
            "litellm.completion", "litellm.acompletion",
            "ChatOpenAI", "ChatAnthropic", "AzureChatOpenAI",
        ]
        cost_patterns = [
            "usage", "total_tokens", "prompt_tokens", "completion_tokens",
            "cost", "token_count", "get_openai_callback", "TokenCounter",
            "drako", "finops",
        ]

        has_llm_calls = False
        has_cost_tracking = False

        for path, content in metadata.file_contents.items():
            for pat in llm_patterns:
                if pat in content:
                    has_llm_calls = True
                    break
            for pat in cost_patterns:
                if pat in content:
                    has_cost_tracking = True
                    break

        if has_llm_calls and not has_cost_tracking:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    "Project makes LLM API calls without any cost tracking mechanism. "
                    "Without cost observability, unexpected spend can go undetected."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "finops:\n"
                    "  tracking:\n"
                    "    enabled: true\n"
                    "    model_costs:\n"
                    "      gpt-4o:\n"
                    "        input: 0.0025\n"
                    "        output: 0.01"
                ),
            )]
        return []


class FIN002(BasePolicy):
    """FIN-002: Single model for all tasks (no cost optimization)."""
    policy_id = "FIN-002"
    category = "FinOps"
    severity = "MEDIUM"
    title = "Single model for all tasks (no cost optimization)"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        model_refs: set[str] = set()
        known_models = [
            "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
            "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
            "claude-3.5-sonnet", "claude-3.5-haiku",
            "gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash",
        ]

        for path, content in metadata.file_contents.items():
            for model in known_models:
                if model in content:
                    model_refs.add(model)

        if len(model_refs) == 1:
            model_name = next(iter(model_refs))
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f"Project uses only one model ({model_name}) for all tasks. "
                    "Routing simpler tasks to cheaper models can reduce costs significantly."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "finops:\n"
                    "  routing:\n"
                    "    enabled: true\n"
                    "    default_model: gpt-4o\n"
                    "    rules:\n"
                    "      - condition: \"task_type == 'summarization'\"\n"
                    "        model: gpt-4o-mini\n"
                    "        reason: \"Summarization doesn't need frontier model\""
                ),
            )]
        return []


class FIN003(BasePolicy):
    """FIN-003: No response caching configured."""
    policy_id = "FIN-003"
    category = "FinOps"
    severity = "MEDIUM"
    title = "No response caching configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.tools:
            return []

        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        # Check if any caching is configured
        cache_patterns = [
            "cache:", "caching:", "redis", "lru_cache",
            "functools.cache", "diskcache", "joblib.Memory",
        ]

        has_cache = False
        for path, content in metadata.file_contents.items():
            for pat in cache_patterns:
                if pat in content:
                    has_cache = True
                    break
        if config_content and "cache:" in config_content:
            has_cache = True

        # Only flag if project has LLM calls but no caching
        llm_patterns = [
            "openai", "anthropic", "litellm", "ChatOpenAI", "ChatAnthropic",
        ]
        has_llm = any(
            pat in content
            for path, content in metadata.file_contents.items()
            for pat in llm_patterns
        )

        if has_llm and not has_cache:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    "LLM calls detected without any caching layer. "
                    "Repeated identical queries waste tokens and increase latency."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "finops:\n"
                    "  cache:\n"
                    "    enabled: true\n"
                    "    similarity_threshold: 0.92\n"
                    "    ttl_hours: 24"
                ),
            )]
        return []


FINOPS_POLICIES: list[BasePolicy] = [
    FIN001(),
    FIN002(),
    FIN003(),
]
