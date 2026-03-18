"""Programmable Hooks policy rules (HOOK-001, HOOK-002, HOOK-003)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from drako.cli.policies.base import BasePolicy, Finding

if TYPE_CHECKING:
    from drako.cli.bom import AgentBOM
    from drako.cli.discovery import ProjectMetadata


class HOOK001(BasePolicy):
    """HOOK-001: No pre-action validation hooks."""
    policy_id = "HOOK-001"
    category = "Hooks"
    severity = "MEDIUM"
    title = "No pre-action validation hooks"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        if not bom.tools:
            return []

        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if not config_content:
            # No config → report if project has tools
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    f"Project has {len(bom.tools)} tool(s) but no pre-action hooks configured. "
                    "Hooks allow you to inject custom validation before tool execution."
                ),
                fix_snippet=(
                    "# Add to .drako.yaml:\n"
                    "hooks:\n"
                    "  pre_action:\n"
                    "    - name: block-dangerous-sql\n"
                    "      condition: \"tool_name == 'execute_sql' and 'DROP' in tool_args\"\n"
                    "      action_on_fail: block"
                ),
            )]

        # Has config — check for hooks.pre_action
        if "pre_action:" in config_content and "hooks:" in config_content:
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                f"No pre-action hooks configured for {len(bom.tools)} tool(s). "
                "Consider adding validation hooks to enforce custom policies before execution."
            ),
            fix_snippet=(
                "# Add to .drako.yaml:\n"
                "hooks:\n"
                "  pre_action:\n"
                "    - name: validate-input\n"
                "      condition: \"tool_name == 'api_call' and 'schema_version' not in tool_args\"\n"
                "      action_on_fail: block"
            ),
        )]


class HOOK002(BasePolicy):
    """HOOK-002: No session-end gate (Stop hook)."""
    policy_id = "HOOK-002"
    category = "Hooks"
    severity = "MEDIUM"
    title = "No session-end gate (Stop hook)"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if not config_content:
            return []  # HOOK-001 already flags missing config

        if "on_session_end:" in config_content and "hooks:" in config_content:
            return []

        return [Finding(
            policy_id=self.policy_id,
            category=self.category,
            severity=self.severity,
            title=self.title,
            message=(
                "No session-end gate (Stop hook) configured. The agent can finish "
                "a session without verifying that all required checks passed."
            ),
            fix_snippet=(
                "# Add to .drako.yaml:\n"
                "hooks:\n"
                "  on_session_end:\n"
                "    - name: require-tests-passed\n"
                "      script: .drako/hooks/check_tests.py\n"
                "      action_on_fail: block\n"
                "      timeout_ms: 10000"
            ),
        )]


class HOOK003(BasePolicy):
    """HOOK-003: Hook without timeout configured."""
    policy_id = "HOOK-003"
    category = "Hooks"
    severity = "LOW"
    title = "Hook without timeout configured"

    def evaluate(self, bom: AgentBOM, metadata: ProjectMetadata) -> list[Finding]:
        config_content = ""
        for path, content in metadata.config_files.items():
            if ".drako" in path:
                config_content = content
                break

        if not config_content or "hooks:" not in config_content:
            return []

        # Check if any hook entry lacks timeout_ms
        # Simple heuristic: if "script:" appears but "timeout_ms:" doesn't follow
        has_scripts = "script:" in config_content
        has_timeout = "timeout_ms:" in config_content

        if has_scripts and not has_timeout:
            return [Finding(
                policy_id=self.policy_id,
                category=self.category,
                severity=self.severity,
                title=self.title,
                message=(
                    "Script hooks detected without explicit timeout_ms. "
                    "Runaway scripts could block the governance pipeline."
                ),
                fix_snippet=(
                    "# Add timeout_ms to each script hook:\n"
                    "hooks:\n"
                    "  pre_action:\n"
                    "    - name: validate-schema\n"
                    "      script: .drako/hooks/validate_schema.py\n"
                    "      timeout_ms: 5000  # 5 second timeout"
                ),
            )]

        return []


HOOKS_POLICIES: list[BasePolicy] = [
    HOOK001(),
    HOOK002(),
    HOOK003(),
]
