"""Tests for HooksConfig and HookEntryConfig Pydantic models."""
import pytest

from drako.config import HookEntryConfig, HooksConfig, DrakoConfig


class TestHookEntryConfig:
    """Tests for individual hook entry config."""

    def test_minimal_entry(self):
        entry = HookEntryConfig(name="block_deletes")
        assert entry.name == "block_deletes"
        assert entry.timeout_ms == 5000
        assert entry.action_on_fail == "allow"
        assert entry.priority == 0

    def test_condition_entry(self):
        entry = HookEntryConfig(
            name="block_sql",
            condition="tool_name == 'execute_sql'",
            action_on_fail="block",
        )
        assert entry.condition == "tool_name == 'execute_sql'"
        assert entry.action_on_fail == "block"

    def test_script_entry(self):
        entry = HookEntryConfig(
            name="validate_schema",
            script=".drako/hooks/validate.py",
            timeout_ms=10000,
        )
        assert entry.script == ".drako/hooks/validate.py"
        assert entry.timeout_ms == 10000


class TestHooksConfig:
    """Tests for the HooksConfig container."""

    def test_empty_hooks(self):
        hooks = HooksConfig()
        assert hooks.pre_action == []
        assert hooks.post_action == []
        assert hooks.on_error == []
        assert hooks.on_session_end == []

    def test_hooks_with_entries(self):
        hooks = HooksConfig(
            pre_action=[
                HookEntryConfig(name="check_a", condition="True"),
                HookEntryConfig(name="check_b", condition="False"),
            ],
            on_session_end=[
                HookEntryConfig(name="verify_tests", script="check_tests.py"),
            ],
        )
        assert len(hooks.pre_action) == 2
        assert len(hooks.on_session_end) == 1


class TestDrakoConfigHooks:
    """Tests for hooks field in DrakoConfig."""

    def test_default_hooks_empty(self):
        cfg = DrakoConfig(tenant_id="t-123")
        assert isinstance(cfg.hooks, HooksConfig)
        assert cfg.hooks.pre_action == []

    def test_hooks_from_dict(self):
        cfg = DrakoConfig(
            tenant_id="t-123",
            hooks={
                "pre_action": [{"name": "block", "condition": "True"}],
            },
        )
        assert len(cfg.hooks.pre_action) == 1
        assert cfg.hooks.pre_action[0].name == "block"
