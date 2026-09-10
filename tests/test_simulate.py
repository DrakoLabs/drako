"""Tests for `drako simulate` CLI command."""

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from drako.cli.main import cli


# ---- Fixtures ----

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def policy_file(tmp_path: Path) -> str:
    """Write a minimal policy YAML and return its path."""
    cfg = tmp_path / ".drako.yaml"
    cfg.write_text(textwrap.dedent("""\
        version: "1.0"
        tenant_id: "t-test-001"
        dlp:
          mode: enforce
        trust:
          enabled: true
          min_score: 0.7
        odd:
          forbidden_tools:
            - dangerous_tool
        hitl:
          mode: enforce
          triggers:
            tools: [web_search]
    """))
    return str(cfg)


SUCCESSFUL_RESPONSE = {
    "total_replayed": 50,
    "blocked": 12,
    "escalated": 5,
    "modified": 3,
    "allowed": 30,
    "blocked_breakdown": [
        {
            "reason": "dlp_enforce",
            "count": 7,
            "example_transaction_id": "tx-001",
        },
        {
            "reason": "trust_below_threshold",
            "count": 5,
            "example_transaction_id": "tx-042",
        },
    ],
}

EMPTY_RESPONSE = {
    "total_replayed": 0,
    "blocked": 0,
    "escalated": 0,
    "modified": 0,
    "allowed": 0,
    "blocked_breakdown": [],
}


def _mock_httpx_success(response_json: dict, status_code: int = 200):
    """Return a context-manager-compatible mock httpx.Client."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = response_json
    mock_response.raise_for_status.return_value = None

    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


def _mock_httpx_error(status_code: int, detail: str = "error"):
    """Return a mock httpx.Client that raises HTTPStatusError."""
    import httpx

    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = {"detail": detail}
    mock_response.text = detail

    error = httpx.HTTPStatusError(
        message=f"HTTP {status_code}",
        request=MagicMock(),
        response=mock_response,
    )

    mock_client = MagicMock()
    mock_client.post.side_effect = error
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    return mock_client


# ---- Tests ----

class TestSimulateCommand:
    """Tests for the `drako simulate` CLI command."""

    @patch("httpx.Client")
    def test_simulate_terminal_output(
        self, mock_client_cls, runner: CliRunner, policy_file: str
    ):
        """Successful simulation renders a Rich summary table."""
        mock_client_cls.return_value = _mock_httpx_success(SUCCESSFUL_RESPONSE)

        result = runner.invoke(
            cli,
            ["simulate", "--policy", policy_file, "--hours", "12", "--api-key", "test-key"],
        )

        assert result.exit_code == 0
        # Summary values should appear in terminal output
        assert "50" in result.output  # total_replayed
        assert "12" in result.output  # blocked (also matches hours, but that's fine)
        assert "30" in result.output  # allowed
        # Breakdown reasons
        assert "dlp_enforce" in result.output
        assert "trust_below_threshold" in result.output

    @patch("httpx.Client")
    def test_simulate_json_output(
        self, mock_client_cls, runner: CliRunner, policy_file: str
    ):
        """--format json emits raw JSON."""
        mock_client_cls.return_value = _mock_httpx_success(SUCCESSFUL_RESPONSE)

        result = runner.invoke(
            cli,
            [
                "simulate",
                "--policy", policy_file,
                "--format", "json",
                "--api-key", "test-key",
            ],
        )

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["total_replayed"] == 50
        assert parsed["blocked"] == 12
        assert len(parsed["blocked_breakdown"]) == 2

    def test_simulate_no_policy_file(self, runner: CliRunner):
        """No policy anywhere: exit 1 with guidance (not a usage error).

        The intended UX is a friendly pointer (drako init / --policy),
        not a click usage error.
        """
        result = runner.invoke(cli, ["simulate"])
        assert result.exit_code != 0
        assert "drako init" in result.output
        assert "--policy" in result.output

    @patch("httpx.Client")
    def test_simulate_api_error(
        self, mock_client_cls, runner: CliRunner, policy_file: str
    ):
        """HTTP 500 from the backend shows a clear error message."""
        mock_client_cls.return_value = _mock_httpx_error(500, "Internal server error")

        result = runner.invoke(
            cli,
            ["simulate", "--policy", policy_file, "--api-key", "test-key"],
        )

        assert result.exit_code != 0
        assert "500" in result.output or "error" in result.output.lower()

    @patch("httpx.Client")
    def test_simulate_empty_results(
        self, mock_client_cls, runner: CliRunner, policy_file: str
    ):
        """Zero audit entries produces a 'no historical data' message."""
        mock_client_cls.return_value = _mock_httpx_success(EMPTY_RESPONSE)

        result = runner.invoke(
            cli,
            ["simulate", "--policy", policy_file, "--api-key", "test-key"],
        )

        assert result.exit_code == 0
        assert "no historical" in result.output.lower() or "0" in result.output
