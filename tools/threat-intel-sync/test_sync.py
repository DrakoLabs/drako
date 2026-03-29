"""Tests for the threat-intel-sync tool.

All tests use mocks — no network calls required.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Ensure sibling modules are importable
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from sync_otx import is_quality_pulse, map_otx_to_abss, fetch_ai_pulses  # noqa: E402
from sync_abusech import (  # noqa: E402
    map_urlhaus_to_abss,
    fetch_ai_targeted_urls,
    _is_ai_targeted,
    _domain_to_framework,
    _extract_domain,
)
from sync_all import validate_advisory, load_existing_ids, write_advisory  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_pulse(
    *,
    subscribers: int = 50,
    indicator_count: int = 5,
    tags: list[str] | None = None,
    pulse_id: str = "abc12345-full-id",
    name: str = "Test Pulse",
    indicators: list[dict] | None = None,
) -> dict:
    if tags is None:
        tags = ["llm", "prompt injection"]
    if indicators is None:
        indicators = [{"type": "URL", "indicator": "http://evil.com"}]
    return {
        "id": pulse_id,
        "name": name,
        "author": {"subscriber_count": subscribers},
        "author_name": "TestAuthor",
        "indicator_count": indicator_count,
        "indicators": indicators,
        "tags": tags,
        "TLP": "green",
        "created": "2026-03-01",
        "modified": "2026-03-01",
        "description": "A test pulse for LLM security",
        "references": ["https://example.com/ref1"],
    }


def _make_urlhaus_entry(
    *,
    url: str = "https://api.openai.com/v1/malicious",
    entry_id: int = 12345678,
    threat: str = "malware_download",
    date_added: str = "2026-03-20",
) -> dict:
    return {
        "id": entry_id,
        "url": url,
        "urlhaus_reference": f"https://urlhaus.abuse.ch/url/{entry_id}/",
        "threat": threat,
        "date_added": date_added,
    }


# ===========================================================================
# OTX Quality Gate
# ===========================================================================

class TestQualityGate:
    def test_rejects_low_subscriber_count(self):
        pulse = _make_pulse(subscribers=3)
        assert not is_quality_pulse(pulse)

    def test_rejects_zero_indicators(self):
        pulse = _make_pulse(indicator_count=0)
        assert not is_quality_pulse(pulse)

    def test_rejects_irrelevant_tags(self):
        pulse = _make_pulse(tags=["windows", "malware", "ransomware"])
        assert not is_quality_pulse(pulse)

    def test_accepts_valid_pulse(self):
        pulse = _make_pulse(subscribers=50, indicator_count=5, tags=["llm"])
        assert is_quality_pulse(pulse)

    def test_accepts_with_custom_thresholds(self):
        pulse = _make_pulse(subscribers=5, indicator_count=1, tags=["llm"])
        assert is_quality_pulse(pulse, min_subscribers=5, min_indicators=1)

    def test_rejects_when_author_is_string(self):
        pulse = _make_pulse()
        pulse["author"] = "string-author"
        assert not is_quality_pulse(pulse)

    def test_tag_matching_is_case_insensitive(self):
        pulse = _make_pulse(tags=["LLM", "Prompt Injection"])
        assert is_quality_pulse(pulse)


# ===========================================================================
# OTX → ABSS Mapping
# ===========================================================================

class TestMapOtxToAbss:
    def test_produces_valid_abss_format(self):
        pulse = _make_pulse()
        result = map_otx_to_abss(pulse)
        assert result is not None
        assert result["id"].startswith("DRAKO-ABSS-EXT-")
        assert result["category"] == "threat-intel"
        assert result["metadata"]["external"] is True
        assert isinstance(result["ioc"]["indicators"], list)
        assert result["mitigation"]["drako_rules"] == []

    def test_rejects_low_quality_pulse(self):
        pulse = _make_pulse(subscribers=2, indicator_count=0, tags=["random"])
        assert map_otx_to_abss(pulse) is None

    def test_rejects_pulse_without_extractable_indicators(self):
        pulse = _make_pulse(indicators=[])
        assert map_otx_to_abss(pulse) is None

    def test_id_uses_pulse_id_prefix(self):
        pulse = _make_pulse(pulse_id="deadbeef-1234-5678-9abc")
        result = map_otx_to_abss(pulse)
        assert result is not None
        assert result["id"] == "DRAKO-ABSS-EXT-deadbeef"

    def test_title_truncated_to_120_chars(self):
        pulse = _make_pulse(name="A" * 200)
        result = map_otx_to_abss(pulse)
        assert result is not None
        assert len(result["title"]) <= 120

    def test_severity_maps_from_tlp(self):
        for tlp, expected in [("red", 9), ("amber", 7), ("green", 5), ("white", 3)]:
            pulse = _make_pulse()
            pulse["TLP"] = tlp
            result = map_otx_to_abss(pulse)
            assert result is not None
            assert result["severity"] == expected, f"TLP {tlp} → expected {expected}"

    def test_all_required_abss_sections_present(self):
        pulse = _make_pulse()
        result = map_otx_to_abss(pulse)
        assert result is not None
        for key in ("id", "title", "category", "severity", "confidence",
                     "affected", "ioc", "taint_path", "references",
                     "mitigation", "metadata"):
            assert key in result, f"Missing key: {key}"


# ===========================================================================
# abuse.ch Helpers
# ===========================================================================

class TestAbusechHelpers:
    def test_is_ai_targeted_matches_openai(self):
        assert _is_ai_targeted("https://api.openai.com/v1/bad", frozenset({"api.openai.com"}))

    def test_is_ai_targeted_rejects_unrelated(self):
        assert not _is_ai_targeted("https://gambling.com/bad", frozenset({"api.openai.com"}))

    def test_domain_to_framework_openai(self):
        assert _domain_to_framework("https://api.openai.com/x") == "openai"

    def test_domain_to_framework_huggingface(self):
        assert _domain_to_framework("https://huggingface.co/x") == "huggingface"

    def test_domain_to_framework_fallback(self):
        assert _domain_to_framework("https://unknown.com/x") == "generic"

    def test_extract_domain(self):
        assert _extract_domain("https://api.openai.com/v1/test") == "api.openai.com"

    def test_extract_domain_invalid(self):
        assert _extract_domain("not-a-url") in ("", "not-a-url", "unknown")


# ===========================================================================
# abuse.ch → ABSS Mapping
# ===========================================================================

class TestMapUrlhausToAbss:
    def test_produces_valid_format(self):
        entry = _make_urlhaus_entry()
        result = map_urlhaus_to_abss(entry)
        assert result["id"].startswith("DRAKO-ABSS-EXT-AH-")
        assert result["category"] == "threat-intel"
        assert result["severity"] == 8
        assert result["ioc"]["type"] == "INFRASTRUCTURE_ATTACK"
        assert result["mitigation"]["drako_rules"] == []
        assert result["metadata"]["external"] is True

    def test_id_uses_entry_id(self):
        entry = _make_urlhaus_entry(entry_id=99887766)
        result = map_urlhaus_to_abss(entry)
        assert result["id"] == "DRAKO-ABSS-EXT-AH-99887766"

    def test_title_includes_domain(self):
        entry = _make_urlhaus_entry(url="https://api.anthropic.com/evil")
        result = map_urlhaus_to_abss(entry)
        assert "api.anthropic.com" in result["title"]


# ===========================================================================
# Validation
# ===========================================================================

class TestValidation:
    def test_rejects_missing_required_fields(self):
        assert not validate_advisory({"id": "test"})
        assert not validate_advisory({"id": "test", "title": "t"})

    def test_accepts_complete_advisory(self):
        assert validate_advisory({
            "id": "test",
            "title": "Test Advisory",
            "severity": 5,
            "source": "test",
            "ioc": {"type": "GENERIC"},
            "metadata": {"external": True},
        })

    def test_rejects_empty_id(self):
        assert not validate_advisory({
            "id": "",
            "title": "t",
            "severity": 5,
            "source": "test",
            "ioc": {"type": "GENERIC"},
            "metadata": {"external": True},
        })


# ===========================================================================
# Write & Load Roundtrip
# ===========================================================================

class TestWriteAndLoad:
    def test_write_advisory_creates_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            advisory = {
                "id": "DRAKO-ABSS-EXT-test01",
                "title": "Test",
                "severity": 5,
                "source": "test",
                "ioc": {"type": "GENERIC"},
                "metadata": {"external": True},
            }
            path = write_advisory(advisory, output_dir=Path(tmpdir))
            assert path.exists()
            assert path.suffix == ".yaml"

            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            assert loaded["id"] == "DRAKO-ABSS-EXT-test01"
            assert loaded["_generated_by"] == "threat-intel-sync"
            assert loaded["_schema_version"] == "1.0"

    def test_load_existing_ids_reads_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            advisory = {
                "id": "DRAKO-ABSS-EXT-abc",
                "title": "Test",
                "severity": 5,
                "source": "test",
                "ioc": {},
                "metadata": {},
            }
            write_advisory(advisory, output_dir=output_dir)
            ids = load_existing_ids(output_dir)
            assert "DRAKO-ABSS-EXT-abc" in ids

    def test_load_existing_ids_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ids = load_existing_ids(Path(tmpdir))
            assert len(ids) == 0


# ===========================================================================
# Deduplication
# ===========================================================================

class TestDeduplication:
    def test_same_id_not_written_twice(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            advisory = {
                "id": "DRAKO-ABSS-EXT-dup1",
                "title": "Dup Test",
                "severity": 5,
                "source": "test",
                "ioc": {"type": "GENERIC"},
                "metadata": {"external": True},
            }
            write_advisory(advisory, output_dir=output_dir)
            write_advisory(advisory, output_dir=output_dir)

            # Should overwrite, not duplicate — only 1 file
            yaml_files = list(output_dir.glob("*.yaml"))
            assert len(yaml_files) == 1


# ===========================================================================
# Async Fetch (mocked)
# ===========================================================================

class TestFetchOtxMocked:
    @pytest.mark.asyncio
    async def test_handles_api_error_gracefully(self):
        import httpx as _httpx

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = _httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response,
        )

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("sync_otx.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_ai_pulses(limit=10)
            assert result == []

    @pytest.mark.asyncio
    async def test_returns_deduplicated_pulses(self):
        pulse = _make_pulse(pulse_id="same-id-123")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"results": [pulse, pulse, pulse]}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("sync_otx.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_ai_pulses(keywords=["test"], limit=10)
            assert len(result) == 1
            assert result[0]["id"] == "same-id-123"


class TestFetchAbusechMocked:
    @pytest.mark.asyncio
    async def test_handles_timeout_gracefully(self):
        import httpx as _httpx

        mock_client = AsyncMock()
        mock_client.post.side_effect = _httpx.TimeoutException("timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("sync_abusech.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_ai_targeted_urls(limit=10)
            assert result == []

    @pytest.mark.asyncio
    async def test_filters_non_ai_urls(self):
        entries = [
            _make_urlhaus_entry(url="https://api.openai.com/bad"),
            _make_urlhaus_entry(url="https://gambling.com/bad", entry_id=999),
        ]
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"urls": entries}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("sync_abusech.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_ai_targeted_urls(limit=10)
            assert len(result) == 1
            assert "openai" in result[0]["title"].lower() or "openai" in str(result[0]["ioc"])
