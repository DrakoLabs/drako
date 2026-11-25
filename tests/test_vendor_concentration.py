"""Tests for Vendor Concentration Risk (VCR) policy rules."""
from pathlib import Path

from drako.cli.bom import AgentBOM, generate_bom
from drako.cli.discovery import FrameworkInfo, ProjectMetadata
from drako.cli.policies.vendor_concentration import (
    VCR001,
    VCR002,
    VCR003,
    _detect_cloud_vendors,
    _detect_framework_vendors,
    _detect_governance_vendors,
    _detect_model_vendors,
)


def _make_metadata(
    files: dict[str, str],
    frameworks: list[FrameworkInfo] | None = None,
    dependencies: dict[str, str | None] | None = None,
) -> tuple[ProjectMetadata, AgentBOM]:
    """Helper: create metadata + BOM from inline file contents."""
    metadata = ProjectMetadata(root=Path("/fake"))
    metadata.file_contents = files
    metadata.frameworks = frameworks or []
    metadata.dependencies = dependencies or {}
    bom = generate_bom(metadata)
    return metadata, bom


# ---------------------------------------------------------------------------
# Vendor detection helpers
# ---------------------------------------------------------------------------

class TestDetectModelVendors:
    def test_openai_model(self):
        metadata, bom = _make_metadata({"main.py": 'model = "gpt-4o"'})
        vendors = _detect_model_vendors(bom, metadata)
        assert "openai" in vendors

    def test_anthropic_model(self):
        metadata, bom = _make_metadata({"main.py": 'model = "claude-3-opus"'})
        vendors = _detect_model_vendors(bom, metadata)
        assert "anthropic" in vendors

    def test_google_model(self):
        metadata, bom = _make_metadata({"main.py": 'model = "gemini-1.5-pro"'})
        vendors = _detect_model_vendors(bom, metadata)
        assert "google" in vendors

    def test_azure_openai_overrides_to_microsoft(self):
        metadata, bom = _make_metadata({
            "main.py": (
                'from langchain_openai import AzureChatOpenAI\n'
                'llm = AzureChatOpenAI(model="gpt-4o")\n'
            ),
        })
        vendors = _detect_model_vendors(bom, metadata)
        assert "microsoft" in vendors

    def test_vertex_ai_overrides_to_google(self):
        metadata, bom = _make_metadata({
            "main.py": 'from langchain_google import ChatVertexAI\n',
        })
        vendors = _detect_model_vendors(bom, metadata)
        assert "google" in vendors

    def test_no_models_returns_empty(self):
        metadata, bom = _make_metadata({"main.py": "x = 1"})
        vendors = _detect_model_vendors(bom, metadata)
        assert vendors == set()


class TestDetectFrameworkVendors:
    def test_autogen_is_microsoft(self):
        _, bom = _make_metadata(
            {"main.py": "x = 1"},
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
        )
        assert "microsoft" in _detect_framework_vendors(bom)

    def test_crewai_is_independent(self):
        _, bom = _make_metadata(
            {"main.py": "x = 1"},
            frameworks=[FrameworkInfo(name="crewai", confidence=1.0)],
        )
        assert _detect_framework_vendors(bom) == set()

    def test_google_adk(self):
        _, bom = _make_metadata(
            {"main.py": "x = 1"},
            frameworks=[FrameworkInfo(name="google_adk", confidence=1.0)],
        )
        assert "google" in _detect_framework_vendors(bom)


class TestDetectCloudVendors:
    def test_azure_env_vars(self):
        metadata, _ = _make_metadata({
            "main.py": 'endpoint = os.environ["AZURE_OPENAI_ENDPOINT"]',
        })
        assert "microsoft" in _detect_cloud_vendors(metadata)

    def test_google_cloud_imports(self):
        metadata, _ = _make_metadata({
            "main.py": "from google.cloud import aiplatform",
        })
        assert "google" in _detect_cloud_vendors(metadata)

    def test_no_cloud_returns_empty(self):
        metadata, _ = _make_metadata({"main.py": "x = 1"})
        assert _detect_cloud_vendors(metadata) == set()


class TestDetectGovernanceVendors:
    def test_semantic_kernel_is_microsoft(self):
        metadata, _ = _make_metadata(
            {"main.py": "x = 1"},
            dependencies={"semantic-kernel": "1.0.0"},
        )
        assert "microsoft" in _detect_governance_vendors(metadata)

    def test_independent_package(self):
        metadata, _ = _make_metadata(
            {"main.py": "x = 1"},
            dependencies={"drako": "2.0.0"},
        )
        assert _detect_governance_vendors(metadata) == set()


# ---------------------------------------------------------------------------
# VCR-001: Single-vendor model + framework stack
# ---------------------------------------------------------------------------

class TestVCR001:
    def test_detects_microsoft_stack(self):
        """Azure OpenAI (model vendor=microsoft) + AutoGen (framework vendor=microsoft)."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    "from langchain_openai import AzureChatOpenAI\n"
                    "from autogen import AssistantAgent\n"
                    'llm = AzureChatOpenAI(model="gpt-4o")\n'
                    'agent = AssistantAgent(name="bot")\n'
                ),
            },
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
        )
        findings = VCR001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "VCR-001"
        assert "microsoft" in findings[0].message.lower()

    def test_detects_google_stack(self):
        """Vertex AI model + Google ADK framework."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    "from langchain_google import ChatVertexAI\n"
                    'model = "gemini-1.5-pro"\n'
                ),
            },
            frameworks=[FrameworkInfo(name="google_adk", confidence=1.0)],
        )
        findings = VCR001().evaluate(bom, metadata)
        assert len(findings) == 1
        assert "google" in findings[0].message.lower()

    def test_no_finding_mixed_vendors(self):
        """CrewAI (independent) + OpenAI models → no vendor overlap."""
        metadata, bom = _make_metadata(
            {"main.py": 'model = "gpt-4o"\n'},
            frameworks=[FrameworkInfo(name="crewai", confidence=1.0)],
        )
        findings = VCR001().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_no_finding_no_models(self):
        """Framework detected but no models → no overlap possible."""
        metadata, bom = _make_metadata(
            {"main.py": "from autogen import Agent\n"},
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
        )
        findings = VCR001().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_no_finding_no_frameworks(self):
        """Models detected but no framework vendor → no overlap."""
        metadata, bom = _make_metadata({"main.py": 'model = "gpt-4o"\n'})
        findings = VCR001().evaluate(bom, metadata)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# VCR-002: Governance tooling from framework vendor
# ---------------------------------------------------------------------------

class TestVCR002:
    def test_detects_microsoft_governance_with_autogen(self):
        """semantic-kernel dep (microsoft) + autogen framework (microsoft)."""
        metadata, bom = _make_metadata(
            {"main.py": "from autogen import Agent\n"},
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
            dependencies={"semantic-kernel": "1.0.0"},
        )
        findings = VCR002().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "VCR-002"
        assert "microsoft" in findings[0].message.lower()

    def test_no_finding_independent_governance(self):
        """semantic-kernel dep (microsoft) + crewai framework (independent)."""
        metadata, bom = _make_metadata(
            {"main.py": "from crewai import Agent\n"},
            frameworks=[FrameworkInfo(name="crewai", confidence=1.0)],
            dependencies={"semantic-kernel": "1.0.0"},
        )
        findings = VCR002().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_no_finding_no_governance_deps(self):
        """No governance-related deps → no finding."""
        metadata, bom = _make_metadata(
            {"main.py": "from autogen import Agent\n"},
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
            dependencies={"httpx": "0.27.0"},
        )
        findings = VCR002().evaluate(bom, metadata)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# VCR-003: Cloud-model-framework lock-in (3+ layers)
# ---------------------------------------------------------------------------

class TestVCR003:
    def test_detects_triple_google_lock_in(self):
        """Google Cloud + Gemini model + Google ADK = 3 layers."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    "from google.cloud import aiplatform\n"
                    'model = "gemini-1.5-pro"\n'
                ),
            },
            frameworks=[FrameworkInfo(name="google_adk", confidence=1.0)],
        )
        findings = VCR003().evaluate(bom, metadata)
        assert len(findings) == 1
        assert findings[0].policy_id == "VCR-003"
        assert "google" in findings[0].message.lower()
        assert "3" in findings[0].message

    def test_detects_triple_microsoft_lock_in(self):
        """Azure cloud + Azure OpenAI model + AutoGen = 3 layers."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    'endpoint = os.environ["AZURE_OPENAI_ENDPOINT"]\n'
                    "from langchain_openai import AzureChatOpenAI\n"
                    'llm = AzureChatOpenAI(model="gpt-4o")\n'
                ),
            },
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
        )
        findings = VCR003().evaluate(bom, metadata)
        assert len(findings) == 1
        assert "microsoft" in findings[0].message.lower()

    def test_no_finding_two_layers_only(self):
        """Only 2 layers from same vendor → no finding."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    "from langchain_openai import AzureChatOpenAI\n"
                    'llm = AzureChatOpenAI(model="gpt-4o")\n'
                ),
            },
            frameworks=[FrameworkInfo(name="autogen", confidence=1.0)],
        )
        # microsoft appears in: model API (AzureChatOpenAI) + framework (autogen) = 2 layers only
        findings = VCR003().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_no_finding_different_vendors(self):
        """Different vendors across all layers → no finding."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    'model = "claude-3-opus"\n'
                    "from google.cloud import storage\n"
                ),
            },
            frameworks=[FrameworkInfo(name="crewai", confidence=1.0)],
        )
        findings = VCR003().evaluate(bom, metadata)
        assert len(findings) == 0

    def test_four_layers_detected(self):
        """All 4 layers from Google → still triggers, message says 4."""
        metadata, bom = _make_metadata(
            {
                "main.py": (
                    "from google.cloud import aiplatform\n"
                    'model = "gemini-1.5-pro"\n'
                ),
            },
            frameworks=[FrameworkInfo(name="google_adk", confidence=1.0)],
            dependencies={"google-cloud-aiplatform": "1.0.0"},
        )
        findings = VCR003().evaluate(bom, metadata)
        assert len(findings) == 1
        assert "4" in findings[0].message
