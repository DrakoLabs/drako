"""Property-based tests for Drako governance rules.

Uses Hypothesis to generate adversarial inputs and verify invariants.
Run: pytest tests/test_properties.py -v --hypothesis-show-statistics
"""

from __future__ import annotations

import copy
from dataclasses import dataclass

from hypothesis import given, strategies as st, settings, assume

from drako.cli.policies.base import Finding
from drako.cli.scoring import calculate_score, score_to_grade, findings_summary


# ===================================================================
# Strategies — reusable generators for common types
# ===================================================================

severity_st = st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"])

category_st = st.sampled_from(["Security", "Governance", "Compliance", "Best Practices", "Operational"])

policy_id_st = st.sampled_from([
    "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005",
    "GOV-001", "GOV-002", "GOV-003", "GOV-004", "GOV-005",
    "GOV-006", "GOV-007", "GOV-008", "GOV-009", "GOV-010",
    "COM-001", "COM-002", "COM-003", "COM-004",
    "BP-001", "BP-002", "BP-003",
    "ODD-001", "ODD-002", "ODD-003",
    "MAG-001", "MAG-002",
])


def make_finding(policy_id: str, severity: str, category: str = "Governance") -> Finding:
    """Helper to create a Finding for tests."""
    return Finding(
        policy_id=policy_id,
        category=category,
        severity=severity,
        title=f"Test finding {policy_id}",
        message=f"Test message for {policy_id}",
    )


finding_st = st.builds(
    make_finding,
    policy_id=policy_id_st,
    severity=severity_st,
    category=category_st,
)

findings_list_st = st.lists(finding_st, max_size=50)


# ===================================================================
# PROPERTY: Scoring invariants
# ===================================================================

@given(findings=findings_list_st)
@settings(max_examples=500)
def test_score_always_in_range(findings: list[Finding]):
    """Score must always be between 0 and 100, regardless of findings."""
    score = calculate_score(findings)
    assert 0 <= score <= 100, f"Score {score} out of range for {len(findings)} findings"


@given(findings=findings_list_st)
@settings(max_examples=300)
def test_score_is_deterministic(findings: list[Finding]):
    """Same findings must always produce the same score."""
    score_a = calculate_score(findings)
    score_b = calculate_score(findings)
    assert score_a == score_b, "Score calculation is non-deterministic"


def test_empty_findings_yield_perfect_score():
    """No findings must produce a perfect 100 score."""
    score = calculate_score([])
    assert score == 100, f"Empty findings gave score {score}, expected 100"


@given(findings=findings_list_st)
@settings(max_examples=300)
def test_score_never_below_zero(findings: list[Finding]):
    """Even with maximum findings, score cannot go below 0."""
    score = calculate_score(findings)
    assert score >= 0


@given(
    base_findings=findings_list_st,
    extra=finding_st,
)
@settings(max_examples=300)
def test_more_findings_never_increase_score(base_findings: list[Finding], extra: Finding):
    """Adding a finding must never increase the score."""
    score_before = calculate_score(base_findings)
    score_after = calculate_score(base_findings + [extra])
    assert score_after <= score_before, (
        f"Score increased from {score_before} to {score_after} by adding {extra.severity}"
    )


@given(
    findings=st.lists(
        st.builds(make_finding, policy_id=st.just("SEC-001"),
                  severity=st.just("CRITICAL")),
        min_size=10, max_size=100,
    )
)
@settings(max_examples=200)
def test_category_caps_prevent_below_threshold(findings: list[Finding]):
    """Category caps prevent one severity from dominating beyond its cap.

    Even with 100 CRITICALs, total deduction is capped at 60, so score >= 40.
    (Minus other severity caps = 0 minimum.)
    """
    score = calculate_score(findings)
    # With only CRITICALs, max deduction is 60, so score >= 40
    assert score >= 40, f"Only-CRITICAL findings gave score {score}, expected >= 40"


@given(findings=findings_list_st)
@settings(max_examples=300)
def test_max_total_deduction_is_130(findings: list[Finding]):
    """Maximum possible deduction is 130 (60+40+20+10), so min score is 0."""
    score = calculate_score(findings)
    # Max deduction: CRITICAL(60)+HIGH(40)+MEDIUM(20)+LOW(10) = 130
    # But score is floored at 0
    assert score >= 0


# ===================================================================
# PROPERTY: Grade invariants
# ===================================================================

@given(score=st.integers(min_value=0, max_value=100))
def test_grade_is_valid(score: int):
    """Grade must be one of A, B, C, D, F."""
    grade = score_to_grade(score)
    assert grade in ("A", "B", "C", "D", "F")


@given(score=st.integers(min_value=0, max_value=100))
def test_grade_monotonicity(score: int):
    """Higher scores must map to the same or better grade."""
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    grade = score_to_grade(score)
    if score < 100:
        grade_plus = score_to_grade(score + 1) if score + 1 <= 100 else "A"
        assert grade_order[grade_plus] >= grade_order[grade], (
            f"Grade decreased from {grade} to {grade_plus} when score increased"
        )


@given(score=st.integers(min_value=90, max_value=100))
def test_high_score_is_grade_a(score: int):
    """Score 90-100 must be grade A."""
    assert score_to_grade(score) == "A"


@given(score=st.integers(min_value=0, max_value=39))
def test_low_score_is_grade_f(score: int):
    """Score 0-39 must be grade F."""
    assert score_to_grade(score) == "F"


# ===================================================================
# PROPERTY: Findings summary invariants
# ===================================================================

@given(findings=findings_list_st)
@settings(max_examples=300)
def test_summary_counts_match_input(findings: list[Finding]):
    """Summary counts must equal actual counts."""
    summary = findings_summary(findings)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        expected = sum(1 for f in findings if f.severity == sev)
        assert summary[sev] == expected, (
            f"{sev}: summary={summary[sev]}, actual={expected}"
        )


@given(findings=findings_list_st)
@settings(max_examples=200)
def test_summary_total_equals_input_length(findings: list[Finding]):
    """Summary total must equal len(findings)."""
    summary = findings_summary(findings)
    total = sum(summary.values())
    assert total == len(findings)


# ===================================================================
# PROPERTY: Template deep merge
# ===================================================================

from drako.templates import deep_merge

dict_st = st.fixed_dictionaries({
    "a": st.integers(),
    "b": st.text(min_size=0, max_size=10),
})

nested_dict_st = st.fixed_dictionaries({
    "top": st.integers(),
    "nested": st.fixed_dictionaries({
        "x": st.integers(),
        "y": st.text(min_size=0, max_size=5),
    }),
})


@given(base=dict_st, override=dict_st)
def test_deep_merge_override_wins(base: dict, override: dict):
    """Override values must take precedence in merge."""
    result = deep_merge(base, override)
    for key, value in override.items():
        assert result[key] == value


@given(base=nested_dict_st, override=nested_dict_st)
def test_deep_merge_recursive(base: dict, override: dict):
    """Nested dicts must be merged recursively."""
    result = deep_merge(base, override)
    assert result["nested"]["x"] == override["nested"]["x"]
    assert result["nested"]["y"] == override["nested"]["y"]
    assert result["top"] == override["top"]


@given(d=dict_st)
def test_deep_merge_identity(d: dict):
    """Merging with empty dict returns the original."""
    result = deep_merge(d, {})
    assert result == d


@given(d=dict_st)
def test_deep_merge_does_not_mutate(d: dict):
    """Deep merge must not mutate the inputs."""
    original = copy.deepcopy(d)
    deep_merge(d, {"a": 999, "b": "mutated"})
    assert d == original


# ===================================================================
# PROPERTY: ODD governance (proxy module)
# ===================================================================

from drako.proxy.proxy_server import _check_odd


@given(
    agent=st.sampled_from(["researcher", "writer", "admin"]),
    tool=st.sampled_from(["web_search", "file_write", "code_exec", "db_read"]),
)
@settings(max_examples=200)
def test_odd_permitted_tool_always_allowed(agent: str, tool: str):
    """A tool in the permitted list must never be rejected."""
    config = {
        "odd": {
            "enforcement_mode": "enforce",
            "agents": {
                agent: {
                    "permitted_tools": [tool, "extra_tool"],
                    "forbidden_tools": [],
                }
            },
        }
    }
    result = _check_odd(agent, tool, config)
    assert result is None, f"Permitted tool {tool} was rejected: {result}"


@given(
    agent=st.sampled_from(["researcher", "writer", "admin"]),
    tool=st.sampled_from(["web_search", "file_write", "code_exec", "db_read"]),
)
@settings(max_examples=200)
def test_odd_forbidden_tool_always_rejected(agent: str, tool: str):
    """A tool in the forbidden list must always be rejected in enforce mode."""
    config = {
        "odd": {
            "enforcement_mode": "enforce",
            "agents": {
                agent: {
                    "permitted_tools": ["other_tool"],
                    "forbidden_tools": [tool],
                }
            },
        }
    }
    result = _check_odd(agent, tool, config)
    assert result is not None, f"Forbidden tool {tool} was not rejected"
    assert result["decision"] == "rejected"


@given(
    agent=st.sampled_from(["researcher", "writer", "admin"]),
    tool=st.sampled_from(["web_search", "file_write", "code_exec"]),
)
def test_odd_off_mode_never_rejects(agent: str, tool: str):
    """ODD in 'off' mode must never reject anything."""
    config = {
        "odd": {
            "enforcement_mode": "off",
            "agents": {
                agent: {
                    "permitted_tools": [],
                    "forbidden_tools": [tool],
                }
            },
        }
    }
    result = _check_odd(agent, tool, config)
    assert result is None


# ===================================================================
# PROPERTY: Magnitude checks (proxy module)
# ===================================================================

from drako.proxy.proxy_server import _check_magnitude


@given(max_actions=st.integers(min_value=1, max_value=100))
@settings(max_examples=100)
def test_magnitude_below_limit_allowed(max_actions: int):
    """Actions below the limit must always be allowed."""
    config = {
        "magnitude": {
            "max_actions_per_minute": max_actions,
            "enforcement_mode": "enforce",
        }
    }
    state: dict = {}
    # First action should always be allowed
    result = _check_magnitude("test_agent", config, state)
    assert result is None, f"First action rejected with limit {max_actions}"


@given(max_actions=st.integers(min_value=1, max_value=10))
@settings(max_examples=50)
def test_magnitude_above_limit_rejected(max_actions: int):
    """Actions above the limit must be rejected in enforce mode."""
    config = {
        "magnitude": {
            "max_actions_per_minute": max_actions,
            "enforcement_mode": "enforce",
        }
    }
    state: dict = {}
    # Exhaust the limit
    for _ in range(max_actions):
        _check_magnitude("test_agent", config, state)
    # The next one should be rejected
    result = _check_magnitude("test_agent", config, state)
    assert result is not None, f"Action {max_actions + 1} was not rejected"
    assert result["decision"] == "rejected"


# ===================================================================
# PROPERTY: DLP checks (proxy module)
# ===================================================================

from drako.proxy.proxy_server import _check_dlp


@given(
    d1=st.from_regex(r"[0-9]{3}", fullmatch=True),
    d2=st.from_regex(r"[0-9]{2}", fullmatch=True),
    d3=st.from_regex(r"[0-9]{4}", fullmatch=True),
)
def test_dlp_detects_ssn_in_enforce_mode(d1: str, d2: str, d3: str):
    """SSN patterns must be detected when DLP is in enforce mode."""
    ssn = f"{d1}-{d2}-{d3}"
    config = {"dlp": {"mode": "enforce"}}
    body = {"messages": [{"role": "user", "content": f"My SSN is {ssn}"}]}
    result = _check_dlp(body, config)
    assert result is not None, f"DLP missed SSN: {ssn}"
    assert result["decision"] == "rejected"


@given(text=st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=5, max_size=50))
def test_dlp_no_false_positive_on_plain_text(text: str):
    """Plain alphabetic text must not trigger DLP."""
    config = {"dlp": {"mode": "enforce"}}
    body = {"messages": [{"role": "user", "content": text}]}
    result = _check_dlp(body, config)
    assert result is None, f"DLP false positive on: {text}"


@given(text=st.text(min_size=1, max_size=100))
def test_dlp_off_never_rejects(text: str):
    """DLP in 'off' mode must never reject."""
    config = {"dlp": {"mode": "off"}}
    body = {"messages": [{"role": "user", "content": text}]}
    result = _check_dlp(body, config)
    assert result is None


# ===================================================================
# PROPERTY: Config loading — governance_level validation
# ===================================================================

@given(level=st.sampled_from(["autopilot", "balanced", "strict", "custom"]))
def test_governance_level_round_trips(level: str):
    """All valid governance levels must be accepted by the config model."""
    from drako.config import DrakoConfig
    config = DrakoConfig(tenant_id="test", governance_level=level)
    assert config.governance_level == level


# ===================================================================
# PROPERTY: Template listing
# ===================================================================

def test_template_list_is_not_empty():
    """Template registry must have at least the base templates."""
    from drako.templates import list_templates
    templates = list_templates()
    names = [t["name"] for t in templates]
    assert "base" in names
    assert "fintech" in names
    assert "healthcare" in names
    assert "enterprise" in names
    assert "startup" in names


def test_all_templates_load_without_error():
    """Every registered template must load successfully."""
    from drako.templates import list_templates, load_template
    for t in list_templates():
        data = load_template(t["name"])
        assert isinstance(data, dict)
        assert "governance_level" in data or "policies" in data
