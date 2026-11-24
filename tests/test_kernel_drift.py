"""Sprint 2 T6: scope-drift suites (2026-09-04). Pure, hermetic."""

from datetime import datetime, timedelta, timezone

from drako.kernel.drift import (
    AuthorityEntry,
    detect_drift,
)


def _tool(id, detail="allow"):
    return AuthorityEntry(id=id, kind="tool", detail=detail)


def _finding(id, detail="HIGHtitle"):
    return AuthorityEntry(id=id, kind="finding", detail=detail)


def test_clean_when_mirror():
    base = [_tool("web_search", "allow"), _finding("SEC-010", "HIGH x")]
    eff = [_tool("web_search", "allow"), _finding("SEC-010", "HIGH x")]
    r = detect_drift(base, eff)
    assert r.clean and r.items == []


def test_uncovered_finding_blocks():
    r = detect_drift([_finding("SEC-010", "HIGH x")], [])
    assert not r.clean
    assert r.blocking[0].kind == "uncovered"


def test_vanished_capability_blocks_as_widened():
    r = detect_drift([_tool("file_delete", "deny")], [])
    assert r.blocking[0].kind == "widened"


def test_new_effective_capability_blocks():
    r = detect_drift([], [_tool("send_email", "allow")])
    assert not r.clean
    assert "re-scan" in r.blocking[0].message


def test_flipped_effect_blocks_with_both_sides():
    r = detect_drift(
        [_tool("web_search", "allow:domain-only")],
        [_tool("web_search", "allow")],
    )
    assert r.blocking[0].kind == "flipped"
    assert "allow:domain-only" in r.blocking[0].message


def test_detail_compare_ignores_case_and_spacing():
    r = detect_drift([_tool("a", "Allow: X")], [_tool("a", "allow:   x")])
    assert r.clean


def test_stale_baseline_is_advisory_only():
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    r = detect_drift([], [], baseline_issued_at=old, max_age_days=30)
    assert r.clean  # stale never blocks
    assert r.items[0].kind == "stale"


def test_fresh_baseline_no_stale():
    now = datetime.now(timezone.utc).isoformat()
    r = detect_drift([], [], baseline_issued_at=now)
    assert r.items == []


def test_unparseable_timestamp_is_advisory():
    r = detect_drift([], [], baseline_issued_at="not-a-date")
    assert r.clean and r.items[0].kind == "stale"

