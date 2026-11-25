"""Host + LangGraph adapter tests (fakes, no langgraph dependency)."""

from __future__ import annotations

import pytest

from drako.adapters.langgraph import (
    govern_tool_node_call,
    require_langgraph,
    wrap_tool_node,
)
from drako.kernel.host import Host, HostConfig
from drako.kernel.policies import guardian_from_yaml
from drako.kernel.receipts import generate_keypair, verify_chain

PROFILE = """
spec_pin: AGENT-HOOKS-0.1
default_effect: deny
tools:
  web_search:
    id: allow-search
    effect: allow
  file_delete:
    id: deny-delete
    effect: deny
    reason: destructive
"""


def _host(with_keys=True):
    cfg = HostConfig(agent_id="test-agent", session_id="s1")
    if with_keys:
        priv, pub = generate_keypair()
        cfg.private_pem, cfg.public_pem = priv, pub
    else:
        pub = None
    host = Host(guardian_from_yaml(PROFILE), cfg)
    return host, (cfg.public_pem if with_keys else None)


def test_host_chains_receipts():
    host, pub = _host()
    _, r1 = host.govern_tool_call("web_search", {}, side_effect_class="read")
    _, r2 = host.govern_tool_call("file_delete", {}, side_effect_class="write")
    assert r1["decision"] == "permit" and r2["decision"] == "deny"
    assert r2["prev_hash"] == r1["payload_hash"]
    assert host.last_hash == r2["payload_hash"]
    ok, idx = verify_chain([r1, r2], pub)
    assert (ok, idx) == (True, None)


def test_host_without_keys_returns_decisions_only():
    host, _ = _host(with_keys=False)
    d, r = host.govern_tool_call("web_search", {}, side_effect_class="read")
    assert d.verdict == "permit" and r is None


def test_langgraph_govern_call_permit_and_deny():
    host, _ = _host()
    d, r = govern_tool_node_call(host, "web_search", {})
    assert d.verdict == "permit" and r is not None
    d, r = govern_tool_node_call(host, "file_delete", {})
    assert d.verdict == "deny" and r is not None  # Charter #4: deny mints receipt


def test_wrap_tool_node_skips_denied_and_annotates():
    host, _ = _host()
    calls = []

    def node_fn(state):
        calls.extend(state["tool_calls"])
        return state

    governed = wrap_tool_node(node_fn, host, side_effect_class="read")
    out = governed({"tool_calls": [
        {"id": "1", "name": "web_search", "args": {}},
        {"id": "2", "name": "file_delete", "args": {}},
    ]})
    assert [c["name"] for c in calls] == ["web_search"]
    assert len(out["drako_denials"]) == 1
    assert out["drako_denials"][0]["receipt_id"] is not None


def test_require_langgraph_errors_without_dep():
    try:
        import langgraph  # noqa: F401
        pytest.skip("langgraph installed; lazy-error path N/A")
    except ImportError:
        with pytest.raises(ImportError, match="drako\\[langgraph\\]"):
            require_langgraph()


MODIFY_PROFILE = """
spec_pin: AGENT-HOOKS-0.1
default_effect: deny
tools:
  price_set:
    id: cap-price
    effect: allow
    conditions:
      - id: cap-high
        when: "amount > 100"
        effect: modify
      - id: review-capped
        when: "reviewed == True"
        effect: deny
    modifications: {"amount": 100, "reviewed": true}
    reason: capped pending review
  always_rewrite:
    id: rewrite-loop
    effect: modify
    modifications: {"tag": "rw"}
    reason: always rewrites
  cap_ok:
    id: cap-ok
    effect: allow
    conditions:
      - id: cap-huge
        when: "amount > 1000"
        effect: modify
    modifications: {"amount": 100}
    reason: capped to safe range
"""


def _modify_host():
    from drako.kernel.policies import guardian_from_yaml
    from drako.kernel.receipts import generate_keypair

    priv, pub = generate_keypair()
    return Host(guardian_from_yaml(MODIFY_PROFILE),
                HostConfig(agent_id="t", private_pem=priv, public_pem=pub))


def test_modified_args_pass_when_clean():
    host = _modify_host()
    d, r = govern_tool_node_call(host, "price_set", {"amount": 50})
    assert d.verdict == "permit"


def test_regovern_modified_args_denied_and_linked():
    """T-5: the args that RUN are re-governed; denial links both receipts."""
    from drako.adapters.langgraph import govern_with_remodify

    host = _modify_host()
    d, r, sup, final_args = govern_with_remodify(host, "price_set", {"amount": 5000})
    assert d.verdict == "deny"
    # The running verdict keeps the RULE's reason (evidence fidelity);
    # the wrapper annotates the re-govern context. The link carries the story.
    assert d.reason == "capped pending review"
    assert r is not None and r["supersedes_receipt_id"] is not None
    assert sup is not None and r["supersedes_receipt_id"] == sup["receipt_id"]
    assert final_args is None  # nothing runs


def test_reggovern_permit_after_modify_runs_modified_args():
    from drako.adapters.langgraph import govern_with_remodify

    host = _modify_host()
    d, r, sup, final_args = govern_with_remodify(host, "price_set", {"amount": 50})
    assert d.verdict == "permit" and final_args == {"amount": 50}


def test_modify_on_modify_denied_loop_guard():
    from drako.adapters.langgraph import govern_with_remodify

    host = _modify_host()
    d, r, sup, final_args = govern_with_remodify(host, "always_rewrite", {"x": 1})
    assert d.verdict == "deny"
    assert "modify-on-modify" in d.reason
    assert final_args is None


def test_modify_passing_regovern_runs_modified_args():
    """The happy path T-5 was built for: capped args re-govern clean."""
    from drako.adapters.langgraph import govern_with_remodify

    host = _modify_host()
    d, r, sup, final_args = govern_with_remodify(host, "cap_ok", {"amount": 5000})
    assert d.verdict == "permit"
    assert final_args == {"amount": 100}  # capped value is what runs
    assert sup is not None  # a modify round happened


def test_wrap_tool_node_applies_modified_args():
    host = _modify_host()

    def node_fn(state):
        return state

    governed = wrap_tool_node(node_fn, host, side_effect_class="read")
    out = governed({"tool_calls": [{"id": "1", "name": "price_set", "args": {"amount": 50}}]})
    assert out["tool_calls"][0]["args"] == {"amount": 50}
    assert "drako_denials" not in out

