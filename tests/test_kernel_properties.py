"""Property tests: non-malleability invariants (Louck T1-T3, bounded).

Claim level: property-tested, never "proven". Seeds fixed for determinism.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from drako.kernel.authority import (
    Label,
    TrustLevel,
    ceiling_for_origin,
    may_influence,
    merge,
)

trusts = st.sampled_from(list(TrustLevel))
origins = st.one_of(
    st.text(min_size=1, max_size=12).filter(lambda s: s.strip() != ""),
    st.sampled_from(["tool:search", "memory:sess", "ctk:fixture", "user:prompt"]),
)
scopes = st.sets(
    st.sampled_from(["read", "write", "external_comms", "irreversible"]),
    max_size=4,
)


def _label(draw, trust=None):
    origin = draw(origins)
    ceiling = ceiling_for_origin(origin)
    if trust is not None:
        eff_trust = min(trust, ceiling)
    else:
        allowed = [t for t in TrustLevel if t <= ceiling]
        eff_trust = draw(st.sampled_from(allowed))
    return Label(
        origin=origin,
        trust=eff_trust,
        scope=frozenset(draw(scopes)),
    )


@settings(max_examples=200, derandomize=True)
@given(st.data())
def test_merge_never_amplifies_trust(data):
    """T2-shape: trust(merge) <= min(trust(inputs)) for all inputs."""
    a = _label(data.draw)
    b = _label(data.draw)
    m = merge(a, b)
    assert m.trust <= a.trust and m.trust <= b.trust


@settings(max_examples=200, derandomize=True)
@given(st.data())
def test_untrusted_never_authorizes_irreversible(data):
    """T1-shape: no UNTRUSTED label passes an irreversible-class check."""
    lab = _label(data.draw, trust=TrustLevel.UNTRUSTED)
    assert may_influence(lab, TrustLevel.USER, "irreversible") is False


@settings(max_examples=200, derandomize=True)
@given(st.data())
def test_scope_is_subset_after_merge(data):
    """Merged scope never exceeds either input scope."""
    a = _label(data.draw)
    b = _label(data.draw)
    m = merge(a, b)
    assert m.scope <= a.scope or m.scope <= b.scope
    assert m.scope <= (a.scope | b.scope)


@settings(max_examples=100, derandomize=True)
@given(
    prefix=st.sampled_from(["tool:", "memory:", "ctk:"]),
    suffix=st.text(min_size=1, max_size=10),
    trust=trusts,
)
def test_origin_ceiling_enforced_fail_closed(prefix, suffix, trust):
    """P1-04: asserting trust above an origin class ceiling raises ValueError."""
    origin = prefix + suffix
    ceiling = ceiling_for_origin(origin)
    if trust > ceiling:
        with pytest.raises(ValueError, match="ceiling"):
            Label(origin=origin, trust=trust)
    else:
        lab = Label(origin=origin, trust=trust)
        assert lab.trust == trust
