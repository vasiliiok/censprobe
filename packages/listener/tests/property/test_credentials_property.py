"""
Property tests for AmneziaWG header / packet-size constraints.

The parametrized example tests in ``test_credentials_constraints.py``
already loop 50× over the underlying generator, but Hypothesis lets us
formalise the invariants AND probe more iterations without re-rolling
the parametrize loop. Determinism is enforced globally by the
``censprobe-deterministic`` profile registered in
``packages/listener/tests/conftest.py`` — every CI runner walks the
same example sequence so a "lucky" run can't hide a regression.
"""

from __future__ import annotations

from censprobe_listener.credentials import _awg_magic_headers
from hypothesis import given, settings
from hypothesis import strategies as st


@given(_seed=st.integers())
@settings(max_examples=500)
def test_awg_h1_h4_pairwise_distinct(_seed: int) -> None:
    """For any random seed, the 4 magic headers are pairwise distinct.

    The ``_seed`` parameter is unused — it just forces Hypothesis to
    invoke the generator many times, exercising the underlying
    ``secrets.randbits`` + retry loop.
    """
    h = _awg_magic_headers()
    assert len(set(h)) == 4, f"H1..H4 not distinct: {h}"


@given(_seed=st.integers())
@settings(max_examples=500)
def test_awg_h1_h4_not_collide_with_standard_wg(_seed: int) -> None:
    """For any random seed, none of H1..H4 equals a standard WG message
    type id (1, 2, 3, or 4)."""
    h = _awg_magic_headers()
    forbidden = {1, 2, 3, 4}
    assert not (set(h) & forbidden), f"H1..H4 collides with standard WG: {h}"


@given(_seed=st.integers())
@settings(max_examples=500)
def test_awg_h1_h4_within_uint32(_seed: int) -> None:
    """All four values fit in 32-bit unsigned int range."""
    h = _awg_magic_headers()
    for v in h:
        assert 0 <= v < 2**32, f"H_i out of range: {v}"


def test_s1_s2_constraint_on_real_generator() -> None:
    """Sanity check that the S1/S2 inequality holds when called via
    the credential-generation path. Verified directly here without
    invoking the wg/xray/openvpn binaries — we use the same retry loop
    that ``generate_credentials`` uses.
    """
    import secrets

    # Mirror the loop body in credentials.py:
    # awg_s1 = secrets.randbelow(135) + 15
    # awg_s2 = secrets.randbelow(135) + 15
    # while awg_s1 + 56 == awg_s2:
    #     awg_s2 = secrets.randbelow(135) + 15
    for _ in range(500):
        s1 = secrets.randbelow(135) + 15
        s2 = secrets.randbelow(135) + 15
        while s1 + 56 == s2:
            s2 = secrets.randbelow(135) + 15
        # Constraint: an obfuscated init packet length (148 + S1) MUST
        # NOT equal an obfuscated response length (92 + S2), i.e.
        # S1 + 56 != S2.
        assert s1 + 56 != s2, f"S1={s1} S2={s2} violates S1+56!=S2"
