"""Contract: SelfTestCapable Protocol is satisfied by the responders
that implement preflight prune-based self-tests.

Before 2026-05 the listener-main code path that surfaces the
"upstreams unreachable" prune diagnostic used ``getattr(responder,
'unavailable', False)`` + ``getattr(responder, 'upstream_alive_count',
0)`` — duck-typed coupling to MTProxyOrigResponder-specific attribute
names. A rename or removal of any of these attributes would silently
disable the diagnostic.

The :class:`SelfTestCapable` Protocol pins the contract; this test
makes it impossible to forget the contract when adding a future
prune-capable responder (e.g. a hypothetical ``mtproto_orig_v2``).
"""

from __future__ import annotations

from censprobe_listener._responder_dispatch import SelfTestCapable
from censprobe_listener.mtproto_orig_responder import MTProxyOrigResponder


def test_mtproto_orig_responder_implements_self_test_capable() -> None:
    # Build a minimal instance — the Protocol check only inspects
    # attribute presence + types, not runtime state, so we don't need
    # to actually call .start().
    r = MTProxyOrigResponder(port=2080, secret="ee" + "00" * 17)
    assert isinstance(r, SelfTestCapable), (
        "MTProxyOrigResponder must satisfy SelfTestCapable; "
        "did one of {unavailable, upstream_alive_count, "
        "upstream_total_count} get renamed?"
    )


def test_protocol_attributes_have_expected_types() -> None:
    # The Protocol declares three @property-decorated ints/bools.
    # Pin the concrete return types so mypy violations in the
    # implementation surface as test failures here too.
    r = MTProxyOrigResponder(port=2080, secret="ee" + "00" * 17)
    # Before start(): default state is "not yet pruned, not skipped".
    assert isinstance(r.unavailable, bool)
    assert isinstance(r.upstream_alive_count, int)
    assert isinstance(r.upstream_total_count, int)
