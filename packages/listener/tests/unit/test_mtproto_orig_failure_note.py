"""
Tests for ``_mtproto_orig_failure_note`` — the per-vantage diagnostic
note that overrides :meth:`ProtocolResult.finalize`'s generic
"self-test failed at startup" wording on mtproto_orig ERROR results.

Two failure shapes verified live on 2026-05-13:

  * Yandex Cloud RU host (89.169.137.79) with 0/N upstreams alive at
    prune time — ``responder.unavailable=True`` — pre-Option-2 this
    produced a 145 connect/s reconnect storm, post-fix the subprocess
    isn't even launched.
  * Same host on a different day — 18/19 upstreams alive at prune
    (so the SYN-probe says "TCP/8888 reachable"), but the 12-s
    loopback self-test still times out, suggesting L7 filtering on
    the C MTProxy ``auth_cluster`` RPC stream rather than a TCP-level
    block.

Both already drive the BLOCKED→ERROR downgrade. These tests just
verify that the operator-facing ``ProtocolResult.note`` string tells
them which shape they are looking at, instead of the generic
ProtocolResult.finalize() wording.
"""

from __future__ import annotations

from dataclasses import dataclass

from censprobe_listener.main import _mtproto_orig_failure_note


@dataclass
class _FakeResponder:
    """Stand-in for :class:`MTProxyOrigResponder` carrying just the
    three fields the failure-note helper inspects."""

    unavailable: bool
    upstream_alive_count: int
    upstream_total_count: int


class TestMtprotoOrigFailureNote:
    def test_returns_none_when_self_test_passed(self) -> None:
        # OK / pass: the override exists to enrich the ERROR/BLOCKED
        # diagnostic, not to overwrite a clean session. Returning None
        # tells the caller to keep whatever finalize() set (typically
        # nothing — OK sessions don't have notes).
        r = _FakeResponder(unavailable=False, upstream_alive_count=19, upstream_total_count=19)
        assert _mtproto_orig_failure_note(r, self_test_ok=True) is None

    def test_returns_none_when_self_test_not_run(self) -> None:
        # ``self_test_ok=None`` is the "no self-test was configured"
        # signal. We must NOT emit an override note in this state,
        # otherwise an off-by-default future protocol would inherit
        # a misleading mtproto-specific diagnostic.
        r = _FakeResponder(unavailable=False, upstream_alive_count=0, upstream_total_count=0)
        assert _mtproto_orig_failure_note(r, self_test_ok=None) is None

    def test_unavailable_zero_alive_note(self) -> None:
        # Shape 1: prune found 0 alive upstreams, subprocess was never
        # launched. Note must surface "not launched" and the upstream
        # counts so the operator immediately knows it's a
        # vantage-routing problem, not L7 censorship of obfuscated2.
        r = _FakeResponder(unavailable=True, upstream_alive_count=0, upstream_total_count=16)
        note = _mtproto_orig_failure_note(r, self_test_ok=False)
        assert note is not None
        assert "0/16" in note
        assert "not launched" in note
        # Reassure the operator that the obfuscated2 protocol itself
        # is NOT what's being reported as blocked here.
        assert "NOT evidence" in note

    def test_launched_but_wedged_note(self) -> None:
        # Shape 2: prune found upstreams (subprocess WAS launched), but
        # the 12-s loopback self-test still timed out. Note must point
        # the operator at the L7 / auth_cluster hypothesis so they
        # don't waste cycles on TCP-level firewall debugging.
        r = _FakeResponder(unavailable=False, upstream_alive_count=18, upstream_total_count=19)
        note = _mtproto_orig_failure_note(r, self_test_ok=False)
        assert note is not None
        assert "18/19" in note
        assert "self-test still timed out" in note
        # The L7 / auth_cluster pointer is the load-bearing diagnostic
        # — without it the operator can't distinguish this from shape 1.
        assert "auth_cluster" in note
        # Same "NOT confirmed blocked" reassurance as shape 1.
        assert "NOT confirmed blocked" in note

    def test_unavailable_overrides_alive_count_when_both_set(self) -> None:
        # Defensive: if upstream_alive_count > 0 but unavailable=True
        # somehow (it shouldn't, but the dataclass has no invariant
        # tying them), we still pick the "not launched" branch.
        # ``unavailable`` is the source of truth for whether the
        # subprocess actually ran.
        r = _FakeResponder(unavailable=True, upstream_alive_count=3, upstream_total_count=16)
        note = _mtproto_orig_failure_note(r, self_test_ok=False)
        assert note is not None
        assert "3/16" in note
        assert "not launched" in note
