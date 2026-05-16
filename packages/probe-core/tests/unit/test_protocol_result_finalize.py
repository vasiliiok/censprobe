"""
Unit tests for :class:`ProtocolResult` and :class:`LiveSnapshot` verdict
derivation.

The truth table is small but load-bearing: it's the single place where
listener (``finalize()``) and client (``_listener_verdict``) decide the
per-protocol verdict for the JSON report and the cross-verification
table, so anything that drifts here ripples into reports/ and Grafana.

Specifically guards against a regression where the
``data_transfer_ok=True, handshake_count=0`` cell collapsed to BLOCKED
even though data flowing is a stronger signal than the (log-parsed,
fragile) handshake counter for SOCKS-routed and mtproto-proxy responders.
"""

from __future__ import annotations

import pytest
from censprobe_core.models import LiveSnapshot, ProtocolResult, Verdict


@pytest.mark.parametrize(
    ("handshake_count", "data_transfer_ok", "expected"),
    [
        (0, False, Verdict.BLOCKED),
        (5, False, Verdict.HANDSHAKE_ONLY),
        (5, True, Verdict.OK),
        # Critical case: data flowed but log-parsed handshake counter
        # stayed at zero (xray/sing-box/hysteria/mtg stdout-marker drift).
        # data_transfer_ok is the cryptographic ground truth — bytes
        # cannot arrive at the echo server / WG rx_bytes / iptables
        # PSH-ACK counter without a successful handshake. Must report OK.
        (0, True, Verdict.OK),
    ],
)
def test_protocol_result_finalize_truth_table(
    handshake_count: int,
    data_transfer_ok: bool,
    expected: Verdict,
) -> None:
    pr = ProtocolResult(
        handshake_count=handshake_count,
        data_transfer_ok=data_transfer_ok,
    )
    pr.finalize()
    assert pr.verdict == expected


def test_protocol_result_default_verdict_is_blocked() -> None:
    """A fresh ProtocolResult with no signals defaults to the strictest
    verdict — accidental ``return ProtocolResult()`` from an error path
    must not look like a passing protocol on the dashboard."""
    pr = ProtocolResult()
    assert pr.verdict == Verdict.BLOCKED


def test_live_snapshot_default_fields() -> None:
    """``LiveSnapshot`` mirrors ProtocolResult's two primary signals so
    the client can run the same predicate on a mid-session snapshot."""
    snap = LiveSnapshot()
    assert snap.handshake_count == 0
    assert snap.data_transfer_ok is False
    assert snap.data_packets is None
    assert snap.bytes_received is None


class TestSelfTestNoLongerDowngradesVerdict:
    """Since 2026-05-14 ``finalize()`` does NOT downgrade BLOCKED→ERROR
    on a failed self-test. The wedged-responder scenario on RU
    vantages is empirically a downstream effect of TSPU L7-filtering
    the C MTProxy auth_cluster RPC heartbeat — same end-to-end
    blocking the client experiences — so the operator-facing verdict
    matches the client's BLOCKED. The L7-vs-local attribution is
    surfaced via the per-protocol failure-note in listener main.

    These tests pin the verdict truth table — verdict depends ONLY on
    the data-flow signals (data_transfer_ok, handshake_count). The
    ``responder_self_test_ok`` field is diagnostic-only.
    """

    def test_blocked_stays_blocked_when_self_test_failed(self) -> None:
        # Self-test failed → wedged responder. Client probes will hit the
        # same end-to-end blocking, so listener reports BLOCKED to match
        # client. Attribution (L7 censor vs local daemon) lives in the
        # per-protocol failure-note that listener main attaches afterwards.
        pr = ProtocolResult(
            handshake_count=0,
            data_transfer_ok=False,
            responder_self_test_ok=False,
        )
        pr.finalize()
        assert pr.verdict == Verdict.BLOCKED
        assert pr.note is None

    def test_blocked_stays_blocked_when_self_test_passed(self) -> None:
        # Self-test passed — pure network-side BLOCKED. Unchanged.
        pr = ProtocolResult(
            handshake_count=0,
            data_transfer_ok=False,
            responder_self_test_ok=True,
        )
        pr.finalize()
        assert pr.verdict == Verdict.BLOCKED
        assert pr.note is None

    def test_blocked_stays_blocked_when_no_self_test_configured(self) -> None:
        # Protocols without a self-test (most of them) follow the same
        # truth table — verdict comes from the data signals only.
        pr = ProtocolResult(
            handshake_count=0,
            data_transfer_ok=False,
            responder_self_test_ok=None,
        )
        pr.finalize()
        assert pr.verdict == Verdict.BLOCKED
        assert pr.note is None

    def test_ok_unaffected_by_self_test(self) -> None:
        # If real data flowed, verdict is OK regardless of self-test
        # state (responder clearly recovered after the startup probe).
        pr = ProtocolResult(
            handshake_count=1,
            data_transfer_ok=True,
            responder_self_test_ok=False,
        )
        pr.finalize()
        assert pr.verdict == Verdict.OK

    def test_handshake_only_unaffected_by_self_test(self) -> None:
        # HANDSHAKE_ONLY implies handshake_count > 0 — also unaffected.
        pr = ProtocolResult(
            handshake_count=2,
            data_transfer_ok=False,
            responder_self_test_ok=False,
        )
        pr.finalize()
        assert pr.verdict == Verdict.HANDSHAKE_ONLY


class TestFinalizeCapAt:
    """``finalize(cap_at=...)`` constrains the derived verdict to be at
    most ``cap_at`` on the usability ladder OK > HANDSHAKE_ONLY > BLOCKED.

    The canonical use case is the dual-RU mtg vantage: iptables PSH+ACK
    counter ticks on just the WelcomePacket emission → derived verdict
    OK, but the inner Telegram session never had a chance to complete.
    ``cap_at=HANDSHAKE_ONLY`` collapses the false-OK without mutating
    the data signal (the listener really did emit bytes — we just
    don't promote them to "session worked").
    """

    def test_cap_at_handshake_only_collapses_ok(self) -> None:
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=True)
        pr.finalize(cap_at=Verdict.HANDSHAKE_ONLY)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY
        # CRITICAL: data signal preserved. The mtg WelcomePacket really
        # did flip the counter; the verdict cap is a usability
        # constraint, not a data correction.
        assert pr.data_transfer_ok is True
        assert pr.handshake_count == 1

    def test_cap_at_handshake_only_preserves_lower_verdicts(self) -> None:
        # BLOCKED is already below the cap — passes through unchanged.
        pr = ProtocolResult(handshake_count=0, data_transfer_ok=False)
        pr.finalize(cap_at=Verdict.HANDSHAKE_ONLY)
        assert pr.verdict == Verdict.BLOCKED

    def test_cap_at_handshake_only_preserves_handshake_only(self) -> None:
        # HANDSHAKE_ONLY == cap — passes through (one-directional cap).
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=False)
        pr.finalize(cap_at=Verdict.HANDSHAKE_ONLY)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY

    def test_cap_at_ok_is_noop(self) -> None:
        # cap_at=OK is the no-cap shape — every derived verdict is
        # already at or below OK, so nothing changes.
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=True)
        pr.finalize(cap_at=Verdict.OK)
        assert pr.verdict == Verdict.OK

    def test_cap_at_none_is_legacy_finalize(self) -> None:
        # No cap → original two-signal finalize behaviour.
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=True)
        pr.finalize(cap_at=None)
        assert pr.verdict == Verdict.OK

    def test_cap_at_blocked_collapses_all(self) -> None:
        # Edge case — cap=BLOCKED means "force to lowest tier". Useful
        # for future extension (e.g., DC unreachable for mtproto_orig
        # could cap at BLOCKED entirely). Verifies the rank table doesn't
        # have a gap.
        for hsk, data in [(0, False), (1, False), (1, True)]:
            pr = ProtocolResult(handshake_count=hsk, data_transfer_ok=data)
            pr.finalize(cap_at=Verdict.BLOCKED)
            assert pr.verdict == Verdict.BLOCKED


class TestFinalizeDataCountersUnavailable:
    """``finalize(data_counters_available=False)`` treats a
    ``data_transfer_ok=False`` reading as a degraded-environment artefact
    rather than evidence of blocking.

    Canonical case: listener in a container without CAP_NET_ADMIN (rootless
    docker, restricted PaaS sandbox) — iptables PSH+ACK counters never tick
    even when bytes do flow. Without this branch every successful client
    probe would be silently downgraded to HANDSHAKE_ONLY on a counter that
    was structurally unable to read.
    """

    def test_counters_unavailable_promotes_handshake_only_to_ok(self) -> None:
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=False)
        pr.finalize(data_counters_available=False)
        assert pr.verdict == Verdict.OK

    def test_counters_unavailable_keeps_zero_handshake_as_blocked(self) -> None:
        # No handshake means there's still nothing to credit — the cap
        # only changes the data-signal interpretation, not the no-signal
        # case. Otherwise we'd promote silent listeners to false OK.
        pr = ProtocolResult(handshake_count=0, data_transfer_ok=False)
        pr.finalize(data_counters_available=False)
        assert pr.verdict == Verdict.BLOCKED

    def test_counters_available_keeps_legacy_handshake_only(self) -> None:
        # CAP_NET_ADMIN present → ``data_transfer_ok=False`` is meaningful
        # "no bytes flowed", so the conservative HANDSHAKE_ONLY shape stays.
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=False)
        pr.finalize(data_counters_available=True)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY

    def test_counters_unavailable_does_not_override_real_data(self) -> None:
        # If the counter DID tick (some other code path, e.g. wg show
        # rx_bytes), the verdict is OK irrespective of the cap.
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=True)
        pr.finalize(data_counters_available=False)
        assert pr.verdict == Verdict.OK

    def test_cap_at_still_applies_when_counters_unavailable(self) -> None:
        # The mtg dual-vantage cap still wins over the counter-unavailable
        # promotion. A degraded listener on a no-DC vantage must not
        # accidentally promote handshake_count=1 to OK when the cap_at
        # branch says HANDSHAKE_ONLY is the ceiling.
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=False)
        pr.finalize(
            cap_at=Verdict.HANDSHAKE_ONLY,
            data_counters_available=False,
        )
        assert pr.verdict == Verdict.HANDSHAKE_ONLY

    def test_counters_none_is_legacy_finalize(self) -> None:
        # data_counters_available=None — older listener that didn't set
        # the field; consumer must default to "trust the counter".
        pr = ProtocolResult(handshake_count=1, data_transfer_ok=False)
        pr.finalize(data_counters_available=None)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY
