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
