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


class TestSelfTestDowngrade:
    """``finalize()`` reclassifies BLOCKED → ERROR when the listener
    self-test confirmed the responder couldn't even handshake against
    itself, preserving the strict "BLOCKED ≡ confirmed block" invariant.
    """

    def test_blocked_downgraded_to_error_when_self_test_failed(self) -> None:
        pr = ProtocolResult(
            handshake_count=0,
            data_transfer_ok=False,
            responder_self_test_ok=False,
        )
        pr.finalize()
        assert pr.verdict == Verdict.ERROR
        assert pr.note is not None and "responder self-test" in pr.note

    def test_blocked_preserved_when_self_test_passed(self) -> None:
        """If the responder DID handshake against itself, a session-time
        BLOCKED is a confirmed network block — the downgrade must NOT
        fire and the verdict must stay BLOCKED."""
        pr = ProtocolResult(
            handshake_count=0,
            data_transfer_ok=False,
            responder_self_test_ok=True,
        )
        pr.finalize()
        assert pr.verdict == Verdict.BLOCKED
        assert pr.note is None

    def test_blocked_preserved_when_no_self_test_configured(self) -> None:
        """Protocols without a self-test (None) must follow the
        unmodified truth table — the field is purely additive."""
        pr = ProtocolResult(
            handshake_count=0,
            data_transfer_ok=False,
            responder_self_test_ok=None,
        )
        pr.finalize()
        assert pr.verdict == Verdict.BLOCKED
        assert pr.note is None

    def test_ok_not_downgraded_even_if_self_test_failed(self) -> None:
        """If real data did flow, the responder clearly recovered after
        the startup self-test — never reclassify OK on a stale signal."""
        pr = ProtocolResult(
            handshake_count=1,
            data_transfer_ok=True,
            responder_self_test_ok=False,
        )
        pr.finalize()
        assert pr.verdict == Verdict.OK

    def test_handshake_only_not_downgraded(self) -> None:
        """HANDSHAKE_ONLY implies handshake_count > 0 — the responder is
        clearly accepting connections, so the self-test must have been
        a transient glitch. Don't rewrite the verdict."""
        pr = ProtocolResult(
            handshake_count=2,
            data_transfer_ok=False,
            responder_self_test_ok=False,
        )
        pr.finalize()
        assert pr.verdict == Verdict.HANDSHAKE_ONLY
