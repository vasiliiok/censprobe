"""Tests for the telegram-dc-reach preflight signal threading.

The 2026-05-14 dual-RU vantage audit (ya-b run) surfaced a misleading
``asymmetric DPI`` attribution for mtproto_proxy / mtproto_proxy_alt
when the listener itself sat behind ТСПУ and couldn't reach the
Telegram DC fleet. mtg's iptables PSH+ACK counter ticked on just the
WelcomePacket emission so the listener verdict promoted to OK; client
timed out on resPQ with the asymmetric-DPI marker; cross-verifier
defaulted to "client-side DPI dropped the data plane".

The fix wires the preflight ``telegram-dc-reach`` result through both
the listener verdict (capping mtg-based protocols at HANDSHAKE_ONLY
when DC egress is blocked) and the cross-verify snapshot (rewriting
the note to "listener egress to Telegram DCs blocked"). This file
covers the listener-side half — the cross-verifier rewrite is tested
in ``packages/client/tests/unit/test_cross_verification.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from censprobe_core.models import Verdict
from censprobe_listener.main import (
    _data_counters_available,
    _extract_dc_reach_ok,
    _extract_iptables_cap_ok,
    _finalize_protocol_result,
)
from censprobe_listener.preflight import CheckResult


class TestExtractDcReachOk:
    """``_extract_dc_reach_ok`` pulls the right ternary from preflight."""

    def test_ok_status_returns_true(self) -> None:
        results = [CheckResult("telegram-dc-reach", "ok", "3/3 DCs reachable")]
        assert _extract_dc_reach_ok(results) is True

    def test_warn_status_returns_false(self) -> None:
        # The "warn" path is the one that drives all the downstream
        # attribution changes — production RU/BY vantages hit this.
        results = [
            CheckResult(
                "telegram-dc-reach",
                "warn",
                "0/3 Telegram DCs reachable from listener egress",
            )
        ]
        assert _extract_dc_reach_ok(results) is False

    def test_skip_status_returns_none(self) -> None:
        # ``skip`` is "the check didn't run on this host" — we treat it
        # as no-signal so the verdict logic doesn't override anything.
        results = [CheckResult("telegram-dc-reach", "skip", "stubbed in unit test")]
        assert _extract_dc_reach_ok(results) is None

    def test_missing_check_returns_none(self) -> None:
        results = [CheckResult("conntrack", "ok", "65k entries free")]
        assert _extract_dc_reach_ok(results) is None

    def test_other_checks_ignored(self) -> None:
        # Only the telegram-dc-reach result drives the signal; mixing
        # other warn/ok rows must not leak into the result.
        results = [
            CheckResult("conntrack", "warn", "table 60% full"),
            CheckResult("telegram-dc-reach", "ok", "2/3 DCs reachable"),
            CheckResult("orphan-rules", "ok", "no orphan rules"),
        ]
        assert _extract_dc_reach_ok(results) is True


class TestExtractIptablesCapOk:
    """``_extract_iptables_cap_ok`` mirrors the dc-reach extractor for the
    CAP_NET_ADMIN preflight signal that drives
    ``LiveSnapshot.data_counters_available``.
    """

    def test_ok_status_returns_true(self) -> None:
        results = [CheckResult("iptables-cap", "ok", "counters available")]
        assert _extract_iptables_cap_ok(results) is True

    def test_warn_status_returns_false(self) -> None:
        # Hit on rootless-docker / no-CAP_NET_ADMIN containers; the
        # downstream effect is that data_counters_available propagates
        # False and the client cross-verify stops downgrading client=OK.
        results = [CheckResult("iptables-cap", "warn", "Operation not permitted")]
        assert _extract_iptables_cap_ok(results) is False

    def test_missing_check_returns_none(self) -> None:
        results = [CheckResult("telegram-dc-reach", "ok", "3/3 DCs reachable")]
        assert _extract_iptables_cap_ok(results) is None

    def test_skip_status_returns_none(self) -> None:
        results = [CheckResult("iptables-cap", "skip", "stubbed in test")]
        assert _extract_iptables_cap_ok(results) is None


class TestDataCountersAvailablePerProtocol:
    """``_data_counters_available`` answers: do counters work for this
    protocol's data-phase signal on this host?
    """

    def test_iptables_protocol_inherits_cap_ok(self) -> None:
        for name in ("openvpn", "mtproto_proxy", "mtproto_proxy_alt", "mtproto_orig"):
            assert _data_counters_available(name, True) is True

    def test_iptables_protocol_inherits_cap_warn(self) -> None:
        for name in ("openvpn", "mtproto_proxy", "mtproto_proxy_alt", "mtproto_orig"):
            assert _data_counters_available(name, False) is False

    def test_iptables_protocol_inherits_cap_none(self) -> None:
        for name in ("openvpn", "mtproto_proxy"):
            assert _data_counters_available(name, None) is None

    def test_non_iptables_protocol_always_true(self) -> None:
        # SS/VLESS/Hy2 signal data via the loopback echo server; WG/AWG
        # use kernel ``wg show`` rx_bytes. Both paths are independent of
        # the iptables-cap preflight, so the per-protocol availability
        # is True regardless of the host-wide cap state.
        for name in ("shadowsocks", "vless_reality", "hysteria2", "wireguard", "amneziawg"):
            assert _data_counters_available(name, True) is True
            assert _data_counters_available(name, False) is True
            assert _data_counters_available(name, None) is True


@dataclass
class _FakeResponder:
    """Mimics the duck-typed surface ``_finalize_protocol_result`` reads.

    Real responders carry the same attributes (``connection_count``,
    ``data_transfer_ok``, ``echo_server``) — the fake just lets us pin
    the values without standing up a full subprocess.
    """

    connection_count: int = 0
    data_transfer_ok: bool = False
    echo_server: object | None = None  # No-throughput path in finalize


class TestFinalizeDcReachGate:
    """``_finalize_protocol_result`` caps mtg verdicts at HANDSHAKE_ONLY
    when listener egress to Telegram DCs is blocked. Non-mtg protocols
    and the dc_reach_ok=True/None paths must stay unchanged.
    """

    def test_mtg_data_ok_with_dc_unreachable_caps_at_handshake_only(self) -> None:
        # WelcomePacket flipped data_transfer_ok=True, but DC was
        # unreachable at preflight — the canonical dual-RU bug shape.
        # Post-cap_at refactor: data_transfer_ok stays True (the listener
        # really DID emit bytes; we just don't promote them to "session
        # worked"). The cap collapses verdict to HANDSHAKE_ONLY.
        r = _FakeResponder(connection_count=1, data_transfer_ok=True)
        pr = _finalize_protocol_result("mtproto_proxy", r, dc_reach_ok=False)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY
        assert pr.data_transfer_ok is True  # truthful: bytes were emitted
        assert pr.handshake_count == 1
        # Note that explains why OK→HANDSHAKE_ONLY collapsed is set by
        # _finalize_protocol_result itself (not the caller anymore).
        assert pr.note is not None
        assert "listener egress" in pr.note.lower()

    def test_mtg_alt_data_ok_with_dc_unreachable_caps_at_handshake_only(self) -> None:
        # Same logic on the alt-port mtg bind.
        r = _FakeResponder(connection_count=1, data_transfer_ok=True)
        pr = _finalize_protocol_result("mtproto_proxy_alt", r, dc_reach_ok=False)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY
        assert pr.data_transfer_ok is True

    def test_mtg_data_ok_with_dc_reachable_stays_ok(self) -> None:
        # When DC is reachable, the OK reading is honest — mtg both
        # accepted the FakeTLS AND successfully relayed bytes to/from
        # the real DC backend.
        r = _FakeResponder(connection_count=1, data_transfer_ok=True)
        pr = _finalize_protocol_result("mtproto_proxy", r, dc_reach_ok=True)
        assert pr.verdict == Verdict.OK
        assert pr.data_transfer_ok is True

    def test_mtg_data_ok_with_dc_reach_none_stays_ok(self) -> None:
        # ``None`` is the no-signal default for older preflight stubs.
        # Verdict logic must be back-compatible — no signal means no
        # override.
        r = _FakeResponder(connection_count=1, data_transfer_ok=True)
        pr = _finalize_protocol_result("mtproto_proxy", r, dc_reach_ok=None)
        assert pr.verdict == Verdict.OK

    def test_non_mtg_protocol_ignores_dc_reach(self) -> None:
        # The override is mtg-only: shadowsocks' OK reading doesn't
        # depend on Telegram DC reachability. Passing dc_reach_ok=False
        # for SS must NOT cap its verdict at HANDSHAKE_ONLY.
        r = _FakeResponder(connection_count=1, data_transfer_ok=True)
        pr = _finalize_protocol_result("shadowsocks", r, dc_reach_ok=False)
        assert pr.verdict == Verdict.OK

    def test_mtg_handshake_only_unchanged_with_dc_unreachable(self) -> None:
        # If the responder already produced HANDSHAKE_ONLY (data_ok
        # was False on its own), the gate is a no-op — already at the
        # cap.
        r = _FakeResponder(connection_count=1, data_transfer_ok=False)
        pr = _finalize_protocol_result("mtproto_proxy", r, dc_reach_ok=False)
        assert pr.verdict == Verdict.HANDSHAKE_ONLY

    def test_mtg_blocked_unchanged_with_dc_unreachable(self) -> None:
        # Zero handshake_count + no data: stays BLOCKED regardless of
        # the dc_reach signal. The gate must not promote BLOCKED.
        r = _FakeResponder(connection_count=0, data_transfer_ok=False)
        pr = _finalize_protocol_result("mtproto_proxy", r, dc_reach_ok=False)
        assert pr.verdict == Verdict.BLOCKED
