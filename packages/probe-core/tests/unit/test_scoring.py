"""
Pure-unit tests for scoring.py — helpers + ``compute_scores``.

Helpers (``_ok_pct``, ``_latency_to_score``, ``_protocol_reachability``)
are pure functions — no fixture needed. ``compute_scores`` and
``_recommend_protocols`` consult :func:`get_config`, so they use the
``loaded_config`` fixture defined in ``conftest.py``.
"""

from __future__ import annotations

import pytest
from censprobe_core.models import (
    BlockingMethod,
    ListenerReport,
    ProtocolResult,
    TestResult,
    Verdict,
)
from censprobe_core.scoring import (
    _latency_to_score,
    _ok_pct,
    _protocol_reachability,
    _recommend_protocols,
    compute_scores,
)


def _make_result(
    verdict: Verdict,
    *,
    test: str = "dns_example_com_system",
    category: str = "dns",
    rtt_ms: float | None = None,
    method: BlockingMethod | None = None,
) -> TestResult:
    return TestResult(
        test=test,
        category=category,
        target="example.com",
        verdict=verdict,
        rtt_ms=rtt_ms,
        method=method,
    )


def _make_listener_report(results: dict[str, Verdict]) -> ListenerReport:
    from datetime import UTC, datetime

    proto_results = {}
    for name, verdict in results.items():
        pr = ProtocolResult(verdict=verdict)
        if verdict == Verdict.OK:
            pr.handshake_count = 1
            pr.data_transfer_ok = True
        elif verdict == Verdict.HANDSHAKE_ONLY:
            pr.handshake_count = 1
        proto_results[name] = pr
    return ListenerReport(
        test_id="t",
        session_id="s",
        listener_started_at=datetime.now(UTC),
        results=proto_results,
    )


# ─────────────────────────────────────────────────────────────────────────────
# _ok_pct
# ─────────────────────────────────────────────────────────────────────────────


class TestOkPct:
    def test_empty_returns_zero_not_neutral(self) -> None:
        # Comment in scoring.py is explicit: empty == 0.0, not 50.0.
        # Returning 50 would mask a crashed module that produced no results.
        assert _ok_pct([]) == pytest.approx(0.0)

    def test_all_ok_returns_100(self) -> None:
        results = [_make_result(Verdict.OK) for _ in range(5)]
        assert _ok_pct(results) == pytest.approx(100.0)

    def test_all_blocked_returns_zero(self) -> None:
        results = [_make_result(Verdict.BLOCKED) for _ in range(5)]
        assert _ok_pct(results) == pytest.approx(0.0)

    def test_half_ok_returns_fifty(self) -> None:
        results = [
            _make_result(Verdict.OK),
            _make_result(Verdict.OK),
            _make_result(Verdict.BLOCKED),
            _make_result(Verdict.BLOCKED),
        ]
        assert _ok_pct(results) == pytest.approx(50.0)

    def test_inconclusive_does_not_count_as_ok(self) -> None:
        results = [
            _make_result(Verdict.OK),
            _make_result(Verdict.INCONCLUSIVE),
            _make_result(Verdict.INCONCLUSIVE),
        ]
        assert _ok_pct(results) == pytest.approx(100.0 / 3)


# ─────────────────────────────────────────────────────────────────────────────
# _latency_to_score
# ─────────────────────────────────────────────────────────────────────────────


class TestLatencyToScore:
    @pytest.mark.parametrize(
        ("rtt_ms", "expected"),
        [
            (10.0, 100.0),  # <50
            (49.999, 100.0),  # boundary
            (50.0, 80.0),  # 50–100
            (99.999, 80.0),
            (100.0, 60.0),  # 100–200
            (150.0, 60.0),
            (200.0, 30.0),  # 200–500
            (499.999, 30.0),
            (500.0, 0.0),  # >=500
            (5000.0, 0.0),
        ],
    )
    def test_boundaries(self, rtt_ms: float, expected: float) -> None:
        # Median of [x] is x — single-element lists let us probe boundary
        # values directly without thinking about even-length tie-breakers.
        assert _latency_to_score([rtt_ms]) == pytest.approx(expected)

    def test_empty_returns_neutral_fifty(self) -> None:
        # Distinct from _ok_pct: latency really is "unknown" → neutral 50.
        # Comment in scoring.py — empty rtts means the probe didn't run,
        # not that it failed.
        assert _latency_to_score([]) == pytest.approx(50.0)

    def test_uses_median_not_mean(self) -> None:
        # 9 fast samples + 1 slow outlier should resolve to "fast".
        rtts = [10.0] * 9 + [10000.0]
        assert _latency_to_score(rtts) == pytest.approx(100.0)


# ─────────────────────────────────────────────────────────────────────────────
# _protocol_reachability
# ─────────────────────────────────────────────────────────────────────────────


class TestProtocolReachability:
    def test_no_reports_returns_neutral(self) -> None:
        # Empty == "unknown", not "0% reachable".
        assert _protocol_reachability(None) == pytest.approx(0.5)
        assert _protocol_reachability([]) == pytest.approx(0.5)

    def test_all_ok_returns_one(self) -> None:
        report = _make_listener_report({"wireguard": Verdict.OK, "openvpn": Verdict.OK})
        assert _protocol_reachability([report]) == pytest.approx(1.0)

    def test_handshake_only_scores_half(self) -> None:
        report = _make_listener_report({"wireguard": Verdict.HANDSHAKE_ONLY})
        assert _protocol_reachability([report]) == pytest.approx(0.5)

    def test_blocked_scores_zero(self) -> None:
        report = _make_listener_report({"wireguard": Verdict.BLOCKED})
        assert _protocol_reachability([report]) == pytest.approx(0.0)

    def test_mixed_averages_correctly(self) -> None:
        # 1.0 + 0.5 + 0.0 over 3 protocols == 0.5
        report = _make_listener_report(
            {
                "wireguard": Verdict.OK,
                "openvpn": Verdict.HANDSHAKE_ONLY,
                "shadowsocks": Verdict.BLOCKED,
            }
        )
        assert _protocol_reachability([report]) == pytest.approx(0.5)


# ─────────────────────────────────────────────────────────────────────────────
# compute_scores — top-level integration of all helpers + config weights
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("loaded_config")
class TestComputeScores:
    def test_empty_results_produces_floor_scores(self) -> None:
        scores = compute_scores([], None)
        # No solo data: dns/tls integrity = 0 (empty = 0 by design),
        # uplink_quality = 0, latency_score = 0.5 (neutral).
        # protocol_reach = 0.5 (no listener reports).
        # entry = (0.5*0.6 + 0.0*0.3 + 0.5*0.1) * 100 = 35.0
        assert scores.entry_score == pytest.approx(35.0)
        # exit = (0.0*0.6 + 0.0*0.4) * 100 = 0.0
        assert scores.exit_score == pytest.approx(0.0)
        # relay = (0.0*0.7 + 0.5*0.3) * 100 = 15.0
        assert scores.relay_score == pytest.approx(15.0)
        assert scores.overall == pytest.approx(35.0)
        assert scores.dns_integrity == pytest.approx(0.0)
        assert scores.tls_integrity == pytest.approx(0.0)
        assert scores.throttling_detected is False
        assert scores.detected_techniques == []

    def test_all_ok_solo_scores_high(self) -> None:
        results = [
            _make_result(Verdict.OK, category="dns"),
            _make_result(Verdict.OK, category="tls"),
            _make_result(Verdict.OK, category="http", rtt_ms=20.0),
            _make_result(Verdict.OK, category="tcp", rtt_ms=20.0),
        ]
        scores = compute_scores(results, None)
        assert scores.dns_integrity == pytest.approx(100.0)
        assert scores.tls_integrity == pytest.approx(100.0)
        # uplink = 1.0 (all http OK), latency_score = 1.0 (rtt < 50ms),
        # protocol_reach = 0.5 (no listener data).
        # entry = (0.5*0.6 + 1.0*0.3 + 1.0*0.1) * 100 = 70.0
        assert scores.entry_score == pytest.approx(70.0)
        # exit = (1.0*0.6 + 1.0*0.4) * 100 = 100.0
        assert scores.exit_score == pytest.approx(100.0)
        # relay = (1.0*0.7 + 1.0*0.3) * 100 = 100.0
        assert scores.relay_score == pytest.approx(100.0)
        assert scores.overall == pytest.approx(100.0)

    def test_throttling_detected_lowers_exit(self) -> None:
        # Method-B SNI throttling should trigger detection AND knock 0.2
        # off the censorship axis of the exit score.
        results = [
            _make_result(Verdict.OK, category="http", rtt_ms=20.0),
            _make_result(
                Verdict.YOUTUBE_SNI_THROTTLED,
                category="throttling",
                test="throttling_youtube_sni_probe_method_b",
                method=BlockingMethod.SNI_THROTTLING,
            ),
        ]
        scores = compute_scores(results, None)
        assert scores.throttling_detected is True
        # uplink_quality = 1.0 (one OK http), censorship_low = max(0, 1.0-0.2) = 0.8
        # exit = (1.0*0.6 + 0.8*0.4) * 100 = 92.0
        assert scores.exit_score == pytest.approx(92.0)

    def test_detected_techniques_only_from_blocking_verdicts(self) -> None:
        # GEOBLOCK_NOT_CENSORSHIP carries a method for context but must
        # NOT contribute to detected techniques. INCONCLUSIVE same.
        results = [
            _make_result(Verdict.BLOCKED, method=BlockingMethod.IP_DROPPED),
            _make_result(
                Verdict.GEOBLOCK_NOT_CENSORSHIP,
                method=BlockingMethod.TLS_HANDSHAKE_FAILURE,
            ),
            _make_result(Verdict.INCONCLUSIVE, method=BlockingMethod.QUIC_DROPPED),
        ]
        scores = compute_scores(results, None)
        # Only IP_DROPPED is allowed in detected techniques.
        assert scores.detected_techniques == ["ip_dropped"]

    def test_listener_ok_contributes_to_entry(self) -> None:
        # With one listener-OK protocol, protocol_reach = 1.0.
        # entry = (1.0*0.6 + 0.0*0.3 + 0.5*0.1) * 100 = 65.0
        listener = _make_listener_report({"wireguard": Verdict.OK})
        scores = compute_scores([], [listener])
        assert scores.entry_score == pytest.approx(65.0)

    def test_recommended_protocols_on_listener_ok(self) -> None:
        # Priority order is [shadowsocks, wireguard, openvpn] (default
        # cfg). Listener says wg+openvpn OK; shadowsocks not in report.
        # Expect ordering by priority: wireguard before openvpn.
        listener = _make_listener_report({"wireguard": Verdict.OK, "openvpn": Verdict.OK})
        scores = compute_scores([], [listener])
        assert scores.recommended_protocols == ["wireguard", "openvpn"]


# ─────────────────────────────────────────────────────────────────────────────
# _recommend_protocols
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("loaded_config")
class TestRecommendProtocols:
    def test_no_listener_falls_back_to_priority(self) -> None:
        # Default protocols.priority == [shadowsocks, wireguard, openvpn].
        # Without listener data, return the priority list (filter unknowns).
        rec = _recommend_protocols([], None)
        assert rec[:3] == ["shadowsocks", "wireguard", "openvpn"]

    def test_signature_blocked_drops_protocol(self) -> None:
        # A solo-side wireguard signature-blocked verdict should remove
        # wireguard from the no-listener-data fallback list.
        results = [
            TestResult(
                test="wg_handshake_probe",
                category="protocols",
                target="x",
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.WIREGUARD_SIGNATURE_BLOCKED,
            ),
        ]
        rec = _recommend_protocols(results, None)
        assert "wireguard" not in rec

    def test_handshake_only_appends_with_suffix(self) -> None:
        # OK protocols come first; HANDSHAKE_ONLY follows with suffix.
        listener = _make_listener_report(
            {"wireguard": Verdict.OK, "shadowsocks": Verdict.HANDSHAKE_ONLY}
        )
        rec = _recommend_protocols([], [listener])
        assert "wireguard" in rec
        assert "shadowsocks (handshake only)" in rec
        # OK before handshake-only.
        assert rec.index("wireguard") < rec.index("shadowsocks (handshake only)")
