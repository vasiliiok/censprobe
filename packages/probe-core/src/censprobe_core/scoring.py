"""
scoring.py — Server suitability scoring.

Computes three scores (entry, exit, relay) and an overall score.
All scores are in range [0.0, 100.0].

Formulas from Часть 11.2:
  entry_score = avg_protocol_reachability_from_clients * 60%
              + avg_server_uplink_quality * 30%
              + avg_latency_score * 10%

  exit_score = server_external_ip_reachable * 40%
             + server_uplink_low_censorship * 40%
             + no_geoblock_inbound * 20%

  relay_score = basic_tcp_udp_reachability * 70%
              + throughput * 30%

  overall = max(entry_score, exit_score, relay_score)
"""
from __future__ import annotations

import logging
from typing import Optional

from censprobe_core.models import (
    ListenerReport,
    ProtocolResult,
    ServerScores,
    TestResult,
    Verdict,
)

logger = logging.getLogger(__name__)


def compute_scores(
    solo_results: list[TestResult],
    listener_reports: Optional[list[ListenerReport]] = None,
) -> ServerScores:
    """
    Compute server suitability scores from solo (and optionally listener) results.

    Args:
        solo_results:     Results from solo container (what server sees from its uplink)
        listener_reports: Listener reports from client sessions
                          (dict[protocol_name → ProtocolResult])
    """
    scores = ServerScores()

    # ── DNS integrity ─────────────────────────────────────────────────────────
    dns_results = [r for r in solo_results if r.category == "dns"]
    scores.dns_integrity = _ok_pct(dns_results)

    # ── TLS integrity ─────────────────────────────────────────────────────────
    tls_results = [r for r in solo_results if r.category == "tls"]
    scores.tls_integrity = _ok_pct(tls_results)

    # ── Throttling detected ───────────────────────────────────────────────────
    thr_results = [r for r in solo_results if r.category == "throttling"]
    scores.throttling_detected = any(
        r.verdict in (Verdict.THROTTLED, Verdict.YOUTUBE_SNI_THROTTLED)
        for r in thr_results
    )

    # ── Telegram health ───────────────────────────────────────────────────────
    tg_health = next(
        (r for r in solo_results if r.test == "telegram_health_score"),
        None,
    )
    if tg_health and tg_health.evidence:
        scores.telegram_health = float(tg_health.evidence.get("health_score", 0.0)) * 100

    # ── Detected techniques ───────────────────────────────────────────────────
    techniques: set[str] = set()
    for r in solo_results:
        if r.method and r.verdict != Verdict.OK:
            techniques.add(str(r.method))
    scores.detected_techniques = sorted(techniques)

    # ── Uplink quality (from solo) ────────────────────────────────────────────
    # How well the server can access external resources
    http_results = [r for r in solo_results if r.category == "http"]
    uplink_quality = _ok_pct(http_results) / 100.0  # 0.0–1.0

    # ── Protocol reachability (from listener sessions, if available) ──────────
    proto_ok = _protocol_reachability(listener_reports)

    # ── Latency score ─────────────────────────────────────────────────────────
    # Based on median RTT to external resources
    rtts = [r.rtt_ms for r in solo_results if r.rtt_ms and r.category in ("tcp", "http")]
    latency_score = _latency_to_score(rtts) / 100.0 if rtts else 0.5

    # ── Entry score ───────────────────────────────────────────────────────────
    # entry = 60% client-reachability + 30% uplink quality + 10% latency
    scores.entry_score = round(
        proto_ok * 60.0 +
        uplink_quality * 30.0 +
        latency_score * 10.0,
        1,
    )

    # ── Exit score ────────────────────────────────────────────────────────────
    # exit = 40% uplink reachability + 40% no censorship + 20% no geoblock
    if scores.throttling_detected:
        censorship_low = max(0.0, uplink_quality - 0.2)
    else:
        censorship_low = uplink_quality
    scores.exit_score = round(
        uplink_quality * 40.0 +
        censorship_low * 40.0 +
        20.0,  # no_geoblock_inbound — assume OK (no GeoIP blocking of VPN clients)
        1,
    )

    # ── Relay score ───────────────────────────────────────────────────────────
    # relay = 70% basic TCP/UDP reachability + 30% latency
    tcp_results = [r for r in solo_results if r.category == "tcp"]
    tcp_ok = _ok_pct(tcp_results) / 100.0
    scores.relay_score = round(tcp_ok * 70.0 + latency_score * 30.0, 1)

    # ── Overall ───────────────────────────────────────────────────────────────
    scores.overall = round(max(scores.entry_score, scores.exit_score, scores.relay_score), 1)

    # ── Recommended protocols ─────────────────────────────────────────────────
    scores.recommended_protocols = _recommend_protocols(solo_results, listener_reports)

    logger.info(
        "Scores — entry=%.0f exit=%.0f relay=%.0f overall=%.0f | techniques=%s",
        scores.entry_score, scores.exit_score, scores.relay_score, scores.overall,
        scores.detected_techniques or "none",
    )
    return scores


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ok_pct(results: list[TestResult]) -> float:
    """Percent of OK results [0–100]. Returns 50 if no results (neutral)."""
    if not results:
        return 50.0
    ok = sum(1 for r in results if r.verdict == Verdict.OK)
    return (ok / len(results)) * 100.0


def _protocol_reachability(
    listener_reports: Optional[list[ListenerReport]],
) -> float:
    """
    Compute average protocol reachability fraction [0.0–1.0] from all listener sessions.

    OK → 1.0, HANDSHAKE_ONLY → 0.5, BLOCKED → 0.0
    Averages over all sessions and all protocols.
    Returns 0.5 (neutral) if no listener data.
    """
    if not listener_reports:
        return 0.5  # unknown → neutral

    total_weight = 0.0
    total_score = 0.0

    for report in listener_reports:
        for proto_name, pr in report.results.items():
            weight = 1.0
            if pr.verdict == Verdict.OK:
                score = 1.0
            elif pr.verdict == Verdict.HANDSHAKE_ONLY:
                score = 0.5
            else:
                score = 0.0
            total_score += score * weight
            total_weight += weight

    if total_weight == 0:
        return 0.5
    return total_score / total_weight


def _latency_to_score(rtts: list[float]) -> float:
    """Convert median RTT to [0–100] score. Lower RTT = higher score."""
    if not rtts:
        return 50.0
    median_rtt = sorted(rtts)[len(rtts) // 2]
    # <50ms → 100, 50–100ms → 80, 100–200ms → 60, 200–500ms → 30, >500ms → 0
    if median_rtt < 50:
        return 100.0
    elif median_rtt < 100:
        return 80.0
    elif median_rtt < 200:
        return 60.0
    elif median_rtt < 500:
        return 30.0
    return 0.0


def _recommend_protocols(
    solo_results: list[TestResult],
    listener_reports: Optional[list[ListenerReport]],
) -> list[str]:
    """
    Suggest which VPN protocols are likely to work.
    Based on signature-blocking results from solo and listener reachability.
    """
    # Track what's confirmed blocked via solo
    blocked: set[str] = set()
    for r in solo_results:
        if r.category == "protocols" and r.verdict == Verdict.BLOCKED and r.method:
            method = str(r.method)
            if "openvpn" in method:
                blocked.add("openvpn")
            elif "wireguard" in method:
                blocked.add("wireguard")
            elif "shadowsocks" in method:
                blocked.add("shadowsocks")

    # Build recommendation from listener data
    recommended: list[str] = []
    confirmed_ok: set[str] = set()
    confirmed_hs: set[str] = set()  # handshake-only (reachable but data phase blocked)

    if listener_reports:
        for report in listener_reports:
            for proto_name, pr in report.results.items():
                if pr.verdict == Verdict.OK and proto_name not in blocked:
                    confirmed_ok.add(proto_name)
                elif pr.verdict == Verdict.HANDSHAKE_ONLY and proto_name not in blocked:
                    confirmed_hs.add(proto_name)

        # Priority: confirmed OK, then HANDSHAKE_ONLY (still reachable)
        priority_order = [
            "vless_reality", "hysteria2", "amneziawg", "shadowsocks",
            "wireguard", "openvpn",
        ]
        for proto in priority_order:
            if proto in confirmed_ok:
                recommended.append(proto)
        for proto in priority_order:
            if proto in confirmed_hs and proto not in recommended:
                recommended.append(f"{proto} (handshake only)")
    else:
        # No listener data — recommend based on known RU survivability
        if "openvpn" not in blocked:
            recommended.append("vless_reality")
        if "wireguard" not in blocked and "amneziawg" not in blocked:
            recommended.append("amneziawg")
        recommended.extend(["hysteria2", "shadowsocks"])

    return recommended
