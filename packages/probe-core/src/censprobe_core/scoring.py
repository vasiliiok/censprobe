"""
scoring.py — Server suitability scoring.

Computes three scores (entry, exit, relay) and an overall score.
All scores are in range [0.0, 100.0].

Weights are read from
:class:`censprobe_core.config.ScoringConfig` (censprobe.yaml):

  entry_score = protocol_reachability·W_p + uplink·W_u + latency·W_l
  exit_score  = uplink·W_u + censorship·W_c
  relay_score = tcp·W_t + latency·W_l
  overall     = max(entry, exit, relay)

The recommended-protocol list is built from
:data:`censprobe_core.protocol_registry.PROTOCOLS` ordered by the
operator-supplied ``protocols.priority`` from censprobe.yaml.
"""
from __future__ import annotations

import logging

from censprobe_core.config import get_config
from censprobe_core.models import (
    ListenerReport,
    ServerScores,
    TestResult,
    Verdict,
)
from censprobe_core.protocol_registry import known_names

logger = logging.getLogger(__name__)


# Verdicts that represent actual blocking / unreachable targets.
# Single source of truth — runner._summarize and the dashboard "blocked"
# filter import this so the three views (CLI summary, saved JSON summary,
# Grafana) never disagree on what counts as blocked.
BLOCKING_VERDICTS: frozenset[Verdict] = frozenset({
    Verdict.BLOCKED,
    Verdict.DNS_BLOCKED,
    Verdict.DOH_BLOCKED,
    Verdict.DNS_POISONING,
    Verdict.IP_DROPPED,
    Verdict.RST_INJECTED,
    Verdict.REFUSED,
    Verdict.YOUTUBE_SNI_THROTTLED,
})


# Same set as BLOCKING_VERDICTS but materialised as plain strings — what
# the CLI summaries, JSON summaries, and Grafana queries actually compare
# against. Centralising the conversion here means callers never have to
# rebuild the set with `{str(v) for v in BLOCKING_VERDICTS}` and a typo
# (e.g. forgetting `str()`) cannot silently miscount a category as
# "other".
BLOCKING_VERDICT_STRINGS: frozenset[str] = frozenset(str(v) for v in BLOCKING_VERDICTS)


def compute_scores(
    solo_results: list[TestResult],
    listener_reports: list[ListenerReport] | None = None,
) -> ServerScores:
    """
    Compute server suitability scores from solo (and optionally listener) results.

    Args:
        solo_results:     Results from solo container (what server sees from its uplink)
        listener_reports: Listener reports from client sessions
                          (dict[protocol_name → ProtocolResult])
    """
    scores = ServerScores()
    weights = get_config().scoring

    # ── DNS integrity ─────────────────────────────────────────────────────────
    dns_results = [r for r in solo_results if r.category == "dns"]
    scores.dns_integrity = _ok_pct(dns_results)

    # ── TLS integrity ─────────────────────────────────────────────────────────
    tls_results = [r for r in solo_results if r.category == "tls"]
    scores.tls_integrity = _ok_pct(tls_results)

    # ── Throttling detected ───────────────────────────────────────────────────
    # Only Method-B SNI throttling produces a non-OK verdict here.
    thr_results = [r for r in solo_results if r.category == "throttling"]
    scores.throttling_detected = any(
        r.verdict == Verdict.YOUTUBE_SNI_THROTTLED for r in thr_results
    )

    # ── Telegram health ───────────────────────────────────────────────────────
    tg_health = next(
        (r for r in solo_results if r.test == "telegram_health_score"),
        None,
    )
    if tg_health and tg_health.evidence:
        scores.telegram_health = float(tg_health.evidence.get("health_score", 0.0)) * 100

    # ── Detected techniques ───────────────────────────────────────────────────
    # Only collect from verdicts that represent actual blocking — INCONCLUSIVE
    # and GEOBLOCK_NOT_CENSORSHIP results often have a method set (for context)
    # but should not contribute to the detected-techniques list.
    techniques: set[str] = set()
    for r in solo_results:
        if r.method and r.verdict in BLOCKING_VERDICTS:
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
    # entry = protocol·W_p + uplink·W_u + latency·W_l   (×100)
    #
    # Weights come from censprobe.yaml's scoring.entry section.
    w_e = weights.entry
    scores.entry_score = round(
        (proto_ok * w_e.protocol +
         uplink_quality * w_e.uplink +
         latency_score * w_e.latency) * 100.0,
        1,
    )

    # ── Exit score ────────────────────────────────────────────────────────────
    # exit = uplink·W_u + censorship·W_c   (×100)
    #
    # The historical formula included a third "no_geoblock" axis worth
    # 20 points, but inbound geoblocking is never actually measured —
    # the term degenerated to a duplicated copy of uplink_quality and
    # made operators think a real signal existed. Until geoblock is
    # measured for real (would need outbound probes from RU IP back at
    # the test server), the score is a two-axis weighted average that
    # honestly reflects what we know.
    w_x = weights.exit
    if scores.throttling_detected:
        censorship_low = max(0.0, uplink_quality - 0.2)
    else:
        censorship_low = uplink_quality
    scores.exit_score = round(
        (uplink_quality * w_x.uplink +
         censorship_low * w_x.censorship) * 100.0,
        1,
    )

    # ── Relay score ───────────────────────────────────────────────────────────
    # relay = tcp·W_t + latency·W_l   (×100)
    w_r = weights.relay
    tcp_results = [r for r in solo_results if r.category == "tcp"]
    tcp_ok = _ok_pct(tcp_results) / 100.0
    scores.relay_score = round(
        (tcp_ok * w_r.tcp + latency_score * w_r.latency) * 100.0,
        1,
    )

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
    """Percent of OK results [0–100].

    Returns 0.0 (NOT 50.0) when the result list is empty: a module that
    crashed and produced zero results must not silently look the same
    as "all targets passed cleanly at 50%". The neutral fallback was
    masking module failures and the runner's `module_failures` flag
    was never consumed downstream — so a half-broken probe scored ≥40
    on multiple axes for free. With 0.0 the score correctly bottoms out
    when data is missing; runner.summary still records which modules
    failed for the dashboard.
    """
    if not results:
        return 0.0
    ok = sum(1 for r in results if r.verdict == Verdict.OK)
    return (ok / len(results)) * 100.0


def _protocol_reachability(
    listener_reports: list[ListenerReport] | None,
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
    listener_reports: list[ListenerReport] | None,
) -> list[str]:
    """Suggest which VPN protocols are likely to work, in priority order.

    Order comes from ``censprobe.yaml::protocols.priority`` (defaults
    to ``[vless_reality, hysteria2, amneziawg, shadowsocks, wireguard,
    openvpn]``). Names are validated against
    :data:`censprobe_core.protocol_registry.PROTOCOLS` — entries the
    operator added that aren't real protocols are silently dropped (a
    typo doesn't become a recommendation).
    """
    cfg = get_config()
    valid = set(known_names())
    priority_order = [n for n in cfg.protocols.priority if n in valid]
    # Append any registered protocol not mentioned in priority — keeps
    # "novel" protocols recommendable even before the operator gets
    # around to placing them in the priority list.
    for n in valid:
        if n not in priority_order:
            priority_order.append(n)

    # Solo-side signature-blocked protocols (substring match against
    # the BlockingMethod enum value) — these are excluded from
    # recommendations even if a listener happens to handshake-only.
    blocked: set[str] = set()
    for r in solo_results:
        if r.category != "protocols" or r.verdict != Verdict.BLOCKED or not r.method:
            continue
        method = str(r.method)
        for name in valid:
            # The BlockingMethod enum encodes protocol-specific blocking
            # as e.g. "openvpn_signature_blocked" / "wireguard_signature_blocked".
            if name in method:
                blocked.add(name)

    confirmed_ok: set[str] = set()
    confirmed_hs: set[str] = set()
    if listener_reports:
        for report in listener_reports:
            for proto_name, pr in report.results.items():
                if proto_name in blocked:
                    continue
                if pr.verdict == Verdict.OK:
                    confirmed_ok.add(proto_name)
                elif pr.verdict == Verdict.HANDSHAKE_ONLY:
                    confirmed_hs.add(proto_name)

        recommended: list[str] = []
        for proto in priority_order:
            if proto in confirmed_ok:
                recommended.append(proto)
        for proto in priority_order:
            if proto in confirmed_hs and proto not in recommended:
                recommended.append(f"{proto} (handshake only)")
        return recommended

    # No listener data — fall back to "what the priority list suggests,
    # minus protocols solo's signature probes already blocked".
    return [proto for proto in priority_order if proto not in blocked]
