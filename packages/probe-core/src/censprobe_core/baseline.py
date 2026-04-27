"""
baseline.py — Baseline loading and verdict computation.

Key design:
- Compare by ASN, not by IP (CDN rotates IPs within same ASN)
- Throttling: probe bandwidth < baseline_p10 * 0.3 → THROTTLED
- TLS: cert chain SHA256 mismatch → TLS_MITM or cert rotation
- HTTP: body_length in range + stable fragments SHA256 check
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from censprobe_core.models import (
    BaselineData,
    Verdict,
    BlockingMethod,
)

logger = logging.getLogger(__name__)

_WORKSPACE = Path("/workspace")
_BASELINE_PATH = _WORKSPACE / "baseline" / "latest.json"


def load_baseline(path: Path | None = None, *, quiet_if_stub: bool = False) -> BaselineData:
    """
    Load baseline from disk.

    If the file is missing or is a stub (runs_count == 0), returns an
    empty stub and logs a warning. The probe will proceed with
    INCONCLUSIVE verdicts where comparison is impossible.

    Args:
        quiet_if_stub: Suppress the "stub" warning. Used by control container
            which loads baseline just to bootstrap its own runs — complaining
            about the stub it's about to overwrite is noise.
    """
    p = path or _BASELINE_PATH
    if not p.exists():
        if not quiet_if_stub:
            logger.warning("Baseline not found at %s — using empty stub", p)
        return BaselineData()

    try:
        raw = json.loads(p.read_text())
        baseline = BaselineData.model_validate(raw)
        if baseline.is_stub():
            if not quiet_if_stub:
                logger.warning(
                    "Baseline is a stub (runs_count=%d). "
                    "Run 'docker compose --profile control up' to generate a real baseline.",
                    baseline.runs_count,
                )
        else:
            # Warn if validity_until has passed — stale baseline produces
            # false positives (DNS/TLS results compared against outdated ASNs/certs).
            if baseline.validity_until is not None:
                now = datetime.now(tz=timezone.utc)
                exp = baseline.validity_until
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if exp < now:
                    logger.warning(
                        "Baseline v%s has EXPIRED on %s. Results may be unreliable. "
                        "Run 'docker compose --profile control up' on a clean VPS.",
                        baseline.version, exp.isoformat(),
                    )
                else:
                    logger.info(
                        "Loaded baseline v%s (runs=%d, valid_until=%s)",
                        baseline.version, baseline.runs_count, exp.isoformat(),
                    )
            else:
                logger.info(
                    "Loaded baseline v%s (runs=%d, validity_until=unknown)",
                    baseline.version, baseline.runs_count,
                )
        return baseline
    except Exception as e:
        logger.error("Failed to parse baseline: %s", e)
        return BaselineData()


class BaselineComparator:
    """
    Compares probe results against baseline data.

    Usage:
        comparator = BaselineComparator(baseline)
        verdict = comparator.compare_dns("meduza.io", resolved_asn="AS99999", cert_valid=False)
    """

    def __init__(self, baseline: BaselineData) -> None:
        self.baseline = baseline
        self._stub = baseline.is_stub()

    # ── DNS ──────────────────────────────────────────────────────────────────

    def compare_dns(
        self,
        domain: str,
        resolved_asn: Optional[str],
        cert_valid: Optional[bool],
    ) -> tuple[Verdict, Optional[BlockingMethod]]:
        """
        Compare DNS resolution result with baseline.

        Returns (verdict, method).
        """
        if self._stub:
            return Verdict.INCONCLUSIVE, None

        b = self.baseline.dns.get(domain)
        if b is None:
            # Domain not in baseline — new target or first run. Cannot compare,
            # but absence from baseline is not itself evidence of DNS manipulation.
            logger.debug("Domain %s not in baseline DNS entries", domain)
            return Verdict.INCONCLUSIVE, None

        # Without a resolved ASN we can't decide between OK and poisoning —
        # ip-api 429-throttling, transient network errors, and IPs that don't
        # resolve to any ASN all land here. Returning OK would silently mask
        # real DNS poisoning whenever ASN lookup is the thing that's broken.
        if not resolved_asn:
            return Verdict.INCONCLUSIVE, None

        if resolved_asn not in b.a_records_asn:
            if cert_valid is False:
                return Verdict.DNS_POISONING, BlockingMethod.DNS_POISONING
            return Verdict.ANOMALY, None

        return Verdict.OK, None

    # ── Throttling ───────────────────────────────────────────────────────────

    def compare_bandwidth(
        self,
        domain: str,
        bandwidth_mbps: float,
    ) -> tuple[Verdict, Optional[BlockingMethod]]:
        """
        Compare measured bandwidth against baseline p10.
        THROTTLED if bandwidth < p10 * 0.3.
        """
        if self._stub:
            return Verdict.INCONCLUSIVE, None

        b = self.baseline.throttling.get(domain)
        if b is None:
            return Verdict.INCONCLUSIVE, None

        threshold = b.bandwidth_mbps_p10 * 0.3
        if b.bandwidth_mbps_p10 > 0 and bandwidth_mbps < threshold:
            return Verdict.THROTTLED, BlockingMethod.BANDWIDTH_THROTTLING

        return Verdict.OK, None

    def compare_sni_throttling(
        self,
        correct_bw: float,
        trigger_bw: float,
        typo_bw: float,
    ) -> Verdict:
        """
        Interpret Method B (SNI throttling probe) results.

        Uses baseline's per-SNI p50 as the reference: "throttled" means the
        measured bandwidth is < 40 % of the baseline p50 for that same SNI
        (a cross-border link to speedtest.selectel.ru can give sub-Mbit speeds
        from a clean jurisdiction, so an absolute threshold doesn't work).

        Args:
            correct_bw: Bandwidth with correct SNI (speedtest.selectel.ru)
            trigger_bw: Bandwidth with trigger SNI (googlevideo.com)
            typo_bw:    Bandwidth with typo SNI (googleviideo.com)

        Returns verdict per spec table (Часть 2.5.5).
        """
        snit = self.baseline.sni_throttling
        baseline_runs = snit.runs if snit is not None else {}

        def _ref(label: str, fallback_floor: float) -> float:
            """Baseline p50 for this label, with a small floor so x<ref*0.4
            still makes sense when we have no baseline at all."""
            entry = baseline_runs.get(label)
            if entry and entry.bandwidth_mbps_p50 > 0:
                return entry.bandwidth_mbps_p50
            return fallback_floor

        ref_correct = _ref("correct_sni", 0.2)
        ref_trigger = _ref("googlevideo_sni", 0.2)
        ref_typo = _ref("typo_sni", 0.2)

        def throttled(measured: float, ref: float) -> bool:
            return measured < ref * 0.4

        correct_throttled = throttled(correct_bw, ref_correct)
        trigger_throttled = throttled(trigger_bw, ref_trigger)
        typo_throttled = throttled(typo_bw, ref_typo)

        if correct_throttled and trigger_throttled and typo_throttled:
            # Everything is slower than baseline — could be channel-wide issue
            # (e.g. probe VPS uplink narrower than control baseline).
            # Before calling INCONCLUSIVE, do a within-run relative check:
            # if googlevideo is dramatically slower than BOTH control SNIs
            # (even when all are below the absolute baseline threshold),
            # that relative suppression is SNI-throttling signal.
            if (
                correct_bw > 0 and typo_bw > 0 and trigger_bw > 0
                and trigger_bw < correct_bw * 0.25
                and trigger_bw < typo_bw * 0.25
            ):
                return Verdict.YOUTUBE_SNI_THROTTLED
            return Verdict.INCONCLUSIVE

        if trigger_throttled and not correct_throttled and not typo_throttled:
            return Verdict.YOUTUBE_SNI_THROTTLED

        if trigger_throttled and typo_throttled and not correct_throttled:
            # Typo also throttled — suspicious, not the classic SNI signature.
            return Verdict.ANOMALY

        # Extra relative check even when absolute thresholds don't trigger:
        # if googlevideo is more than 4× slower than both control SNIs,
        # treat as throttled regardless of baseline comparison.
        if (
            correct_bw > 0 and typo_bw > 0 and trigger_bw > 0
            and trigger_bw < correct_bw * 0.25
            and trigger_bw < typo_bw * 0.25
        ):
            return Verdict.YOUTUBE_SNI_THROTTLED

        return Verdict.OK

    # ── TLS ──────────────────────────────────────────────────────────────────

    def compare_tls(
        self,
        domain: str,
        cert_chain_sha256: list[str],
        cert_issuer_cn: Optional[str] = None,
    ) -> tuple[Verdict, Optional[BlockingMethod]]:
        """Compare TLS cert chain against baseline.

        CDN-aware: global CDNs (Google, Cloudflare, Akamai, Fastly, Meta)
        rotate leaf certs per PoP / region. The SHA256 of the DE baseline
        cert will never match the cert returned to a Russian probe — every
        session would appear as a false MITM. To avoid this, when the
        issuer CN is the same as the baseline issuer, the leaf-hash mismatch
        is treated as CDN rotation (OK). A real ТСПУ MITM replaces the cert
        with a self-signed one whose issuer CN differs from any legit CA.
        """
        if self._stub:
            return Verdict.INCONCLUSIVE, None

        b = self.baseline.tls.get(domain)
        if b is None:
            return Verdict.INCONCLUSIVE, None

        if b.cert_chain_sha256 and cert_chain_sha256 != b.cert_chain_sha256:
            # Leaf cert hash differs from baseline. Before flagging MITM:
            # check whether the issuer (CA) is the same. If issuer matches,
            # this is CDN edge-cert rotation (same CA, different leaf) — not
            # a substitution attack. ТСПУ MITM boxes use self-signed certs
            # with an issuer that differs from any legitimate certificate
            # authority stored in the baseline.
            if (
                cert_issuer_cn is not None
                and b.cert_issuer_cn is not None
                and cert_issuer_cn == b.cert_issuer_cn
            ):
                return Verdict.OK, None
            return Verdict.ANOMALY, BlockingMethod.TLS_HANDSHAKE_FAILURE

        return Verdict.OK, None

    # ── HTTP ─────────────────────────────────────────────────────────────────

    def compare_http(
        self,
        url: str,
        status: int,
        body_length: int,
        tls_ok: bool,
        is_blockpage: bool = False,
        expected_status: Optional[int] = None,
    ) -> tuple[Verdict, Optional[BlockingMethod]]:
        """Compare HTTP response against baseline.

        If the URL has no baseline entry (new target or first run), fall back
        to ``expected_status`` from the target YAML.  This prevents neutral
        control targets (expected_status: 200) from appearing INCONCLUSIVE
        just because the control container hasn't run yet or hasn't recorded
        them.
        """
        if self._stub:
            return Verdict.INCONCLUSIVE, None

        b = self.baseline.http.get(url)
        if b is None:
            # No baseline entry — use expected_status as a minimal sanity check.
            if expected_status is not None:
                if is_blockpage:
                    return Verdict.BLOCKED, BlockingMethod.BLOCKPAGE_RETURNED
                if status in (403, 451) and tls_ok and not is_blockpage:
                    return Verdict.GEOBLOCK_NOT_CENSORSHIP, None
                return (Verdict.OK, None) if status == expected_status else (Verdict.ANOMALY, None)
            return Verdict.INCONCLUSIVE, None

        # Geoblock detection: TLS works, cert valid, but 403/451
        if status in (403, 451) and tls_ok and not is_blockpage:
            return Verdict.GEOBLOCK_NOT_CENSORSHIP, None

        if is_blockpage:
            return Verdict.BLOCKED, BlockingMethod.BLOCKPAGE_RETURNED

        if status != b.status:
            return Verdict.ANOMALY, None

        lo, hi = b.body_length_range[0], b.body_length_range[1]
        if not (lo <= body_length <= hi):
            return Verdict.ANOMALY, None

        return Verdict.OK, None

    # ── Telegram ─────────────────────────────────────────────────────────────

    def compare_telegram(
        self,
        endpoint_key: str,
        reachable: bool,
        rtt_ms: Optional[float],
    ) -> Verdict:
        """Compare Telegram endpoint reachability against baseline."""
        if self._stub:
            return Verdict.INCONCLUSIVE

        b = self.baseline.telegram.get(endpoint_key)
        if b is None:
            return Verdict.INCONCLUSIVE

        if not reachable and b.reachable:
            return Verdict.BLOCKED

        return Verdict.OK
