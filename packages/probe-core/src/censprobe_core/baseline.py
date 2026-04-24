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


def load_baseline(path: Path | None = None) -> BaselineData:
    """
    Load baseline from disk.

    If the file is missing or is a stub (runs_count == 0), returns an
    empty stub and logs a warning. The probe will proceed with
    INCONCLUSIVE verdicts where comparison is impossible.
    """
    p = path or _BASELINE_PATH
    if not p.exists():
        logger.warning("Baseline not found at %s — using empty stub", p)
        return BaselineData()

    try:
        raw = json.loads(p.read_text())
        baseline = BaselineData.model_validate(raw)
        if baseline.is_stub():
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
            logger.debug("Domain %s not in baseline DNS entries", domain)
            return Verdict.ANOMALY, None

        if resolved_asn and resolved_asn not in b.a_records_asn:
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

        Args:
            correct_bw: Bandwidth with correct SNI (speedtest.selectel.ru)
            trigger_bw: Bandwidth with trigger SNI (googlevideo.com)
            typo_bw:    Bandwidth with typo SNI (googleviideo.com)

        Returns verdict per spec table (Часть 2.5.5).
        """
        if self._stub:
            # Without baseline we still can reason about relative values
            pass

        # Threshold for "low" bandwidth: < 1 Mbit/s is burst-then-drop pattern
        _LOW = 1.0

        all_low = correct_bw < _LOW and trigger_bw < _LOW and typo_bw < _LOW
        if all_low:
            return Verdict.INCONCLUSIVE  # channel problem overall

        # Trigger is throttled, others are fine → SNI throttling
        if trigger_bw < _LOW and correct_bw >= _LOW and typo_bw >= _LOW:
            return Verdict.YOUTUBE_SNI_THROTTLED

        # Both trigger and typo are throttled → anomaly
        if trigger_bw < _LOW and typo_bw < _LOW and correct_bw >= _LOW:
            return Verdict.ANOMALY

        return Verdict.OK

    # ── TLS ──────────────────────────────────────────────────────────────────

    def compare_tls(
        self,
        domain: str,
        cert_chain_sha256: list[str],
    ) -> tuple[Verdict, Optional[BlockingMethod]]:
        """Compare TLS cert chain against baseline."""
        if self._stub:
            return Verdict.INCONCLUSIVE, None

        b = self.baseline.tls.get(domain)
        if b is None:
            return Verdict.INCONCLUSIVE, None

        if b.cert_chain_sha256 and cert_chain_sha256 != b.cert_chain_sha256:
            # Could be cert rotation (rare) or MITM
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
    ) -> tuple[Verdict, Optional[BlockingMethod]]:
        """Compare HTTP response against baseline."""
        if self._stub:
            return Verdict.INCONCLUSIVE, None

        b = self.baseline.http.get(url)
        if b is None:
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
