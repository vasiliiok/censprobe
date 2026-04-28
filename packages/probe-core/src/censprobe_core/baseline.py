"""
baseline.py — Baseline loading and verdict computation.

Scope (after baseline simplification):
- Telegram reconcile: convert BLOCKED→OK when control baseline shows the same
  endpoint unreachable (port 2001 / k.web NXDOMAIN / wrong-cert CDNs).
- Method A throttling threshold: probe bw vs baseline_p10 * 0.3.

DNS / TLS / HTTP and Method-B SNI throttling no longer use baseline data —
they decide inline from cert validity, DoH consensus, blockpage signatures
and within-run relative bandwidth, which avoids CDN-cert / ASN-rotation
false positives that a static control snapshot can't distinguish from real
censorship.
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
            # false positives (Telegram reconcile decisions made against
            # outdated DC reachability snapshots).
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

    Public surface is intentionally minimal:
      - compare_bandwidth: Method A throttling p10 threshold
      - compare_telegram: reconcile BLOCKED endpoints against control snapshot

    DNS / TLS / HTTP / Method-B verdicts are decided inline in their modules.
    """

    def __init__(self, baseline: BaselineData) -> None:
        self.baseline = baseline
        self._stub = baseline.is_stub()

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
