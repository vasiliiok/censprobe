"""
baseline_builder.py — Aggregates N probe runs into baseline/latest.json.

After the baseline-scope simplification, only Telegram and Method-A
throttling rely on baseline data. The builder records:
  - Telegram: reachability (True if reachable in >50% runs), rtt range
              — used by the probe to reconcile BLOCKED endpoints that
              the control VPS also can't reach (port 2001, k.web NXDOMAIN,
              wrong-cert CDNs).
  - Throttling: bandwidth p10/p50 per Method-A target — used as the
                 0.3×p10 threshold for the THROTTLED verdict.

DNS / TLS / HTTP and Method-B SNI throttling are decided inline by the
probe modules from cert validity, DoH consensus and within-run relative
bandwidth. Their baseline fields stay defined on BaselineData so older
latest.json files still parse, but we no longer populate them.

Output: BaselineData model → written as baseline/latest.json
        Previous latest.json moved to baseline/archive/<date>.json
"""
from __future__ import annotations

import json
import logging
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Tests that record bandwidth in the *top-level* `bandwidth_mbps` evidence
# key — Method-A throttling targets, in other words. The Method-B SNI probe
# nests its per-SNI bandwidths under `evidence.runs[*].bandwidth_mbps` and
# is no longer aggregated into the baseline (Method B decides verdicts from
# within-run relative bandwidth). Filtering by this explicit set still
# protects against pseudo-domains like "speedtest.selectel.ru (SNI=...)"
# leaking into the throttling map.
_THROTTLING_METHOD_A_TESTS = {
    "throttling_cloudflare_baseline",
    "throttling_selectel_baseline",
    "throttling_youtube_method_a",
}

# Special telegram aggregator-meta tests that should NOT be folded into the
# per-endpoint reachability map; substring matching ("if 'health' in ...")
# would silently swallow any future test like `telegram_dc1_health_check`.
_TELEGRAM_AGGREGATE_TESTS = {
    "telegram_health_score",
}

from censprobe_core import __version__ as PROBE_CORE_VERSION
from censprobe_core.models import (
    BaselineControlPoint,
    BaselineData,
    BaselineTelegramEntry,
    BaselineThrottlingEntry,
    TestResult,
    Verdict,
)

logger = logging.getLogger(__name__)

_WORKSPACE = Path("/workspace")
_BASELINE_LATEST = _WORKSPACE / "baseline" / "latest.json"
_BASELINE_ARCHIVE = _WORKSPACE / "baseline" / "archive"


def build_baseline(
    runs: list[list[TestResult]],
    control_point: BaselineControlPoint,
    probe_core_version: str = PROBE_CORE_VERSION,
    targets_version: str = "unknown",
    validity_days: int = 7,
) -> BaselineData:
    """
    Aggregate N probe runs into a BaselineData object.

    Args:
        runs: list of N probe runs, each a list of TestResult
        control_point: metadata about the control VPS
        probe_core_version: version string of probe-core
        targets_version: version/hash of targets/*.yaml
        validity_days: how many days until baseline expires

    Returns:
        BaselineData ready to be saved as latest.json
    """
    now = datetime.now(tz=timezone.utc)
    version = now.strftime("%Y-%m-%d") + f"-control-{control_point.control_id}-01"

    baseline = BaselineData(
        version=version,
        generated_at=now,
        generated_from=control_point,
        probe_core_version=probe_core_version,
        targets_version=targets_version,
        validity_until=now + timedelta(days=validity_days),
        runs_count=len(runs),
    )

    # Flatten all results by category for aggregation
    all_results: list[TestResult] = [r for run in runs for r in run]

    baseline.telegram = _aggregate_telegram(all_results)
    baseline.throttling = _aggregate_throttling(all_results)

    logger.info(
        "Built baseline %s: telegram=%d throttling=%d",
        version,
        len(baseline.telegram),
        len(baseline.throttling),
    )
    return baseline


# ─────────────────────────────────────────────────────────────────────────────
# Per-category aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate_telegram(results: list[TestResult]) -> dict[str, BaselineTelegramEntry]:
    """Telegram endpoint: reachable if >50% runs succeeded, rtt from successful runs."""
    by_endpoint: dict[str, dict[str, Any]] = {}

    for r in results:
        if r.category != "telegram" or r.test in _TELEGRAM_AGGREGATE_TESTS:
            continue
        key = r.test  # e.g. "telegram_dc1_v4_443"
        if key not in by_endpoint:
            by_endpoint[key] = {"total": 0, "ok": 0, "rtts": []}

        by_endpoint[key]["total"] += 1
        if r.verdict == Verdict.OK:
            by_endpoint[key]["ok"] += 1
        if r.rtt_ms is not None and r.verdict == Verdict.OK:
            by_endpoint[key]["rtts"].append(r.rtt_ms)

    baseline_tg: dict[str, BaselineTelegramEntry] = {}
    for key, data in by_endpoint.items():
        if data["total"] == 0:
            continue
        reachable = (data["ok"] / data["total"]) > 0.5
        rtts = data["rtts"]
        rtt_range = [min(rtts) * 0.8, max(rtts) * 1.2] if rtts else [0.0, 9999.0]
        baseline_tg[key] = BaselineTelegramEntry(
            reachable=reachable,
            rtt_range_ms=rtt_range,
        )

    return baseline_tg


def _aggregate_throttling(results: list[TestResult]) -> dict[str, BaselineThrottlingEntry]:
    """Bandwidth percentiles (p10/p50) per domain from all Method-A runs.

    Only the Method-A throttling tests have a top-level ``bandwidth_mbps``
    in evidence; Method-B (SNI probe) nests its per-SNI bandwidths under
    ``evidence.runs[label].bandwidth_mbps``. Filter by the explicit
    Method-A test set so we don't accidentally fold in unrelated
    category="throttling" entries.
    """
    by_domain: dict[str, list[float]] = {}

    for r in results:
        if r.category != "throttling" or not r.evidence:
            continue
        if r.test not in _THROTTLING_METHOD_A_TESTS:
            continue
        bw = r.evidence.get("bandwidth_mbps")
        if bw is None or bw <= 0:
            continue
        # Domain from target. Strip URL scheme / path, drop any annotation
        # in parentheses (some tests label the target "<host> (SNI=<sni>)").
        domain = r.target.replace("https://", "").split("/")[0].split(" (")[0].strip()
        if not domain:
            continue
        by_domain.setdefault(domain, []).append(float(bw))

    baseline_thr: dict[str, BaselineThrottlingEntry] = {}
    for domain, bw_samples in by_domain.items():
        if len(bw_samples) < 2:
            continue
        # statistics.quantiles(method="inclusive") uses linear interpolation
        # between order statistics, matching numpy.percentile's default.
        # n=10 gives the nine deciles [p10, p20, ..., p90]; we want p10 and p50.
        deciles = statistics.quantiles(bw_samples, n=10, method="inclusive")
        p10 = deciles[0]
        p50 = deciles[4]
        baseline_thr[domain] = BaselineThrottlingEntry(
            bandwidth_mbps_p10=round(p10, 2),
            bandwidth_mbps_p50=round(p50, 2),
        )

    return baseline_thr


# ─────────────────────────────────────────────────────────────────────────────
# Save / archive helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_baseline(baseline: BaselineData, workspace: Path = _WORKSPACE) -> Path:
    """
    Write baseline to baseline/latest.json.
    Archive previous latest.json to baseline/archive/<version>.json.
    """
    latest = workspace / "baseline" / "latest.json"
    archive_dir = workspace / "baseline" / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    # Archive previous if it exists and is not a stub.
    #
    # The old logic keyed the archive by `<version>.json` and bailed via
    # `if not archive_path.exists(): write_text(...)`, which silently
    # *discarded* the previous baseline whenever two runs landed on the
    # same version string (version embeds only the date + control_id, so
    # any two runs on the same control point in one day collide). Append
    # an archived-at timestamp suffix so subsequent runs always land on a
    # fresh path; if the timestamp itself collides (unlikely; same UTC
    # second), fall back to a numeric counter.
    if latest.exists():
        try:
            old_text = latest.read_text()
            old = json.loads(old_text)
            old_version = old.get("version", "unknown")
            if not str(old_version).startswith("stub"):
                archived_at = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                base_name = f"{old_version}-archived-{archived_at}"
                archive_path = archive_dir / f"{base_name}.json"
                seq = 1
                while archive_path.exists():
                    archive_path = archive_dir / f"{base_name}.{seq}.json"
                    seq += 1
                archive_path.write_text(old_text)
                logger.info("Archived previous baseline → %s", archive_path.name)
        except Exception as e:
            logger.warning("Could not archive previous baseline: %s", e)

    # Write new baseline
    data = json.dumps(
        baseline.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    latest.write_text(data, encoding="utf-8")
    logger.info("Saved baseline → %s (%d bytes)", latest, len(data))
    return latest


def load_run_from_report(path: Path) -> list[TestResult]:
    """Load TestResult list from a .json report file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return [TestResult.model_validate(r) for r in raw.get("results", [])]
    except Exception as e:
        logger.error("Failed to load run from %s: %s", path, e)
        return []


