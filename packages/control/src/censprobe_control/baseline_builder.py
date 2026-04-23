"""
baseline_builder.py — Aggregates N probe runs into baseline/latest.json.

Takes raw TestResult lists from multiple runs and computes:
  - DNS: union of ASNs across runs, union of observed IPs
  - TLS: cert chain from first successful run (cert chains don't rotate often)
  - HTTP: status mode, body_length_range (min-max across runs)
  - Telegram: reachability (True if reachable in >50% runs), rtt range
  - Throttling: bandwidth p10/p50/p90 from all window samples
  - SNI throttling: p50 per SNI label across runs

Output: BaselineData model → written as baseline/latest.json
        Previous latest.json moved to baseline/archive/<date>.json
"""
from __future__ import annotations

import gzip
import json
import logging
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from censprobe_core.models import (
    BaselineControlPoint,
    BaselineData,
    BaselineDnsEntry,
    BaselineHttpEntry,
    BaselineSniThrottling,
    BaselineSniThrottlingRun,
    BaselineTelegramEntry,
    BaselineTlsEntry,
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
    probe_core_version: str = "0.3.0",
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

    baseline.dns = _aggregate_dns(all_results)
    baseline.tls = _aggregate_tls(all_results)
    baseline.http = _aggregate_http(all_results)
    baseline.telegram = _aggregate_telegram(all_results)
    baseline.throttling = _aggregate_throttling(all_results)
    baseline.sni_throttling = _aggregate_sni_throttling(all_results)

    logger.info(
        "Built baseline %s: dns=%d tls=%d http=%d telegram=%d throttling=%d",
        version,
        len(baseline.dns),
        len(baseline.tls),
        len(baseline.http),
        len(baseline.telegram),
        len(baseline.throttling),
    )
    return baseline


# ─────────────────────────────────────────────────────────────────────────────
# Per-category aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate_dns(results: list[TestResult]) -> dict[str, BaselineDnsEntry]:
    """Union of ASNs and observed IPs per domain across all runs."""
    by_domain: dict[str, dict[str, Any]] = {}

    for r in results:
        if r.category != "dns" or not r.evidence:
            continue
        # Parse domain from test name: dns_meduza_io_system → meduza.io
        domain = _domain_from_dns_test(r.test, r.target)
        if not domain:
            continue

        if domain not in by_domain:
            by_domain[domain] = {"a_records_asn": set(), "observed_ips": set()}

        ev = r.evidence
        if asn := ev.get("resolved_asn"):
            by_domain[domain]["a_records_asn"].add(asn)
        for ip in ev.get("system_ips", []):
            by_domain[domain]["observed_ips"].add(ip)
        for ip in ev.get("doh_ips", []):
            by_domain[domain]["observed_ips"].add(ip)

    return {
        domain: BaselineDnsEntry(
            a_records_asn=sorted(data["a_records_asn"]),
            observed_ips_v4=sorted(data["observed_ips"]),
        )
        for domain, data in by_domain.items()
        if data["a_records_asn"]  # only include if we got at least one ASN
    }


def _aggregate_tls(results: list[TestResult]) -> dict[str, BaselineTlsEntry]:
    """Take TLS cert chain from first successful run per domain."""
    seen: dict[str, BaselineTlsEntry] = {}

    for r in results:
        if r.category != "tls" or r.verdict != Verdict.OK or not r.evidence:
            continue

        # Extract domain from target like "1.2.3.4:meduza.io"
        domain = _domain_from_tls_target(r.target)
        if not domain or domain in seen:
            continue

        cert_chain = r.evidence.get("cert_chain_sha256", [])
        alpn = [r.evidence.get("alpn")] if r.evidence.get("alpn") else []
        cert_subject = None
        if subj := r.evidence.get("cert_subject"):
            # cert_subject is list of tuples like [("commonName", "meduza.io")]
            for item in subj:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    if item[0] == "commonName":
                        cert_subject = item[1]
                        break

        seen[domain] = BaselineTlsEntry(
            cert_chain_sha256=cert_chain,
            cert_subject_cn=cert_subject,
            alpn=[a for a in alpn if a],
        )

    return seen


def _aggregate_http(results: list[TestResult]) -> dict[str, BaselineHttpEntry]:
    """Mode status, min-max body length range per URL."""
    by_url: dict[str, dict[str, Any]] = {}

    for r in results:
        if r.category != "http" or not r.evidence:
            continue
        url = r.target
        if url not in by_url:
            by_url[url] = {"statuses": [], "body_lengths": []}

        if status := r.evidence.get("status"):
            by_url[url]["statuses"].append(status)
        if length := r.evidence.get("body_length"):
            by_url[url]["body_lengths"].append(length)

    baseline_http: dict[str, BaselineHttpEntry] = {}
    for url, data in by_url.items():
        statuses = data["statuses"]
        lengths = data["body_lengths"]
        if not statuses:
            continue

        # Mode status
        mode_status = _mode(statuses) or 200
        # Body length range: 10% below min to 10% above max for tolerance
        if lengths:
            lo = int(min(lengths) * 0.9)
            hi = int(max(lengths) * 1.1)
        else:
            lo, hi = 0, 999999999

        baseline_http[url] = BaselineHttpEntry(
            status=mode_status,
            body_length_range=[lo, hi],
        )

    return baseline_http


def _aggregate_telegram(results: list[TestResult]) -> dict[str, BaselineTelegramEntry]:
    """Telegram endpoint: reachable if >50% runs succeeded, rtt from successful runs."""
    by_endpoint: dict[str, dict[str, Any]] = {}

    for r in results:
        if r.category != "telegram" or "health" in r.test:
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
    """Bandwidth percentiles (p10/p50/p90) per domain from all Method A runs."""
    by_domain: dict[str, list[float]] = {}

    for r in results:
        if r.category != "throttling" or not r.evidence:
            continue
        # Extract bandwidth from evidence
        bw = r.evidence.get("bandwidth_mbps")
        if bw is None or bw <= 0:
            continue
        # Domain from target
        domain = r.target.replace("https://", "").split("/")[0]
        if domain not in by_domain:
            by_domain[domain] = []
        by_domain[domain].append(float(bw))

    baseline_thr: dict[str, BaselineThrottlingEntry] = {}
    for domain, bw_samples in by_domain.items():
        if len(bw_samples) < 2:
            continue
        sorted_bw = sorted(bw_samples)
        n = len(sorted_bw)
        p10 = sorted_bw[max(0, int(n * 0.10) - 1)]
        p50 = sorted_bw[int(n * 0.50)]
        baseline_thr[domain] = BaselineThrottlingEntry(
            bandwidth_mbps_p10=round(p10, 2),
            bandwidth_mbps_p50=round(p50, 2),
        )

    return baseline_thr


def _aggregate_sni_throttling(results: list[TestResult]) -> Optional[BaselineSniThrottling]:
    """Aggregate Method B SNI throttling probe results."""
    sni_results = [r for r in results if r.test == "throttling_youtube_sni_probe_method_b"]
    if not sni_results:
        return None

    # Collect bandwidth per label across all runs
    by_label: dict[str, list[float]] = {}
    for r in sni_results:
        if not r.evidence:
            continue
        for label in ("correct_sni", "googlevideo_sni", "typo_sni"):
            run_data = r.evidence.get("runs", {}).get(label, {})
            bw = run_data.get("bandwidth_mbps", 0.0)
            if bw > 0:
                if label not in by_label:
                    by_label[label] = []
                by_label[label].append(float(bw))

    if not by_label:
        return None

    runs: dict[str, BaselineSniThrottlingRun] = {}
    sni_map = {
        "correct_sni": "speedtest.selectel.ru",
        "googlevideo_sni": "googlevideo.com",
        "typo_sni": "googleviideo.com",
    }
    for label, samples in by_label.items():
        p50 = statistics.median(samples)
        runs[label] = BaselineSniThrottlingRun(
            sni=sni_map.get(label, label),
            bandwidth_mbps_p50=round(p50, 2),
            drop_pattern="none",  # on clean uplink all should be consistent
        )

    return BaselineSniThrottling(
        target_ip_host="speedtest.selectel.ru",
        runs=runs,
    )


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

    # Archive previous if it exists and is not a stub
    if latest.exists():
        try:
            old = json.loads(latest.read_text())
            old_version = old.get("version", "unknown")
            if not old_version.startswith("stub"):
                archive_path = archive_dir / f"{old_version}.json"
                if not archive_path.exists():
                    archive_path.write_text(latest.read_text())
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
    """Load TestResult list from a gzipped JSON report file."""
    try:
        with gzip.open(path, "rb") as f:
            raw = json.loads(f.read())
        return [TestResult.model_validate(r) for r in raw.get("results", [])]
    except Exception as e:
        logger.error("Failed to load run from %s: %s", path, e)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _domain_from_dns_test(test_name: str, target: str) -> Optional[str]:
    """Extract domain from DNS test name or target."""
    # test_name like "dns_meduza_io_system" → "meduza.io"
    # Or just use target directly
    if "." in target:
        return target
    # Try to reconstruct from test name: dns_meduza_io_system
    parts = test_name.replace("dns_", "").split("_")
    # Remove trailing "system", "public", etc.
    trailing = {"system", "public", "doh", "dot", "access"}
    while parts and parts[-1] in trailing:
        parts.pop()
    if parts:
        return ".".join(parts)
    return None


def _domain_from_tls_target(target: str) -> Optional[str]:
    """Extract SNI domain from TLS target like '1.2.3.4:meduza.io'."""
    if ":" in target:
        return target.split(":", 1)[1]
    return target if "." in target else None


def _mode(values: list) -> Any:
    """Return most common value in a list."""
    if not values:
        return None
    counts: dict = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return max(counts, key=counts.get)  # type: ignore[arg-type]
