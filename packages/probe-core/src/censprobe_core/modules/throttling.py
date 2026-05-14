"""
modules/throttling.py — Bandwidth throttling detection.

Method B (per Vetrov/Habr 2024): YouTube SNI throttling probe via
``curl --connect-to``.

Three sequential downloads from speedtest.selectel.ru with different SNIs:
  1. Correct SNI (speedtest.selectel.ru) → unthrottled control
  2. Trigger SNI (googlevideo.com)      → throttled if ТСПУ active
  3. Typo SNI    (googleviideo.com)     → unthrottled control

Attribution: if only the trigger SNI runs at <25% of BOTH the correct and
typo runs on the same uplink in the same run, that's SNI-level inspection
(verdict=THROTTLED, method=sni_throttling). The within-run relative
comparison is robust to varying probe uplink — a baseline snapshot from a
fast control VPS would mis-flag every narrow-uplink probe as throttled,
which is why Method A (absolute baseline-derived threshold) was retired.

We use ``/100MB`` instead of ``/`` so the download runs long enough for the
per-second throughput to dominate over RTT/TLS-handshake noise (the root
page is ~7 KB and completes in <200 ms).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING, Any

from censprobe_core.config import get_config

if TYPE_CHECKING:
    from censprobe_core.config import ThrottlingModuleConfig
from censprobe_core.models import BlockingMethod, TestResult, Verdict
from censprobe_core.server_meta import is_censoring_vantage

logger = logging.getLogger(__name__)


async def run_throttling_tests() -> list[TestResult]:
    """Run Method-B SNI throttling probe.

    Vantage gating: Method B targets a single throughput-test endpoint
    (defaults to ``speedtest.selectel.ru``). From an uncensored vantage
    the geographic RTT × BDP product dominates the bandwidth
    measurement and the relative comparison ``trigger < threshold ×
    correct`` becomes noise — there is no TSPU in the path, yet
    routing variance can push one SNI below the threshold. We skip
    the probe entirely outside the configured censoring countries
    (defaults: RU, BY) and emit a single INCONCLUSIVE marker so the
    dashboard sees "not run" instead of "false negative".

    Tunable in censprobe.yaml under ``modules.throttling``:
      * ``target_url`` — the URL to download (Selectel by default);
      * ``correct_sni`` / ``typo_sni`` / ``trigger_sni`` — the three
        SNIs sent to the same IP for the relative comparison;
      * ``bandwidth_ratio_threshold`` — the trigger/(min(correct,typo))
        ratio below which the verdict flips to THROTTLED;
      * ``curl_timeout_sec`` — per-run curl timeout;
      * ``require_censoring_vantage`` — set to false to force the
        probe to run regardless of vantage country (useful when the
        operator has supplied a custom target_url tied to their own
        in-country control).
    """
    cfg = get_config().modules.throttling

    if cfg.require_censoring_vantage and not is_censoring_vantage():
        return [
            TestResult(
                test="throttling_youtube_sni_probe_method_b",
                category="throttling",
                target=f"{cfg.correct_sni} (SNI={cfg.trigger_sni})",
                verdict=Verdict.INCONCLUSIVE,
                evidence={"reason": "non_censoring_vantage_method_b_skipped"},
                confidence=0.0,
                notes=(
                    "Method B is a censor-specific test against a single throughput "
                    "endpoint; from an uncensored vantage the relative bandwidth "
                    "comparison is dominated by geographic latency rather than SNI "
                    "policy. Override modules.throttling.require_censoring_vantage "
                    "if you have supplied a custom target_url tied to your own "
                    "in-country control."
                ),
            )
        ]

    results: list[TestResult] = []
    result = await _run_method_b_sni_probe(cfg)
    if result:
        results.append(result)
    return results


def _decide_method_b_verdict(
    bw_correct: float,
    bw_trigger: float,
    bw_typo: float,
    threshold_ratio: float,
) -> Verdict:
    """Within-run relative bandwidth check for SNI throttling.

    THROTTLED iff the trigger SNI is below ``threshold_ratio`` of BOTH
    the correct and typo SNIs on the same uplink in the same run — i.e.
    the only plausible explanation is that the network treats the
    trigger SNI differently. INCONCLUSIVE when any of the three
    measurements failed (bw == 0); otherwise OK.
    """
    if bw_correct <= 0 or bw_trigger <= 0 or bw_typo <= 0:
        return Verdict.INCONCLUSIVE
    if bw_trigger < bw_correct * threshold_ratio and bw_trigger < bw_typo * threshold_ratio:
        return Verdict.THROTTLED
    return Verdict.OK


# ─────────────────────────────────────────────────────────────────────────────
# Method B — SNI throttling probe via curl --connect-to
# ─────────────────────────────────────────────────────────────────────────────


async def _run_method_b_sni_probe(cfg: ThrottlingModuleConfig) -> TestResult | None:
    """
    Three sequential curl runs to ``cfg.correct_sni`` IP with different SNIs.

    curl --connect-to ::<correct_sni> -k
    sends TLS ClientHello with SNI=<trigger_sni> but connects to the
    correct-SNI IP. The censor sees the SNI and throttles if it matches
    their list.

    Verdict is decided by within-run relative bandwidth, not against a
    static control snapshot. The baseline approach was unstable: a
    probe VPS with a narrower uplink than the control VPS would have
    all three SNIs measure below the baseline, masking real throttling.
    The relative check (trigger vs. correct/typo on the same uplink in
    the same run) is robust to that.
    """
    control_host = cfg.correct_sni
    runs_spec = (
        ("correct_sni", cfg.correct_sni),
        ("googlevideo_sni", cfg.trigger_sni),
        ("typo_sni", cfg.typo_sni),
    )

    run_results: dict[str, dict[str, Any]] = {}

    # Run sequentially, not in parallel. Parallel downloads compete for the
    # same uplink: on a narrow VPS (30–50 Mbit/s) three simultaneous curls
    # split the channel three ways and the relative drop of the throttled
    # SNI is masked. Sequential runs give each SNI the full uplink.
    for label, sni in runs_spec:
        try:
            result = await _curl_connect_to_run(
                sni=sni,
                connect_to_host=control_host,
                label=label,
                target_url=cfg.target_url,
                timeout_sec=cfg.curl_timeout_sec,
            )
            run_results[label] = result
        except Exception as e:
            run_results[label] = {"bandwidth_mbps": 0.0, "error": str(e)}

    bw_correct = run_results.get("correct_sni", {}).get("bandwidth_mbps", 0.0)
    bw_trigger = run_results.get("googlevideo_sni", {}).get("bandwidth_mbps", 0.0)
    bw_typo = run_results.get("typo_sni", {}).get("bandwidth_mbps", 0.0)

    verdict = _decide_method_b_verdict(
        bw_correct,
        bw_trigger,
        bw_typo,
        cfg.bandwidth_ratio_threshold,
    )

    method = BlockingMethod.SNI_THROTTLING if verdict == Verdict.THROTTLED else None

    return TestResult(
        test="throttling_youtube_sni_probe_method_b",
        category="throttling",
        target=f"{control_host} (SNI={cfg.trigger_sni})",
        verdict=verdict,
        method=method,
        evidence={
            "control_host": control_host,
            "target_url": cfg.target_url,
            "trigger_sni": cfg.trigger_sni,
            "typo_sni": cfg.typo_sni,
            "ratio_threshold": cfg.bandwidth_ratio_threshold,
            "runs": run_results,
            "bandwidth_correct_sni_mbps": round(bw_correct, 2),
            "bandwidth_googlevideo_sni_mbps": round(bw_trigger, 2),
            "bandwidth_typo_sni_mbps": round(bw_typo, 2),
        },
        confidence=0.95 if verdict != Verdict.INCONCLUSIVE else 0.3,
        notes="Method B (Vetrov/Habr 2024): SNI-level ТСПУ throttling attribution",
    )


async def _curl_connect_to_run(
    sni: str,
    connect_to_host: str,
    label: str,
    target_url: str,
    timeout_sec: float,
) -> dict[str, Any]:
    """
    Run curl --connect-to to send traffic to connect_to_host with SNI=sni.

    Command:
        curl --connect-to ::<connect_to_host> -k -o /dev/null
             --write-out '%{speed_download}' --max-time 30
             https://<sni>/100MB

    -k disables cert verification (selectel will serve its own cert, not sni's).
    --connect-to makes curl resolve <sni> as <connect_to_host>.

    We use the /100MB path instead of the root / so the download runs long
    enough for the per-second measurement to reflect steady-state throughput
    (the root page is ~7 KB and completes in <200 ms, making speed_download
    dominated by RTT rather than actual bandwidth — especially important when
    ТСПУ throttles to 128 kbps, which takes 0.44 s to transfer 7 KB and
    would give ~16 KB/s vs the unthrottled ~350 KB/s instead of the much
    cleaner 16 KB/s vs 50 MB/s with a sustained download).
    """
    # ``target_url`` is configured to be the path under the control
    # host (``https://speedtest.selectel.ru/100MB`` by default). We
    # rewrite the host portion to the trigger SNI so curl's SNI matches
    # the on-wire ClientHello, while ``--connect-to`` keeps the actual
    # TCP destination at the control host's IP.
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(target_url)
    sni_url = urlunparse(parsed._replace(netloc=sni))

    cmd = [
        "curl",
        "--connect-to",
        f"::{connect_to_host}",
        "-k",
        "-o",
        "/dev/null",
        "--write-out",
        "%{speed_download} %{time_total} %{http_code}",
        "--max-time",
        str(int(timeout_sec)),
        "--limit-rate",
        "0",  # no rate limit
        "-s",
        sni_url,
    ]

    proc = None
    try:
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec + 5)
        except TimeoutError:
            # Critical: kill + reap so we don't accumulate zombie curl
            # children across runs.
            with contextlib.suppress(ProcessLookupError, OSError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            return {"label": label, "sni": sni, "bandwidth_mbps": 0.0, "error": "timeout"}

        elapsed = time.monotonic() - t0

        out = stdout.decode(errors="replace").strip()
        parts = out.split()
        speed_bytes_sec = float(parts[0]) if parts else 0.0
        time_total = float(parts[1]) if len(parts) > 1 else elapsed
        http_code = int(parts[2]) if len(parts) > 2 else 0

        bandwidth_mbps = (speed_bytes_sec * 8) / 1_000_000

        return {
            "label": label,
            "sni": sni,
            "bandwidth_mbps": bandwidth_mbps,
            "speed_bytes_sec": speed_bytes_sec,
            "time_total_sec": time_total,
            "http_code": http_code,
            "curl_returncode": proc.returncode,
        }

    except FileNotFoundError:
        return {"label": label, "sni": sni, "bandwidth_mbps": 0.0, "error": "curl_not_found"}
    except Exception as e:
        # Best-effort cleanup of a half-spawned process.
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(Exception):
                proc.kill()
                await proc.wait()
        return {"label": label, "sni": sni, "bandwidth_mbps": 0.0, "error": str(e)}
