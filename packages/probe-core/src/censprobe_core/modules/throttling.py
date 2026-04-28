"""
modules/throttling.py — Bandwidth throttling detection.

Implements two methods from Часть 2.5.5:

Method A: Baseline bandwidth profile
  - Download ~10 MB file from target domain
  - Measure bandwidth in 1-second sliding windows
  - Compare against baseline p10 * 0.3 threshold
  - Detect "burst-then-drop" pattern (ТСПУ signature: fast start → ~128 kbps)

Method B: YouTube SNI throttling probe
  - Three parallel downloads from speedtest.selectel.ru with different SNIs:
    1. Correct SNI (speedtest.selectel.ru) → should be full speed
    2. Trigger SNI (googlevideo.com) → throttled if ТСПУ active
    3. Typo SNI (googleviideo.com) → should be full speed (control)
  - Attribution: if only trigger SNI is throttled → SNI-level ТСПУ inspection
  - Uses curl --connect-to to send to selectel IP but with googlevideo SNI
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from censprobe_core.models import TestResult, Verdict, BlockingMethod
from censprobe_core.baseline import BaselineComparator

logger = logging.getLogger(__name__)

# Method B: SNI throttling probe config
_METHOD_B_CONFIG = {
    "control_ip_host": "speedtest.selectel.ru",
    "runs": [
        {"label": "correct_sni",    "sni": "speedtest.selectel.ru"},
        {"label": "googlevideo_sni", "sni": "googlevideo.com"},
        {"label": "typo_sni",       "sni": "googleviideo.com"},
    ],
}

# Below this bandwidth (Mbit/s) = throttled
_THROTTLE_LOW_MBPS = 1.0


async def run_throttling_tests(
    comparator: BaselineComparator,
    enable_method_b: bool = True,
) -> list[TestResult]:
    """Run both throttling detection methods."""
    results: list[TestResult] = []

    # Method A — cloudflare baseline speed test
    results.extend(await _run_method_a_baseline(comparator))

    # Method B — YouTube SNI probe
    if enable_method_b:
        result = await _run_method_b_sni_probe()
        if result:
            results.append(result)

    return results


def _decide_method_b_verdict(
    bw_correct: float, bw_trigger: float, bw_typo: float,
) -> Verdict:
    """Within-run relative bandwidth check for ТСПУ SNI throttling.

    YOUTUBE_SNI_THROTTLED iff trigger SNI is < 25% of BOTH the correct and
    typo SNIs on the same uplink in the same run — i.e., the only
    plausible explanation is that the network treats googlevideo.com SNI
    differently. INCONCLUSIVE when any of the three measurements failed
    (bw == 0); otherwise OK.
    """
    if bw_correct <= 0 or bw_trigger <= 0 or bw_typo <= 0:
        return Verdict.INCONCLUSIVE
    if bw_trigger < bw_correct * 0.25 and bw_trigger < bw_typo * 0.25:
        return Verdict.YOUTUBE_SNI_THROTTLED
    return Verdict.OK


# ─────────────────────────────────────────────────────────────────────────────
# Method A
# ─────────────────────────────────────────────────────────────────────────────

async def _run_method_a_baseline(comparator: BaselineComparator) -> list[TestResult]:
    """Method A: download test files, measure bandwidth profile."""
    results = []

    # Cloudflare speed (control — should not be throttled)
    cf_bw = await _measure_bandwidth_cloudflare()
    # bw=0.0 means the download failed with an exception — return INCONCLUSIVE,
    # not ANOMALY (there's no measurement to interpret as throttling).
    cf_verdict: Verdict
    if cf_bw == 0.0:
        cf_verdict = Verdict.INCONCLUSIVE
    else:
        cf_verdict = Verdict.OK if cf_bw > 1.0 else Verdict.ANOMALY
    results.append(TestResult(
        test="throttling_cloudflare_baseline",
        category="throttling",
        target="speed.cloudflare.com",
        verdict=cf_verdict,
        evidence={"bandwidth_mbps": round(cf_bw, 2), "role": "control_baseline"},
    ))

    # Selectel (Russian datacenter — comparison point for ТСПУ SNI throttling).
    # The root URL returns a tiny HTML landing page, not a large file, so the
    # per-second profile is typically empty. Without a sustained download we
    # cannot measure bandwidth — return INCONCLUSIVE instead of fabricating
    # a ANOMALY from a 7 KB download.
    sel_bw, sel_profile = await _measure_bandwidth_with_profile("https://speedtest.selectel.ru/", 10)
    sel_verdict: Verdict
    if not sel_profile:
        sel_verdict = Verdict.INCONCLUSIVE
    else:
        sel_verdict = Verdict.OK if sel_bw > 1.0 else Verdict.ANOMALY
    results.append(TestResult(
        test="throttling_selectel_baseline",
        category="throttling",
        target="speedtest.selectel.ru",
        verdict=sel_verdict,
        evidence={"bandwidth_mbps": round(sel_bw, 2), "profile_mbps": sel_profile},
    ))

    # YouTube (front page — googlevideo.com is also tagged so ТСПУ sees it as YT).
    yt_bw, yt_profile, yt_url = await _measure_bandwidth_googlevideo()
    # bw=0.0 means every candidate URL failed (DNS error, connection refused,
    # non-200 response, exception). Without a measurement we have nothing to
    # compare against the baseline p10 — comparator.compare_bandwidth would
    # otherwise see 0.0 < threshold and falsely return THROTTLED.
    if yt_bw == 0.0:
        yt_verdict, yt_method = Verdict.INCONCLUSIVE, None
    else:
        yt_verdict, yt_method = comparator.compare_bandwidth("youtube.com", yt_bw)
    results.append(TestResult(
        test="throttling_youtube_method_a",
        category="throttling",
        target="youtube.com",
        verdict=yt_verdict,
        method=yt_method,
        evidence={
            "source_url": yt_url,
            "bandwidth_mbps": round(yt_bw, 2),
            "profile_mbps": yt_profile,
            "burst_then_drop": _detect_burst_drop(yt_profile),
        },
    ))

    return results


async def _measure_bandwidth_cloudflare() -> float:
    """Download 10MB from Cloudflare and return Mbit/s."""
    bw, _ = await _measure_bandwidth_with_profile(
        "https://speed.cloudflare.com/__down?bytes=10000000",
        10,
    )
    return bw


async def _measure_bandwidth_googlevideo() -> tuple[float, list[float], str]:
    """
    Measure bandwidth towards Google/YouTube infrastructure.

    HTML front pages (youtube.com, google.com) finish downloading in far
    less than one second, so the per-second sampling loop in
    `_measure_bandwidth_with_profile` never records a single sample and
    returns an empty profile — useless for burst-then-drop analysis.
    We want a genuinely sustained download from Google's AS15169.

    Candidates:
      1. `dl.google.com` Chrome installer (~100MB, consistent AS15169,
         CDN edge — same path ТСПУ would see for googlevideo.com).
      2. YouTube homepage as degraded fallback.

    Returns (overall_mbps, per_second_profile_mbps, source_url_used).
    """
    for url in (
        "https://dl.google.com/dl/android/studio/ide-zips/2023.1.1.28/"
        "android-studio-2023.1.1.28-linux.tar.gz",
        "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
        "https://www.youtube.com/",
    ):
        bw, profile = await _measure_bandwidth_with_profile(url, 10)
        if bw > 0.01:
            return bw, profile, url
    return 0.0, [], "https://dl.google.com/"


async def _measure_bandwidth_with_profile(
    url: str,
    timeout_sec: int = 15,
) -> tuple[float, list[float]]:
    """
    Download URL for up to timeout_sec seconds, measuring per-second bandwidth.

    Returns:
        (overall_mbps, per_second_profile_mbps)
    """
    import httpx

    profile: list[float] = []
    total_bytes = 0
    t_start = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_sec + 5)) as client:
            async with client.stream("GET", url) as r:
                if r.status_code not in (200, 206):
                    return 0.0, []

                sec_bytes = 0
                sec_start = time.monotonic()

                async for chunk in r.aiter_bytes(chunk_size=65536):
                    total_bytes += len(chunk)
                    sec_bytes += len(chunk)
                    elapsed_sec = time.monotonic() - sec_start

                    if elapsed_sec >= 1.0:
                        profile.append((sec_bytes * 8) / (elapsed_sec * 1_000_000))
                        sec_bytes = 0
                        sec_start = time.monotonic()

                    if time.monotonic() - t_start > timeout_sec:
                        break

    except Exception as e:
        logger.debug("Bandwidth measurement failed for %s: %s", url, e)
        return 0.0, []

    total_elapsed = max(time.monotonic() - t_start, 0.001)
    overall_mbps = (total_bytes * 8) / (total_elapsed * 1_000_000)
    return overall_mbps, profile


def _detect_burst_drop(profile: list[float]) -> bool:
    """
    Detect ТСПУ "burst-then-drop" pattern:
    First 1-2 seconds at full speed, then drops to ~0.1-1 Mbit/s.
    """
    if len(profile) < 3:
        return False
    initial = max(profile[:2]) if profile else 0.0
    later = min(profile[2:]) if len(profile) > 2 else initial
    # Drop of 90%+ from initial to later = burst-then-drop
    if initial > 2.0 and later < initial * 0.1:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Method B — SNI throttling probe via curl --connect-to
# ─────────────────────────────────────────────────────────────────────────────

async def _run_method_b_sni_probe() -> Optional[TestResult]:
    """
    Method B: Three curl runs to selectel.ru IP with different SNIs.

    curl --connect-to ::speedtest.selectel.ru -k
    sends TLS ClientHello with SNI=googlevideo.com but connects to selectel IP.
    ТСПУ sees the SNI and throttles if it's in their list.

    Verdict is decided by within-run relative bandwidth, not against a
    static control snapshot. The baseline approach was unstable: a probe
    VPS with a narrower uplink than the control VPS would have all three
    SNIs measure below the baseline, masking real throttling. The
    relative check (trigger vs. correct/typo on the same uplink in the
    same run) is robust to that.
    """
    cfg = _METHOD_B_CONFIG
    control_host = cfg["control_ip_host"]

    run_results: dict[str, dict] = {}

    # Run sequentially, not in parallel. Parallel downloads compete for the
    # same uplink: on a narrow VPS (30–50 Mbit/s) three simultaneous curls
    # split the channel three ways and the relative drop of the throttled
    # SNI is masked. Sequential runs give each SNI the full uplink.
    for run in cfg["runs"]:
        try:
            result = await _curl_connect_to_run(
                sni=run["sni"],
                connect_to_host=control_host,
                label=run["label"],
            )
            run_results[run["label"]] = result
        except Exception as e:
            run_results[run["label"]] = {"bandwidth_mbps": 0.0, "error": str(e)}

    bw_correct = run_results.get("correct_sni", {}).get("bandwidth_mbps", 0.0)
    bw_trigger = run_results.get("googlevideo_sni", {}).get("bandwidth_mbps", 0.0)
    bw_typo    = run_results.get("typo_sni", {}).get("bandwidth_mbps", 0.0)

    verdict = _decide_method_b_verdict(bw_correct, bw_trigger, bw_typo)

    method = BlockingMethod.SNI_THROTTLING if verdict == Verdict.YOUTUBE_SNI_THROTTLED else None

    return TestResult(
        test="throttling_youtube_sni_probe_method_b",
        category="throttling",
        target="speedtest.selectel.ru (SNI=googlevideo.com)",
        verdict=verdict,
        method=method,
        evidence={
            "control_host": control_host,
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
) -> dict:
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
    url = f"https://{sni}/100MB"
    cmd = [
        "curl",
        "--connect-to", f"::{connect_to_host}",
        "-k",
        "-o", "/dev/null",
        "--write-out", "%{speed_download} %{time_total} %{http_code}",
        "--max-time", "30",
        "--limit-rate", "0",  # no rate limit
        "-s",
        url,
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
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=35)
        except asyncio.TimeoutError:
            # Critical: kill + reap so we don't accumulate zombie curl
            # children across runs (Method B fires three of these in
            # parallel, each baseline run, on every probe — leaks add up).
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            try:
                await proc.wait()
            except Exception:
                pass
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
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        return {"label": label, "sni": sni, "bandwidth_mbps": 0.0, "error": str(e)}
