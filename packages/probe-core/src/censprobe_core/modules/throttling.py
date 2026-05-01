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
(YOUTUBE_SNI_THROTTLED). The within-run relative comparison is robust to
varying probe uplink — a baseline snapshot from a fast control VPS would
mis-flag every narrow-uplink probe as throttled, which is why Method A
(absolute baseline-derived threshold) was retired.

We use ``/100MB`` instead of ``/`` so the download runs long enough for the
per-second throughput to dominate over RTT/TLS-handshake noise (the root
page is ~7 KB and completes in <200 ms).
"""
from __future__ import annotations

import asyncio
import logging
import time

from censprobe_core.models import BlockingMethod, TestResult, Verdict

logger = logging.getLogger(__name__)

_METHOD_B_CONFIG = {
    "control_ip_host": "speedtest.selectel.ru",
    "runs": [
        {"label": "correct_sni",    "sni": "speedtest.selectel.ru"},
        {"label": "googlevideo_sni", "sni": "googlevideo.com"},
        {"label": "typo_sni",       "sni": "googleviideo.com"},
    ],
}


async def run_throttling_tests() -> list[TestResult]:
    """Run Method-B SNI throttling probe."""
    results: list[TestResult] = []
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
# Method B — SNI throttling probe via curl --connect-to
# ─────────────────────────────────────────────────────────────────────────────

async def _run_method_b_sni_probe() -> TestResult | None:
    """
    Three curl runs to selectel.ru IP with different SNIs.

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
            # children across runs.
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
