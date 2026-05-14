"""
modules/tcp.py — TCP reachability measurement module.

Tests TCP connectivity to (IP, port) pairs using asyncio.open_connection
(full 3-way handshake — no raw sockets).

Outcomes (verdict + method):
  OK                              — connect() succeeded
  BLOCKED + method=IP_DROPPED     — SYN sent, timeout (null-route / blackhole)
  BLOCKED + method=TCP_REFUSED    — legitimate RST from the host
                                    (port closed, service down)
  BLOCKED + method=TCP_RST_INJECTION  — ⚠ SUSPICION ONLY (not a confirmation).
                                    RST arrives in less than fast_rst_threshold_ms
                                    after connect(). Pure timing heuristic, NOT
                                    a TTL-anomaly analysis: low-latency networks
                                    (same DC, anycast, localhost) can legitimately
                                    return a REFUSED RST faster than the threshold.
                                    Surface as a lead — confirmation requires
                                    out-of-band TTL-delta capture which the MVP
                                    does not perform. Confidence capped at 0.5
                                    and evidence carries signal=suspicion +
                                    disclaimer to keep this honest in dashboards.

True TTL-delta analysis requires raw sockets (eBPF or similar) and is
deliberately not implemented in the MVP — we surface the heuristic RTT
in evidence.rtts_ms so reviewers can sanity-check it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING

from censprobe_core.config import get_config

if TYPE_CHECKING:
    from censprobe_core.config import TcpModuleConfig
from censprobe_core.models import BlockingMethod, TestResult, Verdict
from censprobe_core.server_meta import is_censoring_vantage
from censprobe_core.utils import stamp_test_elapsed

logger = logging.getLogger(__name__)


# Internal attempt outcome — verdict + blocking method (None if not blocked).
# Returned by _single_tcp_attempt and majority-voted in _test_tcp.
_AttemptOutcome = tuple[Verdict, "BlockingMethod | None"]


async def run_tcp_tests(
    targets: list[tuple[str, int]],  # (ip, port) pairs
    repeats: int = 3,
) -> list[TestResult]:
    """Run TCP reachability tests for a list of (ip, port) targets in parallel.

    Concurrency cap, SYN timeout, and the fast-RST heuristic threshold
    all come from :class:`censprobe_core.config.TcpModuleConfig`.
    """
    cfg = get_config().modules.tcp
    sem = asyncio.Semaphore(cfg.max_parallel)

    async def _bounded(ip: str, port: int) -> TestResult:
        async with sem:
            return await _test_tcp(ip, port, repeats, cfg)

    return await asyncio.gather(*[_bounded(ip, port) for ip, port in targets])


@stamp_test_elapsed
async def _test_tcp(ip: str, port: int, repeats: int, cfg: TcpModuleConfig) -> TestResult:
    """Test TCP connectivity to ip:port."""
    target = f"{ip}:{port}"
    outcomes: list[_AttemptOutcome] = []
    rtts: list[float] = []

    for _ in range(repeats):
        t0 = time.monotonic()
        outcome = await _single_tcp_attempt(ip, port, cfg)
        rtt_ms = (time.monotonic() - t0) * 1000
        outcomes.append(outcome)
        rtts.append(rtt_ms)
        await asyncio.sleep(0.5)  # small jitter between repeats

    # Aggregate: majority wins on the (verdict, method) tuple
    final_verdict, final_method = _majority(outcomes)

    # Vantage gating: the fast-RST heuristic is calibrated for inside-
    # censor vantages where a censor's RST is the only RST that arrives
    # that fast. From an uncensored VM (Frankfurt → 9.9.9.9 anycast at
    # ~5 ms) every closed port is sub-threshold and this heuristic
    # falsely paints a healthy network as RST-injected. Outside the
    # configured censoring countries (defaults: RU, BY) we downgrade
    # the method to plain TCP_REFUSED while keeping verdict=BLOCKED.
    if final_method == BlockingMethod.TCP_RST_INJECTION and not is_censoring_vantage():
        final_method = BlockingMethod.TCP_REFUSED

    # TCP_RST_INJECTION is a timing-only heuristic (fast RST below the
    # configured threshold), NOT a TTL-delta verification. The flags
    # below — explicit confidence ≤ 0.5, evidence.signal="suspicion",
    # a long-form note — are all there so the dashboard, the CLI
    # summary, and any reviewer of the JSON report can SEE that this
    # verdict is a suspicion, not a confirmation. A genuine attribution
    # would require raw-socket capture of incoming RST TTL and
    # comparison with the SYN-ACK TTL on the same path, which the MVP
    # doesn't do.
    is_heuristic_rst = final_method == BlockingMethod.TCP_RST_INJECTION
    evidence: dict[str, object] = {
        "all_verdicts": [str(v) for v, _ in outcomes],
        "all_methods": [str(m) if m else None for _, m in outcomes],
        "rtts_ms": rtts,
        "rst_detection": "rtt_heuristic_no_scapy",
    }
    if is_heuristic_rst:
        evidence["signal"] = "suspicion"
        evidence["heuristic"] = "rst_timing_only"
        evidence["heuristic_threshold_ms"] = cfg.fast_rst_threshold_ms
        evidence["disclaimer"] = (
            "Fast-RST timing heuristic only — same-AS / same-DC peers "
            "can produce sub-threshold REFUSED that this rule "
            "misclassifies. Confirm with an out-of-band TTL-delta "
            "capture before treating as evidence of TSPU injection."
        )
    return TestResult(
        test=f"tcp_{_slug(ip)}_{port}",
        category="tcp",
        target=target,
        verdict=final_verdict,
        method=final_method,
        rtt_ms=min(rtts) if rtts else None,
        attempts=repeats,
        confidence=0.5 if is_heuristic_rst else 1.0,
        notes=(
            "SUSPICION (heuristic, not confirmed): RST arrived within "
            f"{cfg.fast_rst_threshold_ms} ms of SYN, which is consistent "
            "with an in-path injector but also occurs naturally on "
            "same-AS / same-DC paths. No TTL-delta verification was "
            "performed; treat as a lead, not a verdict."
            if is_heuristic_rst
            else None
        ),
        evidence=evidence,
    )


async def _single_tcp_attempt(ip: str, port: int, cfg: TcpModuleConfig) -> _AttemptOutcome:
    """Attempt a single TCP connect; return (verdict, method) tuple."""
    try:
        t0 = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=cfg.syn_timeout_sec,
        )
        writer.close()
        # We've already proven reachability with the SYN-ACK; clean shutdown
        # is unnecessary and may race with peer-side close.
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return Verdict.OK, None

    except TimeoutError:
        return Verdict.BLOCKED, BlockingMethod.IP_DROPPED

    except ConnectionRefusedError:
        # Real RST from the host — port closed but host is alive
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms < cfg.fast_rst_threshold_ms:
            return Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION
        return Verdict.BLOCKED, BlockingMethod.TCP_REFUSED

    except OSError as e:
        # Could be ECONNRESET (RST) or other socket error
        elapsed_ms = (time.monotonic() - t0) * 1000
        err_str = str(e).lower()
        if "reset" in err_str or "refused" in err_str:
            if elapsed_ms < cfg.fast_rst_threshold_ms:
                return Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION
            return Verdict.BLOCKED, BlockingMethod.TCP_REFUSED
        return Verdict.ERROR, None

    except Exception:
        return Verdict.ERROR, None


def _majority(outcomes: list[_AttemptOutcome]) -> _AttemptOutcome:
    """Return most common (verdict, method) tuple."""
    if not outcomes:
        return Verdict.INCONCLUSIVE, None
    counts: dict[_AttemptOutcome, int] = {}
    for o in outcomes:
        counts[o] = counts.get(o, 0) + 1
    return max(counts, key=counts.get)  # type: ignore[arg-type]


def _slug(ip: str) -> str:
    return ip.replace(".", "_").replace(":", "_")
