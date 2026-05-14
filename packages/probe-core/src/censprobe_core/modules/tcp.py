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

from censprobe_core._tcp_kernel_rtt import read_kernel_rtt_us
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


# Sentinel meaning "kernel RTT not available for this attempt" — caller
# falls back to wall-clock timing. Same shape as _AttemptOutcome (tuple
# return) so the per-attempt loop in _test_tcp stays linear.
_NO_KERNEL_RTT: int | None = None


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

    # Per-attempt wall-clock fallbacks for when TCP_INFO is unavailable
    # (non-Linux, getsockopt failure). Used only as a last resort — the
    # kernel-side tcpi_rtt path is preferred because it's invariant to
    # asyncio event-loop scheduling overhead (verified on Vultr 2026-05-14:
    # under Phase-A load, wall-clock RTT inflated 100× while kernel RTT
    # stayed accurate).
    wallclock_rtts: list[float] = []
    for _ in range(repeats):
        t0 = time.monotonic()
        outcome, kernel_rtt_us = await _single_tcp_attempt(ip, port, cfg)
        wallclock_ms = (time.monotonic() - t0) * 1000
        outcomes.append(outcome)
        wallclock_rtts.append(wallclock_ms)
        # Prefer kernel-measured RTT when available — see
        # ``_tcp_kernel_rtt.read_kernel_rtt_us`` for the rationale.
        if kernel_rtt_us is not None:
            rtts.append(kernel_rtt_us / 1000.0)
        else:
            rtts.append(wallclock_ms)
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
    # rtts is what we report as rtt_ms (kernel-preferred); wallclock_rtts
    # preserves the old measurement for evidence-only debugging — useful
    # for spotting event-loop scheduling spikes (a wallclock value 100×
    # the kernel rtt is the diagnostic signature of a busy Phase A).
    evidence: dict[str, object] = {
        "all_verdicts": [str(v) for v, _ in outcomes],
        "all_methods": [str(m) if m else None for _, m in outcomes],
        "rtts_ms": rtts,
        "wallclock_rtts_ms": wallclock_rtts,
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


async def _single_tcp_attempt(
    ip: str, port: int, cfg: TcpModuleConfig
) -> tuple[_AttemptOutcome, int | None]:
    """Attempt a single TCP connect; return ``(outcome, kernel_rtt_us)``.

    ``kernel_rtt_us`` is the Linux ``tcpi_rtt`` reading taken immediately
    after a successful connect — see ``_tcp_kernel_rtt`` module docstring
    for why we prefer this over wall-clock timing. ``None`` on any
    non-OK outcome or when TCP_INFO is unavailable; the caller falls
    back to wall-clock RTT in that case.
    """
    try:
        t0 = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=cfg.syn_timeout_sec,
        )
        # Read kernel RTT BEFORE close() — once the socket enters
        # FIN_WAIT/TIME_WAIT the kernel may reset tcpi_rtt to 0.
        kernel_rtt_us = read_kernel_rtt_us(writer)
        writer.close()
        # We've already proven reachability with the SYN-ACK; clean shutdown
        # is unnecessary and may race with peer-side close.
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return (Verdict.OK, None), kernel_rtt_us

    except TimeoutError:
        return (Verdict.BLOCKED, BlockingMethod.IP_DROPPED), _NO_KERNEL_RTT

    except ConnectionRefusedError:
        # Real RST from the host — port closed but host is alive
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms < cfg.fast_rst_threshold_ms:
            return (Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION), _NO_KERNEL_RTT
        return (Verdict.BLOCKED, BlockingMethod.TCP_REFUSED), _NO_KERNEL_RTT

    except OSError as e:
        # Could be ECONNRESET (RST) or other socket error
        elapsed_ms = (time.monotonic() - t0) * 1000
        err_str = str(e).lower()
        if "reset" in err_str or "refused" in err_str:
            if elapsed_ms < cfg.fast_rst_threshold_ms:
                return (Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION), _NO_KERNEL_RTT
            return (Verdict.BLOCKED, BlockingMethod.TCP_REFUSED), _NO_KERNEL_RTT
        logger.debug("tcp probe %s:%d OSError: %s", ip, port, e)
        return (Verdict.ERROR, None), _NO_KERNEL_RTT

    except Exception as e:
        # Defensive catch: any unexpected exception (TypeError, etc.)
        # surfaces in the log so a future bug doesn't silently degrade
        # to a generic ERROR row without traceback. exc_info=True
        # produces the full stack at DEBUG level.
        logger.debug("tcp probe %s:%d unexpected: %s", ip, port, e, exc_info=True)
        return (Verdict.ERROR, None), _NO_KERNEL_RTT


# Verdict severity for tie-breaking in :func:`_majority`. Lower value =
# more conservative; when two outcomes tie on count, we pick the one
# with the SMALLEST severity number (BLOCKED beats OK on a 2-vs-2 tie,
# THROTTLED beats OK, etc.). The motivation: a tie of [OK, BLOCKED]
# should not silently become OK just because OK happens to iterate
# first in the counter dict.
_VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.BLOCKED: 0,
    Verdict.THROTTLED: 1,
    Verdict.ANOMALY: 2,
    Verdict.HANDSHAKE_ONLY: 3,
    Verdict.ERROR: 4,
    Verdict.SERVER_REFUSED: 5,
    Verdict.INCONCLUSIVE: 6,
    Verdict.OK: 7,
}


def _majority(outcomes: list[_AttemptOutcome]) -> _AttemptOutcome:
    """Return most common (verdict, method) tuple; ties favour the more
    conservative verdict (see :data:`_VERDICT_SEVERITY`).

    Deterministic: ``max(counts, key=counts.get)`` used to return
    whichever key iterated first on a tie, which depended on dict
    insertion order and made the verdict path subtly non-reproducible
    across Python versions. The explicit severity tiebreaker makes the
    output order-independent — a 1-vs-1 [OK, BLOCKED] tie now always
    returns BLOCKED, matching how the operator interprets "even split"
    (one bad attempt is enough to keep us on the cautious side).
    """
    if not outcomes:
        return Verdict.INCONCLUSIVE, None
    counts: dict[_AttemptOutcome, int] = {}
    for o in outcomes:
        counts[o] = counts.get(o, 0) + 1
    return max(
        counts.items(),
        # Primary key: count descending. Secondary: conservative-first
        # (smaller severity number wins on tie).
        key=lambda item: (item[1], -_VERDICT_SEVERITY.get(item[0][0], 99)),
    )[0]


def _slug(ip: str) -> str:
    return ip.replace(".", "_").replace(":", "_")
