"""
modules/tcp.py — TCP reachability measurement module.

Tests TCP connectivity to (IP, port) pairs using asyncio.open_connection
(full 3-way handshake — no raw sockets / Scapy).

Verdicts:
  OK            — connect() succeeded
  IP_DROPPED    — SYN sent, timeout (null-route / blackhole)
  REFUSED       — legitimate RST from the host (port closed, service down)
  RST_INJECTED  — HEURISTIC ONLY: RST that arrives in less than
                  _SYN_FAST_RST_MS after connect(). This is a rough
                  timing heuristic, NOT a TTL-anomaly analysis: low-latency
                  networks (same datacenter, localhost) can legitimately
                  return a REFUSED RST faster than the threshold and be
                  mislabeled as RST_INJECTED. Treat this verdict as a hint,
                  not a conclusion.

True TTL-delta analysis requires raw sockets (Scapy or eBPF) and is
deliberately not implemented in the MVP — we surface the heuristic RTT
in evidence.rtts_ms so reviewers can sanity-check it.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 5.0    # seconds before declaring IP_DROPPED
_SYN_FAST_RST_MS = 500    # RST within this time = likely injected
_MAX_PARALLEL = 16        # concurrency cap for TCP probes


async def run_tcp_tests(
    targets: list[tuple[str, int]],  # (ip, port) pairs
    repeats: int = 3,
) -> list[TestResult]:
    """Run TCP reachability tests for a list of (ip, port) targets in parallel."""
    sem = asyncio.Semaphore(_MAX_PARALLEL)

    async def _bounded(ip: str, port: int) -> TestResult:
        async with sem:
            return await _test_tcp(ip, port, repeats)

    return await asyncio.gather(*[_bounded(ip, port) for ip, port in targets])


async def _test_tcp(ip: str, port: int, repeats: int) -> TestResult:
    """Test TCP connectivity to ip:port."""
    target = f"{ip}:{port}"
    verdicts = []
    rtts = []
    rst_ttls = []

    for _ in range(repeats):
        t0 = time.monotonic()
        verdict, rst_ttl = await _single_tcp_attempt(ip, port)
        rtt_ms = (time.monotonic() - t0) * 1000
        verdicts.append(verdict)
        rtts.append(rtt_ms)
        if rst_ttl is not None:
            rst_ttls.append(rst_ttl)
        await asyncio.sleep(0.5)  # small jitter between repeats

    # Aggregate: majority wins
    final_verdict = _majority(verdicts)
    method: Optional[BlockingMethod] = None

    if final_verdict == Verdict.RST_INJECTED:
        method = BlockingMethod.TCP_RST_INJECTION
    elif final_verdict == Verdict.IP_DROPPED:
        method = BlockingMethod.IP_DROPPED

    # RST_INJECTED is only a timing heuristic here — flag that explicitly
    # in evidence and lower confidence so baseline/scoring can discount it.
    is_heuristic_rst = final_verdict == Verdict.RST_INJECTED
    return TestResult(
        test=f"tcp_{_slug(ip)}_{port}",
        category="tcp",
        target=target,
        verdict=final_verdict,
        method=method,
        rtt_ms=min(rtts) if rtts else None,
        attempts=repeats,
        confidence=0.5 if is_heuristic_rst else 1.0,
        notes=(
            "RST_INJECTED is a timing heuristic (fast RST, no TTL check); "
            "treat as a hint, not a conclusion."
            if is_heuristic_rst
            else None
        ),
        evidence={
            "all_verdicts": verdicts,
            "rtts_ms": rtts,
            "rst_ttls": rst_ttls,
            "rst_detection": "rtt_heuristic_no_scapy",
        },
    )


async def _single_tcp_attempt(ip: str, port: int) -> tuple[Verdict, Optional[int]]:
    """
    Attempt a single TCP connect. Returns (verdict, rst_ttl_if_applicable).
    """
    try:
        t0 = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=_CONNECT_TIMEOUT,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return Verdict.OK, None

    except asyncio.TimeoutError:
        return Verdict.IP_DROPPED, None

    except ConnectionRefusedError:
        # Real RST from the host — port closed but host is alive
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms < _SYN_FAST_RST_MS:
            # Very fast RST — might be injected
            return Verdict.RST_INJECTED, None
        return Verdict.REFUSED, None

    except OSError as e:
        # Could be ECONNRESET (RST) or other socket error
        elapsed_ms = (time.monotonic() - t0) * 1000
        err_str = str(e).lower()
        if "reset" in err_str or "refused" in err_str:
            if elapsed_ms < _SYN_FAST_RST_MS:
                return Verdict.RST_INJECTED, None
            return Verdict.REFUSED, None
        return Verdict.ERROR, None  # type: ignore[return-value]

    except Exception:
        return Verdict.ERROR, None  # type: ignore[return-value]


def _majority(verdicts: list[Verdict]) -> Verdict:
    """Return most common verdict."""
    if not verdicts:
        return Verdict.INCONCLUSIVE
    counts: dict[Verdict, int] = {}
    for v in verdicts:
        counts[v] = counts.get(v, 0) + 1
    return max(counts, key=counts.get)  # type: ignore[arg-type]


def _slug(ip: str) -> str:
    return ip.replace(".", "_").replace(":", "_")
