"""
Tests for ``modules.tcp`` — single-attempt outcome attribution and the
``_majority`` aggregator.

Two distinct concerns:
  1. ``_single_tcp_attempt`` — translates socket errors into
     (verdict, method) tuples, with a timing-based RST attribution:
     ConnectionRefusedError that arrives faster than
     ``fast_rst_threshold_ms`` is treated as
     (BLOCKED, TCP_RST_INJECTION) (TSPU forging an RST), slower is
     (BLOCKED, TCP_REFUSED) (host genuinely closed port).
  2. ``_majority`` — most-common-vote tie-breaker over the
     (verdict, method) tuples.
"""

from __future__ import annotations

from typing import Any

import pytest
from censprobe_core.config import TcpModuleConfig
from censprobe_core.models import BlockingMethod, Verdict
from censprobe_core.modules import tcp as tcp_mod
from censprobe_core.modules.tcp import _majority, _single_tcp_attempt


def _cfg(*, fast_rst_threshold_ms: int = 30) -> TcpModuleConfig:
    return TcpModuleConfig(
        enabled=True,
        repeats=1,
        syn_timeout_sec=5.0,
        fast_rst_threshold_ms=fast_rst_threshold_ms,
        max_parallel=4,
    )


class _FakeWriter:
    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


def _patch_monotonic_sequence(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
    """Make ``time.monotonic()`` yield the given values in order."""
    idx = [0]

    def _fake() -> float:
        v = values[idx[0]] if idx[0] < len(values) else values[-1]
        idx[0] += 1
        return v

    monkeypatch.setattr(tcp_mod.time, "monotonic", _fake)


async def _passthrough_wait_for(coro: Any, **_kw: Any) -> Any:
    """Bypass real timeout machinery — just await the inner coro."""
    return await coro


# ─────────────────────────────────────────────────────────────────────────────
# _majority
# ─────────────────────────────────────────────────────────────────────────────


class TestMajority:
    def test_empty_returns_inconclusive(self) -> None:
        # No samples at all is a different signal from "tied" — we want
        # (INCONCLUSIVE, None), not (ERROR, None).
        assert _majority([]) == (Verdict.INCONCLUSIVE, None)

    def test_single_returns_that(self) -> None:
        assert _majority([(Verdict.OK, None)]) == (Verdict.OK, None)

    def test_strict_majority(self) -> None:
        outcomes = [
            (Verdict.OK, None),
            (Verdict.OK, None),
            (Verdict.BLOCKED, BlockingMethod.IP_DROPPED),
        ]
        assert _majority(outcomes) == (Verdict.OK, None)

    def test_tie_picks_first_in_dict_order(self) -> None:
        # Python dict insertion order: first key with the max count wins.
        # Pin this so a refactor doesn't silently change tie-break behaviour.
        outcomes = [
            (Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION),
            (Verdict.OK, None),
        ]
        assert _majority(outcomes) == (Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION)

    def test_all_errors(self) -> None:
        assert _majority([(Verdict.ERROR, None), (Verdict.ERROR, None)]) == (Verdict.ERROR, None)


# ─────────────────────────────────────────────────────────────────────────────
# _single_tcp_attempt — timing-based RST attribution
# ─────────────────────────────────────────────────────────────────────────────


async def test_ok_on_clean_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_open(*_a: Any, **_kw: Any) -> Any:
        return object(), _FakeWriter()

    monkeypatch.setattr(tcp_mod.asyncio, "open_connection", _fake_open)
    monkeypatch.setattr(tcp_mod.asyncio, "wait_for", _passthrough_wait_for)
    outcome, kernel_rtt_us = await _single_tcp_attempt("1.2.3.4", 443, _cfg())
    assert outcome == (Verdict.OK, None)
    # Kernel RTT comes from a fake writer with no real socket → None.
    assert kernel_rtt_us is None


async def test_timeout_returns_ip_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_open(*_a: Any, **_kw: Any) -> Any:
        raise TimeoutError

    monkeypatch.setattr(tcp_mod.asyncio, "open_connection", _fake_open)
    monkeypatch.setattr(tcp_mod.asyncio, "wait_for", _passthrough_wait_for)
    outcome, kernel_rtt_us = await _single_tcp_attempt("1.2.3.4", 443, _cfg())
    assert outcome == (Verdict.BLOCKED, BlockingMethod.IP_DROPPED)
    # No successful connect → no socket → no kernel RTT.
    assert kernel_rtt_us is None


async def test_fast_refused_is_rst_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ConnectionRefused at 5 ms (well under 30 ms threshold) →
    # (BLOCKED, TCP_RST_INJECTION). Vantage gating is applied later in
    # the aggregator, not here.
    _patch_monotonic_sequence(monkeypatch, [0.000, 0.005])

    async def _fake_open(*_a: Any, **_kw: Any) -> Any:
        raise ConnectionRefusedError("forged RST")

    monkeypatch.setattr(tcp_mod.asyncio, "open_connection", _fake_open)
    monkeypatch.setattr(tcp_mod.asyncio, "wait_for", _passthrough_wait_for)
    outcome, kernel_rtt_us = await _single_tcp_attempt("1.2.3.4", 443, _cfg())
    assert outcome == (Verdict.BLOCKED, BlockingMethod.TCP_RST_INJECTION)
    assert kernel_rtt_us is None


async def test_slow_refused_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ConnectionRefused at 100 ms (above 30 ms threshold) →
    # (BLOCKED, TCP_REFUSED) — genuine host-side close.
    _patch_monotonic_sequence(monkeypatch, [0.000, 0.100])

    async def _fake_open(*_a: Any, **_kw: Any) -> Any:
        raise ConnectionRefusedError("real RST from host")

    monkeypatch.setattr(tcp_mod.asyncio, "open_connection", _fake_open)
    monkeypatch.setattr(tcp_mod.asyncio, "wait_for", _passthrough_wait_for)
    outcome, kernel_rtt_us = await _single_tcp_attempt("1.2.3.4", 443, _cfg())
    assert outcome == (Verdict.BLOCKED, BlockingMethod.TCP_REFUSED)
    assert kernel_rtt_us is None


async def test_oserror_with_reset_keyword_uses_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # OSError("connection reset by peer") with elapsed > threshold →
    # (BLOCKED, TCP_REFUSED) (not TCP_RST_INJECTION).
    _patch_monotonic_sequence(monkeypatch, [0.000, 0.080])

    async def _fake_open(*_a: Any, **_kw: Any) -> Any:
        raise OSError("Connection reset by peer")

    monkeypatch.setattr(tcp_mod.asyncio, "open_connection", _fake_open)
    monkeypatch.setattr(tcp_mod.asyncio, "wait_for", _passthrough_wait_for)
    outcome, kernel_rtt_us = await _single_tcp_attempt("1.2.3.4", 443, _cfg())
    assert outcome == (Verdict.BLOCKED, BlockingMethod.TCP_REFUSED)
    assert kernel_rtt_us is None


async def test_oserror_unrelated_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_monotonic_sequence(monkeypatch, [0.0, 0.1])

    async def _fake_open(*_a: Any, **_kw: Any) -> Any:
        raise OSError("Network is unreachable")

    monkeypatch.setattr(tcp_mod.asyncio, "open_connection", _fake_open)
    monkeypatch.setattr(tcp_mod.asyncio, "wait_for", _passthrough_wait_for)
    outcome, kernel_rtt_us = await _single_tcp_attempt("1.2.3.4", 443, _cfg())
    assert outcome == (Verdict.ERROR, None)
    assert kernel_rtt_us is None
