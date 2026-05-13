"""
Tests for the ``_stamp_elapsed`` (protocol_probes) and
``stamp_test_elapsed`` (utils) decorators that thread a total
wall-clock probe-duration measurement through ``ProbeResult``/
``TestResult``.

Regression target: prior to 2026-05, the client display rendered
``rtt_ms`` as ``(Xms)`` next to every verdict — but for the
mtproto/shadowsocks/etc TCP-probe family ``rtt_ms`` was set from
``_open_mtproto_tcp``'s TCP-connect timing, NOT from the total probe
duration. Result: a 15-second BLOCKED timeout displayed as
``(10ms)`` on a fast LAN, mislabelling slow stalls as fast failures.

These tests verify:
  * the decorator always stamps ``elapsed_ms`` on the result, even
    when the wrapped probe returned early with a ``BLOCKED`` verdict
    and no ``rtt_ms`` was captured;
  * a probe's own explicit ``elapsed_ms`` value (if it sets one) is
    preserved — the decorator only fills the field when it was left
    ``None``;
  * ``rtt_ms`` is left untouched (the two fields carry independent
    signals).
"""

from __future__ import annotations

import asyncio

import pytest
from censprobe_core.models import TestResult, Verdict
from censprobe_core.protocol_probes import ProbeResult, _stamp_elapsed
from censprobe_core.utils import stamp_test_elapsed


class TestStampElapsedProbeResult:
    """``_stamp_elapsed`` on probe coroutines returning ``ProbeResult``."""

    @pytest.mark.asyncio
    async def test_stamps_elapsed_on_ok_return(self) -> None:
        @_stamp_elapsed
        async def _probe() -> ProbeResult:
            await asyncio.sleep(0.02)
            r = ProbeResult()
            r.verdict = Verdict.OK
            r.rtt_ms = 5.0  # protocol-level signal, e.g. TCP-connect rtt
            return r

        result = await _probe()
        assert result.verdict == Verdict.OK
        assert result.rtt_ms == 5.0
        assert result.elapsed_ms is not None
        assert result.elapsed_ms >= 20.0  # at least the sleep
        # rtt_ms is independent of elapsed_ms — the decorator must not
        # overwrite it with the elapsed value.
        assert result.elapsed_ms != result.rtt_ms

    @pytest.mark.asyncio
    async def test_stamps_elapsed_on_error_return(self) -> None:
        # Regression: prior bug — a BLOCKED return whose probe-side
        # error-result helper produced ``ProbeResult(error=..., verdict=
        # BLOCKED)`` left elapsed_ms unset, and the caller stamped
        # only the TCP-connect rtt. Now the decorator always fills it.
        @_stamp_elapsed
        async def _probe() -> ProbeResult:
            await asyncio.sleep(0.015)
            r = ProbeResult()
            r.verdict = Verdict.BLOCKED
            r.error = "orig_resPQ_len_timeout_post_init"
            # rtt_ms stays None — probe returned before stamping it.
            return r

        result = await _probe()
        assert result.verdict == Verdict.BLOCKED
        assert result.rtt_ms is None
        assert result.elapsed_ms is not None
        assert result.elapsed_ms >= 15.0

    @pytest.mark.asyncio
    async def test_preserves_caller_supplied_elapsed_ms(self) -> None:
        # If a probe wants to set its own ``elapsed_ms`` (e.g. to
        # subtract setup time), the decorator must not overwrite it.
        @_stamp_elapsed
        async def _probe() -> ProbeResult:
            await asyncio.sleep(0.02)
            r = ProbeResult()
            r.verdict = Verdict.OK
            r.elapsed_ms = 0.0  # caller deliberately zeroed it
            return r

        result = await _probe()
        assert result.elapsed_ms == 0.0

    @pytest.mark.asyncio
    async def test_exception_propagates_without_stamp(self) -> None:
        # If the wrapped coroutine raises, the decorator does not
        # construct a ProbeResult — the exception flows through, and
        # the caller (e.g. client/main.py) is responsible for building
        # an error ProbeResult with its own elapsed_ms.
        @_stamp_elapsed
        async def _probe() -> ProbeResult:
            await asyncio.sleep(0.01)
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await _probe()


class TestStampTestElapsedTestResult:
    """``stamp_test_elapsed`` on solo-module ``_test_*`` coroutines."""

    @pytest.mark.asyncio
    async def test_stamps_elapsed_on_testresult(self) -> None:
        @stamp_test_elapsed
        async def _test() -> TestResult:
            await asyncio.sleep(0.02)
            return TestResult(
                test="dns_x",
                category="dns",
                target="x",
                verdict=Verdict.OK,
                rtt_ms=2.0,
            )

        result = await _test()
        assert result.elapsed_ms is not None
        assert result.elapsed_ms >= 20.0
        assert result.rtt_ms == 2.0  # untouched

    @pytest.mark.asyncio
    async def test_handles_none_return(self) -> None:
        # Some solo helpers (e.g. ``_test_ech`` in tls.py) return None
        # when the test is not applicable. The decorator must accept
        # this without erroring.
        @stamp_test_elapsed
        async def _test() -> TestResult | None:
            return None

        result = await _test()
        assert result is None

    @pytest.mark.asyncio
    async def test_preserves_explicit_elapsed_ms(self) -> None:
        @stamp_test_elapsed
        async def _test() -> TestResult:
            return TestResult(
                test="x",
                category="c",
                target="x",
                verdict=Verdict.OK,
                elapsed_ms=42.0,
            )

        result = await _test()
        assert result.elapsed_ms == 42.0
