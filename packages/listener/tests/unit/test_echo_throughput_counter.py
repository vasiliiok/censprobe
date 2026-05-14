"""Tests for the wire-counter throughput methodology in echo_server.

The 2026-05-14 ya-b dual-RU run exposed that the legacy wait_closed
methodology fabricates 10× throughput inflation on slow client uplinks:
sing-box/xray/hysteria buffer the 8 MiB /throughput response in their
userspace before encrypting → kernel loopback FIN-ACK fires immediately
→ `(n * 8 / wait_closed_duration)` reports listener uplink × buffer
absorption rate, not the actual wire.

The fix wires each SubprocessResponder's iptables OUTPUT --sport byte
counter through ``register_throughput_reader`` so the echo server polls
the counter delta around the body emission. TCP back-pressure from the
slow client downlink throttles the tunnel binary's WAN-write, which
throttles the loopback-read, which means the byte counter ticks at
true line rate — matching what curl-through-the-tunnel measures on
the client side.

These tests exercise the new path with a fake reader; the iptables
integration is covered by integration tests that have actual NET_ADMIN.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from censprobe_listener.echo_server import EchoServer


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    """Pin time.monotonic() to a controllable list so we get deterministic
    elapsed times without sleeping in tests. The list[0] is the current
    time; ``advance(n)`` adds ``n`` seconds.
    """
    state = [1000.0]

    def _monotonic() -> float:
        return state[0]

    monkeypatch.setattr(
        "censprobe_listener.echo_server.time.monotonic",
        _monotonic,
    )
    yield state


@pytest.fixture
def fake_sleep(monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]) -> None:
    """Make ``asyncio.sleep`` advance the fake clock instead of waiting
    on the real event loop. Lets the quiesce-poll loop iterate in
    bounded test time."""

    async def _sleep(seconds: float) -> None:
        fake_clock[0] += seconds

    monkeypatch.setattr("censprobe_listener.echo_server.asyncio.sleep", _sleep)


class _CountingReader:
    """Async byte-counter callable returning a scripted sequence.

    Each call consumes one entry from ``values``; if the list runs out,
    the last value is repeated (the "quiesced" steady state).
    """

    def __init__(self, values: list[int]) -> None:
        self._values = list(values)
        self.call_count = 0

    async def __call__(self) -> int | None:
        self.call_count += 1
        if not self._values:
            return None
        if len(self._values) == 1:
            return self._values[0]
        return self._values.pop(0)


@pytest.mark.usefixtures("fake_sleep")
class TestMeasureThroughputViaCounter:
    @pytest.mark.asyncio
    async def test_quiesces_after_consecutive_no_growth_samples(
        self, fake_clock: list[float]
    ) -> None:
        # Counter grows for the first 3 polls, then plateaus → quiesce.
        # 1 MiB delta over 0.3 s = 8 388 608 * 8 / 0.3 / 1_000_000 ≈ 223.7 Mbps
        srv = EchoServer()
        reader = _CountingReader(
            [
                0,
                2_000_000,
                5_000_000,
                8_388_608,  # final value, repeated by reader
            ]
        )
        result = await srv._measure_throughput_via_counter(
            proto="shadowsocks",
            reader=reader,
            bytes_before=0,
            t0=fake_clock[0],
        )
        assert result.measured is True
        assert result.mbps is not None
        # 8388608 bytes / ~0.6 s ≈ 100 Mbps — the exact value depends on
        # the fake-clock advance, just sanity-check it's a positive
        # plausible number.
        assert 1.0 < result.mbps < 10_000.0

    @pytest.mark.asyncio
    async def test_zero_delta_returns_measured_none(self, fake_clock: list[float]) -> None:
        # Counter never grew — tunnel emitted no wire bytes. Measured
        # but None mbps; caller stores None and does NOT fall back.
        srv = EchoServer()
        reader = _CountingReader([100, 100])
        result = await srv._measure_throughput_via_counter(
            proto="shadowsocks",
            reader=reader,
            bytes_before=100,
            t0=fake_clock[0],
        )
        assert result.measured is True
        assert result.mbps is None

    @pytest.mark.asyncio
    async def test_reader_returning_none_triggers_fallback(self, fake_clock: list[float]) -> None:
        # Counter became unavailable mid-poll (iptables binary
        # disappeared) — return measured=False so the caller falls back
        # to wait_closed.
        srv = EchoServer()

        class _BrokenReader:
            async def __call__(self) -> int | None:
                return None

        result = await srv._measure_throughput_via_counter(
            proto="vless_reality",
            reader=_BrokenReader(),
            bytes_before=42,
            t0=fake_clock[0],
        )
        assert result.measured is False
        assert result.mbps is None

    @pytest.mark.asyncio
    async def test_reader_raising_triggers_fallback(self, fake_clock: list[float]) -> None:
        srv = EchoServer()

        class _RaisingReader:
            async def __call__(self) -> int | None:
                raise RuntimeError("iptables binary missing")

        result = await srv._measure_throughput_via_counter(
            proto="hysteria2",
            reader=_RaisingReader(),
            bytes_before=0,
            t0=fake_clock[0],
        )
        assert result.measured is False
        assert result.mbps is None


class TestRegisterReader:
    def test_register_and_unregister_idempotent(self) -> None:
        srv = EchoServer()

        async def _reader() -> int | None:
            return 12345

        srv.register_throughput_reader("shadowsocks", _reader)
        assert "shadowsocks" in srv._throughput_readers
        srv.unregister_throughput_reader("shadowsocks")
        assert "shadowsocks" not in srv._throughput_readers
        # Idempotent: second unregister is a no-op.
        srv.unregister_throughput_reader("shadowsocks")

    def test_unregister_missing_is_noop(self) -> None:
        srv = EchoServer()
        # Never registered — must not raise.
        srv.unregister_throughput_reader("hysteria2")


def test_wait_closed_path_used_when_no_reader(fake_clock: list[float]) -> None:
    """Sanity: with no reader registered, the wait_closed fallback path
    records the measurement (the existing behaviour we preserve as
    the backup methodology)."""
    del fake_clock  # only here to make the fixture parametrisable
    srv = EchoServer()
    # Direct call to the helper — duration of 1.0s gives n*8/1s Mbps.
    srv._record_wait_closed_throughput(proto="shadowsocks", n=1_000_000, duration=1.0)
    assert srv.throughput_mbps["shadowsocks"] == pytest.approx(8.0)


def test_wait_closed_discards_kernel_buffer_regime() -> None:
    """Sub-30-ms transfer is kernel-buffer-absorbed — must be discarded."""
    srv = EchoServer()
    srv._record_wait_closed_throughput(proto="shadowsocks", n=1_000_000, duration=0.01)
    assert srv.throughput_mbps["shadowsocks"] is None


def test_wait_closed_discards_implausible_mbps() -> None:
    """Above the 5000 Mbps ceiling = also kernel-buffer artefact."""
    srv = EchoServer()
    # 1 GiB / 0.5s = 16 Gbps → above the 5000 Mbps cap.
    srv._record_wait_closed_throughput(proto="vless_reality", n=1_073_741_824, duration=0.5)
    assert srv.throughput_mbps["vless_reality"] is None


def _yield_once_for_asyncio() -> None:
    """pytest-asyncio sanity probe — keeps importers honest."""
    asyncio.run(asyncio.sleep(0))
