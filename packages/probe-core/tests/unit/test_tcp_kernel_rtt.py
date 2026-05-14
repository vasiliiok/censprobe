"""Tests for :func:`censprobe_core._tcp_kernel_rtt.read_kernel_rtt_us`.

The function reads the Linux kernel's smoothed RTT estimate from a
connected socket via the TCP_INFO socket option. The integration
path is verified by ``test_tcp_kernel_rtt_integration_smoke`` in
the live integration suite (gated on real ``socket.TCP_INFO``); the
unit tests here pin behavior on the fallback / error paths that
the live test can't exercise.
"""

from __future__ import annotations

import struct
from typing import Any

from censprobe_core._tcp_kernel_rtt import _TCP_INFO_RTT_OFFSET, read_kernel_rtt_us


class _FakeSocket:
    """Stand-in for the real socket object behind asyncio's writer.

    ``getsockopt(IPPROTO_TCP, TCP_INFO, n)`` is the only call we make;
    everything else can be left undefined. The buffer length is
    parametrised so we can test both the "short read" path (older
    kernel returning fewer fields) and the success path.
    """

    def __init__(self, buf: bytes | None = None, raises: BaseException | None = None) -> None:
        self._buf = buf
        self._raises = raises

    def getsockopt(self, _level: int, _opt: int, _size: int) -> bytes:
        if self._raises is not None:
            raise self._raises
        assert self._buf is not None
        return self._buf


class _FakeWriter:
    def __init__(self, sock: object | None) -> None:
        self._sock = sock

    def get_extra_info(self, name: str) -> object | None:
        if name == "socket":
            return self._sock
        return None


def _tcp_info_buf(rtt_us: int) -> bytes:
    """Synthesize a minimally-valid struct tcp_info with rtt_us at the
    documented offset. Pre-rtt fields stay zero (we don't read them).
    """
    buf = bytearray(_TCP_INFO_RTT_OFFSET + 4)
    struct.pack_into("I", buf, _TCP_INFO_RTT_OFFSET, rtt_us)
    return bytes(buf)


class TestReadKernelRttUs:
    def test_returns_rtt_when_kernel_provides_one(self) -> None:
        # Kernel says smoothed RTT is 1500 microseconds (1.5 ms).
        sock = _FakeSocket(_tcp_info_buf(1500))
        result = read_kernel_rtt_us(_FakeWriter(sock))
        assert result == 1500

    def test_returns_none_when_writer_has_no_socket(self) -> None:
        # asyncio StreamWriter without a real underlying socket
        # (mocked / closed). Must NOT raise — caller falls back.
        result = read_kernel_rtt_us(_FakeWriter(None))
        assert result is None

    def test_returns_none_when_get_extra_info_missing(self) -> None:
        # Duck-typed test fake that doesn't implement get_extra_info
        # at all — production asyncio writers always do, but in unit
        # tests fakes may omit it.
        class _Bare:
            pass

        result = read_kernel_rtt_us(_Bare())  # type: ignore[arg-type]
        assert result is None

    def test_returns_none_on_oserror(self) -> None:
        # Non-Linux kernel: getsockopt raises ENOPROTOOPT (OSError).
        # Must NOT crash; caller falls back to wall-clock RTT.
        sock = _FakeSocket(raises=OSError("ENOPROTOOPT"))
        result = read_kernel_rtt_us(_FakeWriter(sock))
        assert result is None

    def test_returns_none_when_buffer_too_short(self) -> None:
        # Pre-2.4 Linux returns a shorter struct that doesn't contain
        # tcpi_rtt. Length check guards against unpack_from on
        # undersized data → silent None fallback.
        sock = _FakeSocket(bytes(_TCP_INFO_RTT_OFFSET))  # one byte short
        result = read_kernel_rtt_us(_FakeWriter(sock))
        assert result is None

    def test_returns_none_when_kernel_rtt_is_zero(self) -> None:
        # tcpi_rtt == 0 is "no samples yet" (rare, but happens on
        # SYN-ACK / immediate close paths). Treat as no signal so the
        # caller fast-paths to wall-clock instead of recording a
        # bogus 0-ms RTT.
        sock = _FakeSocket(_tcp_info_buf(0))
        result = read_kernel_rtt_us(_FakeWriter(sock))
        assert result is None

    def test_returns_rtt_for_high_latency_path(self) -> None:
        # A real RU→US-East path is around 200,000 µs (200 ms).
        # Sanity-check the parser handles realistic-magnitude values.
        sock = _FakeSocket(_tcp_info_buf(200_000))
        result = read_kernel_rtt_us(_FakeWriter(sock))
        assert result == 200_000

    def test_handles_writer_get_extra_info_raising(self) -> None:
        # Some mock libraries make get_extra_info raise rather than
        # return None for unknown keys. Production asyncio doesn't —
        # but the catch makes us robust to the wider testing world.
        class _Raising:
            def get_extra_info(self, _name: str) -> Any:
                raise AttributeError("not implemented")

        result = read_kernel_rtt_us(_Raising())  # type: ignore[arg-type]
        assert result is None
