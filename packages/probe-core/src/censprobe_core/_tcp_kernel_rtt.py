"""Read kernel-side smoothed RTT via the Linux TCP_INFO socket option.

The default wall-clock timing in :func:`modules.tcp._test_tcp` —
``time.monotonic()`` deltas around ``await asyncio.open_connection`` —
includes asyncio event-loop scheduling overhead. On a quiet event loop
this is microseconds, but during solo's Phase A (DNS + TCP + TLS + HTTP
+ Telegram + Cloudflare all running concurrently, ~150 parallel
HTTPS+DoH coroutines) the SYN-ACK kernel-callback fires while many
other coroutines are still queued — our resume can be delayed by
80–500 ms. That delta then masquerades as "network RTT" and feeds
the latency-based scoring axis, unfairly docking the relay/entry
scores on fast hosts (verified 2026-05-14: Vultr Frankfurt → Cloudflare
real RTT ~1 ms, recorded RTT 84–127 ms; under simulated load the same
target showed 100–500 ms wall-clock while kernel RTT stayed at <1 ms).

The kernel maintains its own smoothed RTT estimate (``tcpi_rtt``,
microseconds, derived from SYN / SYN-ACK / ACK packet timestamps via
the congestion-control RTT estimator). It's available via
``getsockopt(IPPROTO_TCP, TCP_INFO, ...)`` and is **invariant to
user-space scheduling delays** — exactly the signal we want for
"how fast is the network path".

Linux only. On *BSD ``struct tcp_info`` exists but the field layout
differs; we don't attempt to read it there — returning ``None`` lets
the caller fall back to wall-clock timing, matching pre-fix behaviour.
"""

from __future__ import annotations

import asyncio
import socket
import struct

# Byte offset of ``tcpi_rtt`` in ``struct tcp_info`` on Linux.
#
# Layout (see /usr/include/linux/tcp.h; stable since kernel 2.4 — newer
# fields are APPENDED, so the offset is forward-compatible):
#
#   8 bytes  — eight u8 / bitfield fields (state, ca_state, retransmits,
#              probes, backoff, options, snd_wscale|rcv_wscale,
#              delivery_rate_app_limited|fastopen_client_fail)
#  16 bytes  — 4×u32: rto, ato, snd_mss, rcv_mss
#  20 bytes  — 5×u32: unacked, sacked, lost, retrans, fackets
#  16 bytes  — 4×u32: last_data_sent, last_ack_sent, last_data_recv,
#              last_ack_recv
#   8 bytes  — 2×u32: pmtu, rcv_ssthresh
# ─ offset 68
#   4 bytes  — u32 tcpi_rtt (microseconds)  ← here
#
# Verified runtime against `python3 -c "import socket; s=...;
# print(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104))"` on
# Linux 6.8 (Debian trixie), kernel match expected layout.
_TCP_INFO_RTT_OFFSET = 68

# How many bytes to request from getsockopt. The kernel returns
# ``min(requested, sizeof(tcp_info))``. 104 covers every Linux
# version that exposes tcpi_rtt at the documented offset; older
# kernels return fewer bytes and we handle that with the
# length check below.
_TCP_INFO_SIZE = 104


def read_kernel_rtt_us(writer: asyncio.StreamWriter) -> int | None:
    """Return tcpi_rtt (microseconds) for a connected asyncio writer.

    Used as the authoritative "network RTT" signal in :mod:`modules.tcp`:
    the kernel's RTT estimate doesn't pay any event-loop tax, so it
    correctly reports sub-millisecond paths even when our coroutine
    is queued behind 100+ concurrent TLS/DoH probes.

    ``None`` means: socket no longer accessible, ``TCP_INFO`` not
    supported (non-Linux host), or the kernel returned a struct
    too short to contain the field. Callers fall back to wall-clock
    timing — which is wrong but at least matches pre-2026-05-14
    behaviour and never zeros out the rtt signal entirely.

    Safe to call AFTER a successful ``asyncio.open_connection`` but
    BEFORE ``writer.close()`` — once the socket enters TIME_WAIT the
    kernel may return tcpi_rtt=0 (no longer maintained). Inline this
    call right after the connect, not in a finally block.
    """
    # ``get_extra_info`` is part of the asyncio StreamWriter ABI, but
    # tests pass duck-typed fakes that may not implement it. AttributeError
    # here is "test environment", not a real failure mode in production
    # — fall back to None silently.
    try:
        sock = writer.get_extra_info("socket")
    except AttributeError:
        return None
    if sock is None:
        return None
    try:
        buf = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, _TCP_INFO_SIZE)
    except (OSError, AttributeError):
        # AttributeError covers Python builds where TCP_INFO isn't in
        # the socket module (very old Python on stripped systems).
        # OSError covers ENOPROTOOPT on non-Linux kernels.
        return None
    if len(buf) < _TCP_INFO_RTT_OFFSET + 4:
        return None
    rtt_us: int = struct.unpack_from("I", buf, _TCP_INFO_RTT_OFFSET)[0]
    # tcpi_rtt == 0 happens before the kernel has computed any samples
    # (very rare on a connection that successfully returned from
    # connect, but possible on a SYN-ACK followed by immediate close).
    # Treat as "no signal" so the caller falls back.
    return rtt_us if rtt_us > 0 else None
