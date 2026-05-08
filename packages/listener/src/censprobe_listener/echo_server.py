"""
echo_server.py — Local TCP echo endpoint for data-phase measurement.

SS / VLESS / Hysteria-2 listeners route *only* to one of these ports.
When a client tunnel carries data to e.g. 127.0.0.1:9991, that connection
reaches our echo server, which increments the per-port counter and echoes
bytes back. This lets us distinguish HANDSHAKE_ONLY from full OK:

  * handshake_count > 0  and  echo_count == 0  → HANDSHAKE_ONLY
  * handshake_count > 0  and  echo_count  > 0  → OK

In addition to the small ``GET /ping`` round-trip, the server now also
serves ``GET /throughput?bytes=N`` — streams ``N`` zero bytes back to the
client and measures wall-clock time from first write to connection close,
which is the listener-side view of the tunnel's sustained downlink. The
resulting Mbps figure is *not* used by scoring (it would be wrong to
penalise a slow VPS for narrow uplink); it is exposed only as an
operator-facing signal in the listener report and dashboard.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

# Canonical home of the echo-port contract is probe-core (it is shared
# with the client-side probe via :mod:`censprobe_core.protocol_probes`,
# so a single source of truth eliminates silent drift). Re-exported here
# for back-compat with the responder modules that imported it from this
# file historically.
from censprobe_core.echo_ports import ECHO_PORTS

__all__ = ["ECHO_PORTS", "EchoServer"]

logger = logging.getLogger(__name__)


# Cap the throughput payload so a malicious client (or a misconfigured
# probe) cannot ask for arbitrary GiB and starve the listener box of
# memory. 16 MiB is comfortably above what the client probe asks for
# (1 MiB by default).
_MAX_THROUGHPUT_BYTES = 16 * 1024 * 1024

# Hard-cap how long a single /throughput response may take. The default
# matches the client-side curl --max-time so a stuck transfer doesn't
# hold the only echo socket past the listener's session window.
_THROUGHPUT_RESPONSE_TIMEOUT_SEC = 35.0

# Below this elapsed time, the listener-side measurement is dominated by
# kernel/loopback buffer absorption (see the long comment in
# _serve_throughput) and the resulting Mbps figure is meaningless. 100 ms
# is comfortably above the loopback round-trip but well below the
# duration of any realistic 1 MiB tunneled transfer (8 ms at 1 Gbps would
# already saturate sub-Gbps consumer links — we don't see those here).
_MIN_THROUGHPUT_DURATION_SEC = 0.1

# Even with duration above the floor, anything wildly above what a real
# remote tunnel can deliver is the same artefact under a different mask
# (write was very small, kernel still absorbed in <one tick). 2 Gbps is
# above any consumer / VPS uplink we expect to test against; treat
# anything beyond as "kernel buffer absorption did not block hard enough"
# and discard.
_MAX_PLAUSIBLE_MBPS = 2000.0


class EchoServer:
    """Single-process asyncio TCP echo server with per-port counters."""

    def __init__(self, ports: dict[str, int] | None = None) -> None:
        self.ports = dict(ports) if ports is not None else dict(ECHO_PORTS)
        self._servers: list[asyncio.base_events.Server] = []
        self.connection_counts: dict[str, int] = dict.fromkeys(self.ports, 0)
        self.bytes_counts: dict[str, int] = dict.fromkeys(self.ports, 0)
        # Latest /throughput measurement per protocol — None until a probe
        # actually requests one. Overwritten on each call rather than
        # averaged, because the operator wants the most recent observation
        # not a smoothed history.
        self.throughput_mbps: dict[str, float | None] = dict.fromkeys(self.ports)

    async def start(self) -> None:
        # Bring up each port; on partial failure (e.g. one of the loopback
        # ports already busy from a leaked previous run) tear down everything
        # we did manage to start so we don't leak listening sockets that
        # block the next start_server() retry. The listener's main.py
        # treats any exception here as "no echo server" and continues —
        # without this rollback, those orphan servers would survive.
        try:
            for proto, port in self.ports.items():
                # `reuse_address=True` lets us rebind to the same port even
                # if the previous listener died with sockets still in
                # TIME_WAIT — without it, a fast restart hits "address
                # already in use". asyncio enables it by default on POSIX
                # but we set it explicitly so the behaviour doesn't depend
                # on platform defaults.
                # Capture `proto` by default-arg binding so each spawned
                # server keeps its own protocol label (closing over the
                # loop variable would give every server the last value).
                async def _client_cb(
                    r: asyncio.StreamReader,
                    w: asyncio.StreamWriter,
                    p: str = proto,
                ) -> None:
                    await self._handle(r, w, p)

                srv = await asyncio.start_server(
                    _client_cb,
                    host="127.0.0.1",
                    port=port,
                    reuse_address=True,
                )
                self._servers.append(srv)
                logger.info("echo server: %s on 127.0.0.1:%d", proto, port)
        except Exception:
            await self.stop()
            raise

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        proto: str,
    ) -> None:
        self.connection_counts[proto] = self.connection_counts.get(proto, 0) + 1
        try:
            # Read enough to see the HTTP request line + headers (or the
            # raw payload if the client isn't speaking HTTP). 8 KiB
            # comfortably covers any sane ``GET /...`` line + headers.
            data = await asyncio.wait_for(reader.read(8192), timeout=3.0)
            total_bytes = len(data)
            self.bytes_counts[proto] = self.bytes_counts.get(proto, 0) + total_bytes

            if data.startswith(b"GET /throughput"):
                # Throughput probe — server-side measurement of wall-clock
                # time from first write to connection close. The bytes
                # counter has already been credited above for the request
                # line, which is enough to satisfy data_ok().
                await self._serve_throughput(proto, data, writer)
                return

            if data.startswith(b"GET ") or data.startswith(b"POST "):
                body = b"pong"
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            else:
                writer.write(data)
            await writer.drain()
        except TimeoutError:
            pass
        except Exception as e:
            logger.debug("echo handler (%s) error: %s", proto, e)
        finally:
            # Best-effort connection close — the peer may have already
            # vanished after delivering the request, in which case any
            # cleanup error is irrelevant.
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _serve_throughput(
        self,
        proto: str,
        request: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Stream N zero bytes back; measure transfer wall-clock duration.

        ``writer.wait_closed()`` is what actually meters the slow link:
        for any payload that fits in the kernel send buffer, ``drain()``
        returns immediately, but ``wait_closed`` blocks on the FIN-ACK
        round-trip after the kernel has finished pushing the bytes
        through the throttled tunnel. The measurement is approximate on
        very fast / very small transfers (kernel buffer absorption hides
        actual time-on-wire), but accurate within ~10% on anything that
        takes more than ~1 second — which is exactly the regime where
        we care about the number.
        """
        n = _parse_throughput_n(request)
        if n <= 0:
            writer.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            try:
                await writer.drain()
            finally:
                writer.close()
                # Bad-request 400 path — peer may close before we ack.
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            return

        if n > _MAX_THROUGHPUT_BYTES:
            n = _MAX_THROUGHPUT_BYTES

        body = b"\x00" * n
        headers = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(n).encode() + b"\r\n"
            b"Cache-Control: no-store\r\n"
            b"Connection: close\r\n\r\n"
        )

        t0 = time.monotonic()
        duration: float | None = None
        try:
            writer.write(headers)
            writer.write(body)
            await asyncio.wait_for(
                writer.drain(),
                timeout=_THROUGHPUT_RESPONSE_TIMEOUT_SEC,
            )
            writer.close()
            # Client hung — measurement still meaningful (we know it
            # didn't finish), record duration as the deadline and let
            # the caller see a low Mbps. Suppress both timeout (expected
            # on a slow link) and any other socket-side exception.
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    writer.wait_closed(),
                    timeout=_THROUGHPUT_RESPONSE_TIMEOUT_SEC,
                )
            duration = time.monotonic() - t0
        except TimeoutError:
            duration = time.monotonic() - t0
        except Exception as e:
            logger.debug("throughput serve to %s aborted: %s", proto, e)
            return

        if duration and duration > 0:
            mbps = (n * 8) / duration / 1_000_000
            # Listener-side throughput is fundamentally limited: the echo
            # server sits on 127.0.0.1, behind the tunnel binary
            # (sing-box/xray/hysteria) running on the same host. drain() and
            # wait_closed() return when the loopback FIN-ACK is done — i.e.
            # when the tunnel binary has buffered the bytes locally, NOT
            # when they have egressed the tunnel and reached the operator.
            # For payloads that fit in the kernel/loopback buffer (usually
            # several MiB), the measurement collapses to "kernel buffer
            # absorption time" and yields multi-Gbps numbers that have no
            # physical meaning.  Discard the result when it lands in that
            # regime so the dashboard / report carry an honest "not
            # measured" instead of fabricated throughput.
            if duration < _MIN_THROUGHPUT_DURATION_SEC or mbps > _MAX_PLAUSIBLE_MBPS:
                logger.info(
                    "throughput[%s]: discarded — %d bytes in %.3fs "
                    "(would be %.0f Mbps; loopback buffer absorbed the write)",
                    proto,
                    n,
                    duration,
                    mbps,
                )
                self.throughput_mbps[proto] = None
                return
            self.throughput_mbps[proto] = mbps
            logger.info(
                "throughput[%s]: %.2f Mbps (%d bytes in %.2fs)",
                proto,
                mbps,
                n,
                duration,
            )

    async def stop(self) -> None:
        for srv in self._servers:
            srv.close()
        for srv in self._servers:
            # Servers may already be in the process of shutting down by
            # the time we reach this loop (SIGTERM races) — suppress.
            with contextlib.suppress(Exception):
                await srv.wait_closed()
        self._servers.clear()

    def snapshot(self) -> dict[str, dict[str, float | int | None]]:
        """Return per-protocol {connections, bytes, throughput_mbps}."""
        return {
            proto: {
                "connections": self.connection_counts.get(proto, 0),
                "bytes": self.bytes_counts.get(proto, 0),
                "throughput_mbps": self.throughput_mbps.get(proto),
            }
            for proto in self.ports
        }

    # Smallest expected payload size for a successful round-trip.
    # The current censprobe-client always issues an HTTP request through
    # the tunnel ("GET /ping HTTP/1.1\r\nHost: ...\r\n..."), which is
    # ≥70 bytes — so we floor at 64 to require an actual round-trip
    # rather than the leaked plaintext from a Reality handshake. The
    # previous floor of 4 ("ping" literal) accepted as little as the
    # decrypted handshake echo from a mid-session RST and produced
    # false-OK verdicts. The legacy 4-byte path is gone.
    def data_ok(self, proto: str, min_bytes: int = 64) -> bool:
        return self.bytes_counts.get(proto, 0) >= min_bytes


def _parse_throughput_n(request: bytes) -> int:
    """Extract ``bytes`` query param from a ``GET /throughput?...`` line.

    Returns 0 when the value is missing, malformed, or non-numeric.
    The caller treats 0 as "reject the request" so a typo in the client
    doesn't quietly stream nothing and read as a successful zero-byte
    transfer.
    """
    try:
        first_line = request.split(b"\r\n", 1)[0]
        # "GET /throughput?bytes=1048576 HTTP/1.1"
        parts = first_line.split(b" ")
        if len(parts) < 2:
            return 0
        path_qs = parts[1]
        if b"?" not in path_qs:
            return 0
        _, qs = path_qs.split(b"?", 1)
        for pair in qs.split(b"&"):
            if pair.startswith(b"bytes="):
                value = pair[len(b"bytes=") :]
                return max(0, int(value))
    except (ValueError, IndexError):
        return 0
    return 0
