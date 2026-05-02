"""
echo_server.py — Local TCP echo endpoint for data-phase measurement.

SS / VLESS / Hysteria-2 listeners route *only* to one of these ports.
When a client tunnel carries data to e.g. 127.0.0.1:9991, that connection
reaches our echo server, which increments the per-port counter and echoes
bytes back. This lets us distinguish HANDSHAKE_ONLY from full OK:

  * handshake_count > 0  and  echo_count == 0  → HANDSHAKE_ONLY
  * handshake_count > 0  and  echo_count  > 0  → OK
"""
from __future__ import annotations

import asyncio
import logging

# Canonical home of the echo-port contract is probe-core (it is shared
# with the client-side probe via :mod:`censprobe_core.protocol_probes`,
# so a single source of truth eliminates silent drift). Re-exported here
# for back-compat with the responder modules that imported it from this
# file historically.
from censprobe_core.echo_ports import ECHO_PORTS

__all__ = ["ECHO_PORTS", "EchoServer"]

logger = logging.getLogger(__name__)


class EchoServer:
    """Single-process asyncio TCP echo server with per-port counters."""

    def __init__(self, ports: dict[str, int] | None = None) -> None:
        self.ports = dict(ports) if ports is not None else dict(ECHO_PORTS)
        self._servers: list[asyncio.base_events.Server] = []
        self.connection_counts: dict[str, int] = {p: 0 for p in self.ports}
        self.bytes_counts: dict[str, int] = {p: 0 for p in self.ports}

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
                srv = await asyncio.start_server(
                    lambda r, w, p=proto: self._handle(r, w, p),
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
        total_bytes = 0
        try:
            # Echo up to 8 KiB, then send a tiny HTTP-ish reply so curl is happy
            # whether the client sends raw bytes or an HTTP GET.
            data = await asyncio.wait_for(reader.read(8192), timeout=3.0)
            total_bytes = len(data)
            self.bytes_counts[proto] = self.bytes_counts.get(proto, 0) + total_bytes

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
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug("echo handler (%s) error: %s", proto, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self) -> None:
        for srv in self._servers:
            srv.close()
        for srv in self._servers:
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self._servers.clear()

    def snapshot(self) -> dict[str, dict[str, int]]:
        """Return per-protocol {connections, bytes}."""
        return {
            proto: {
                "connections": self.connection_counts.get(proto, 0),
                "bytes": self.bytes_counts.get(proto, 0),
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
