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
from collections.abc import Awaitable, Callable

# Canonical home of the echo-port contract is probe-core (it is shared
# with the client-side probe via :mod:`censprobe_core.protocol_probes`,
# so a single source of truth eliminates silent drift). Re-exported here
# for back-compat with the responder modules that imported it from this
# file historically.
from censprobe_core.echo_ports import (
    ECHO_PORTS,
    SOCKS_ECHO_PORTS,
    TUN_ECHO_PORTS,
)

# Type alias for the wire-throughput byte-counter callback. Echo server
# calls this before/after the /throughput body emission and computes
# Mbps from the delta — see ``_serve_throughput`` for the rationale.
ThroughputReader = Callable[[], Awaitable["int | None"]]

# How long to poll the wire byte-counter after the body has been fully
# pushed to the loopback writer. Counter ticks at link rate via TCP
# backpressure (slow client = slow tick); we keep polling until two
# consecutive 100 ms samples show no growth, with this hard ceiling
# so a totally stuck transfer doesn't wedge the handler forever.
_WIRE_THROUGHPUT_QUIESCE_MAX_SEC = 30.0
_WIRE_THROUGHPUT_POLL_INTERVAL_SEC = 0.1
_WIRE_THROUGHPUT_QUIESCE_SAMPLES = 3

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
# _serve_throughput) and the resulting Mbps figure is meaningless. 30 ms
# is comfortably above the loopback round-trip (sub-millisecond on Linux
# host-mode docker) while leaving headroom to record real ~2 Gbps
# transfers of the 8 MiB target_bytes payload.
_MIN_THROUGHPUT_DURATION_SEC = 0.03

# Even with duration above the floor, anything wildly above what a real
# remote tunnel can deliver is the same artefact under a different mask
# (write was very small, kernel still absorbed in <one tick). 5 Gbps is
# above any consumer / VPS uplink we expect to test against; treat
# anything beyond as "kernel buffer absorption did not block hard enough"
# and discard.
_MAX_PLAUSIBLE_MBPS = 5000.0


class EchoServer:
    """Single-process asyncio TCP echo server with per-port counters.

    Bind topology:
      * SOCKS-routed protocols (shadowsocks / vless_reality / hysteria2) —
        bound on 127.0.0.1 at :meth:`start`, reachable only through the
        protocol's SOCKS responder.
      * VPN protocols (openvpn / wireguard / amneziawg) — NOT bound at
        :meth:`start`. Instead, each VPN responder calls
        :meth:`add_tun_bind` after its tun device is up; the echo server
        binds the corresponding port on the listener-side tun IP, so the
        socket only accepts traffic that routes through the tun and is
        never exposed on any public interface. :meth:`stop` tears down
        both kinds.

    Per-protocol counters (``connection_counts``, ``bytes_counts``,
    ``throughput_mbps``) are pre-allocated for every protocol in
    :data:`ECHO_PORTS` whether or not it ends up bound — keeps the
    snapshot shape stable for downstream consumers.
    """

    def __init__(self, ports: dict[str, int] | None = None) -> None:
        self.ports = dict(ports) if ports is not None else dict(ECHO_PORTS)
        # Initial-bind set: SOCKS-routed protocols only. VPN protocols
        # join this set via add_tun_bind() after their tun is up. The
        # custom ``ports`` override is honoured as-is for test scenarios
        # that want to bind everything immediately on 127.0.0.1.
        if ports is None:
            self._initial_bind_ports = dict(SOCKS_ECHO_PORTS)
        else:
            self._initial_bind_ports = dict(self.ports)
        # Servers are tracked per-bind so add_tun_bind / stop can manage
        # them independently. The key for SOCKS ports is the protocol
        # name; tun-side binds use a synthetic ``f"{proto}@{ip}"`` key
        # so a probe that re-runs the same protocol in a single session
        # can rebind cleanly.
        self._servers: dict[str, asyncio.base_events.Server] = {}
        self.connection_counts: dict[str, int] = dict.fromkeys(self.ports, 0)
        self.bytes_counts: dict[str, int] = dict.fromkeys(self.ports, 0)
        # Latest /throughput measurement per protocol — None until a probe
        # actually requests one. Overwritten on each call rather than
        # averaged, because the operator wants the most recent observation
        # not a smoothed history.
        self.throughput_mbps: dict[str, float | None] = dict.fromkeys(self.ports)
        # Wire-throughput readers registered by SOCKS-tunneled responders
        # (SS / VLESS+Reality / Hysteria2). Each callback reads the
        # iptables byte counter on the tunnel binary's WAN-facing port —
        # see SubprocessResponder.read_throughput_bytes. When present,
        # the /throughput handler computes Mbps from counter delta rather
        # than the loopback FIN-ACK time, eliminating the kernel-buffer-
        # absorption inflation that made hysteria2 appear at 54 Mbps on
        # a 5 Mbps cellular client uplink.
        self._throughput_readers: dict[str, ThroughputReader] = {}

    async def start(self) -> None:
        # Bring up each port; on partial failure (e.g. one of the loopback
        # ports already busy from a leaked previous run) tear down everything
        # we did manage to start so we don't leak listening sockets that
        # block the next start_server() retry. The listener's main.py
        # treats any exception here as "no echo server" and continues —
        # without this rollback, those orphan servers would survive.
        try:
            for proto, port in self._initial_bind_ports.items():
                await self._bind_one(proto=proto, host="127.0.0.1", port=port, key=proto)
        except Exception:
            await self.stop()
            raise

    async def _bind_one(self, *, proto: str, host: str, port: int, key: str) -> None:
        """Open one listening socket on ``(host, port)`` for ``proto``.

        ``reuse_address=True`` lets us rebind to the same port even if the
        previous listener died with sockets still in TIME_WAIT — without
        it, a fast restart hits "address already in use". asyncio enables
        it by default on POSIX but we set it explicitly so the behaviour
        doesn't depend on platform defaults.

        Capture ``proto`` by default-arg binding inside ``_client_cb`` so
        each spawned server keeps its own protocol label (closing over
        the loop variable would give every server the last value).
        """

        async def _client_cb(
            r: asyncio.StreamReader,
            w: asyncio.StreamWriter,
            p: str = proto,
        ) -> None:
            await self._handle(r, w, p)

        srv = await asyncio.start_server(
            _client_cb,
            host=host,
            port=port,
            reuse_address=True,
        )
        # Replace any previous bind under the same key (e.g. a leftover
        # tun bind from a half-torn-down session); the new socket inherits
        # the counters because they live at the protocol level, not the
        # bind level.
        if key in self._servers:
            old = self._servers.pop(key)
            old.close()
            with contextlib.suppress(Exception):
                await old.wait_closed()
        self._servers[key] = srv
        logger.info("echo server: %s on %s:%d", proto, host, port)

    def register_throughput_reader(self, proto: str, reader: ThroughputReader) -> None:
        """Register a wire-throughput byte-counter reader for ``proto``.

        Called by SubprocessResponder.start() after its iptables
        accounting rule is installed. The /throughput handler picks up
        the reader the next time a client probes; absence (or a reader
        that returns None) signals "no wire-side counter" and falls back
        to the loopback wait_closed timing.
        """
        self._throughput_readers[proto] = reader

    def unregister_throughput_reader(self, proto: str) -> None:
        """Drop the reader registered by :meth:`register_throughput_reader`.

        Idempotent: missing-key removals are no-ops, so a half-failed
        responder start that never registered won't crash on stop.
        """
        self._throughput_readers.pop(proto, None)

    async def add_tun_bind(self, proto: str, tun_ip: str) -> None:
        """Bind ``proto``'s echo port on a VPN responder's listener-side tun IP.

        Called by openvpn / wireguard / amneziawg responders after their
        tun device is up. The bind only succeeds once the kernel knows
        about ``tun_ip``, which guarantees the socket is reachable solely
        through the tun (no host-network exposure).

        Idempotent against responder restarts — re-binding with the same
        ``(proto, tun_ip)`` replaces any previous server under the same
        key.
        """
        port = TUN_ECHO_PORTS.get(proto)
        if port is None:
            raise ValueError(
                f"add_tun_bind: {proto!r} is not a VPN protocol (known: {sorted(TUN_ECHO_PORTS)})"
            )
        key = f"{proto}@{tun_ip}"
        await self._bind_one(proto=proto, host=tun_ip, port=port, key=key)

    async def remove_tun_bind(self, proto: str, tun_ip: str) -> None:
        """Tear down the bind registered by :meth:`add_tun_bind`.

        Safe to call when no matching bind exists (e.g. responder stop()
        races with start() failure) — the missing-key case is a no-op.
        """
        key = f"{proto}@{tun_ip}"
        srv = self._servers.pop(key, None)
        if srv is None:
            return
        srv.close()
        with contextlib.suppress(Exception):
            await srv.wait_closed()
        logger.info("echo server: %s on %s removed", proto, tun_ip)

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
        """Stream N zero bytes back; measure transfer time on the WAN.

        Two measurement methodologies live here:

        1. **Wire-counter delta (preferred for SOCKS-tunneled protocols).**
           When a responder has registered a wire byte-counter reader
           (SS / VLESS+Reality / Hysteria-2 — :class:`SubprocessResponder`
           installs an iptables OUTPUT --sport=<port> rule), we snapshot
           the counter before emitting the body, push the body to the
           loopback writer, and then poll the counter until consecutive
           samples show no growth. ``Mbps = (bytes_delta * 8) / quiesce_time``
           reflects the bytes that REALLY crossed the WAN — TCP back-pressure
           from the slow client downlink throttles the tunnel binary's
           WAN-write, which throttles the loopback-read, which delays the
           counter ticks at line rate. Robust on cellular vantages where
           the previous wait_closed methodology over-reported by 5–10×.

        2. **wait_closed fallback (VPN protocols + no-iptables hosts).**
           For OpenVPN / WireGuard / AmneziaWG the echo binds on the
           listener-side tun IP, so loopback buffer absorption isn't a
           factor — the bytes go through the kernel tun device, get
           encapsulated, hit the WAN, and the FIN-ACK round-trip reflects
           wire delivery. Also used when iptables wasn't available at
           responder start (no CAP_NET_ADMIN, missing binary). Discards
           anything that lands inside the kernel-buffer-absorption regime
           (``_MIN_THROUGHPUT_DURATION_SEC`` / ``_MAX_PLAUSIBLE_MBPS``).
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

        reader = self._throughput_readers.get(proto)
        bytes_before: int | None = None
        if reader is not None:
            try:
                bytes_before = await reader()
            except Exception as e:
                logger.debug("throughput[%s] pre-read failed: %s", proto, e)
                bytes_before = None

        t0 = time.monotonic()
        wait_closed_duration: float | None = None
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
            wait_closed_duration = time.monotonic() - t0
        except TimeoutError:
            wait_closed_duration = time.monotonic() - t0
        except Exception as e:
            logger.debug("throughput serve to %s aborted: %s", proto, e)
            return

        # Try the wire-counter delta methodology first when available;
        # fall back to wait_closed if the counter read failed mid-poll
        # or the responder didn't register one. ``measured`` flag tells
        # us "the counter was consulted and produced a final value
        # (possibly None=no delta)" — distinct from "the counter chain
        # was broken" where we want the legacy fallback.
        if reader is not None and bytes_before is not None:
            measured, mbps = await self._measure_throughput_via_counter(
                proto=proto,
                reader=reader,
                bytes_before=bytes_before,
                t0=t0,
            )
            if measured:
                self.throughput_mbps[proto] = mbps
                return
            # Counter read returned None mid-poll — fall through to the
            # wait_closed-based methodology below as a backup. The
            # operator log already explained the fallback in the helper.

        self._record_wait_closed_throughput(
            proto=proto,
            n=n,
            duration=wait_closed_duration,
        )

    async def _measure_throughput_via_counter(
        self,
        *,
        proto: str,
        reader: ThroughputReader,
        bytes_before: int,
        t0: float,
    ) -> tuple[bool, float | None]:
        """Poll the WAN byte counter until quiesce; compute Mbps from delta.

        Returns ``(measured, mbps)``:
          * ``(True, mbps)`` — counter delivered a final delta; ``mbps``
            is the computed value or ``None`` if the delta was zero
            (legitimate "tunnel emitted no wire bytes" outcome — caller
            stores None, does NOT fall back to wait_closed).
          * ``(False, None)`` — the counter chain broke mid-poll
            (iptables binary disappeared, ip6tables out of sync, etc).
            Caller falls back to wait_closed timing.

        The quiesce window is `_WIRE_THROUGHPUT_QUIESCE_SAMPLES ×
        _WIRE_THROUGHPUT_POLL_INTERVAL_SEC` of no-growth — small enough
        to avoid waiting for a phantom retransmit flurry, large enough
        to ride out TCP's coalescing pauses on slow links. Hard ceiling
        is ``_WIRE_THROUGHPUT_QUIESCE_MAX_SEC`` so a permanently stuck
        transfer doesn't wedge the handler.
        """
        deadline = t0 + _WIRE_THROUGHPUT_QUIESCE_MAX_SEC
        prev = bytes_before
        no_growth = 0
        last_total = bytes_before
        last_t = t0
        while time.monotonic() < deadline:
            await asyncio.sleep(_WIRE_THROUGHPUT_POLL_INTERVAL_SEC)
            try:
                current = await reader()
            except Exception as e:
                logger.info(
                    "throughput[%s] counter poll failed: %s — falling back",
                    proto,
                    e,
                )
                return False, None
            if current is None:
                logger.info(
                    "throughput[%s] counter no longer available — falling back",
                    proto,
                )
                return False, None
            last_t = time.monotonic()
            last_total = current
            if current == prev:
                no_growth += 1
                if no_growth >= _WIRE_THROUGHPUT_QUIESCE_SAMPLES:
                    break
            else:
                no_growth = 0
                prev = current

        delta_bytes = last_total - bytes_before
        elapsed = last_t - t0
        if delta_bytes <= 0 or elapsed <= 0:
            logger.info(
                "throughput[%s] wire counter saw no delta over %.2fs — "
                "tunnel binary didn't emit bytes (DPI silent-drop on the "
                "WAN-side, or the probe ended before the kernel flushed). "
                "Discarding the measurement.",
                proto,
                elapsed,
            )
            return True, None
        mbps = (delta_bytes * 8) / elapsed / 1_000_000
        logger.info(
            "throughput[%s]: %.2f Mbps (wire-counter: %d bytes over %.2fs) — "
            "TCP backpressure throttled at line rate, methodology=iptables-delta",
            proto,
            mbps,
            delta_bytes,
            elapsed,
        )
        return True, mbps

    def _record_wait_closed_throughput(
        self,
        *,
        proto: str,
        n: int,
        duration: float | None,
    ) -> None:
        """Legacy wait_closed-based methodology — accurate for VPN protocols
        (echo on tun-IP, real kernel encap) but unreliable for SOCKS-tunneled.

        Kept as a fallback for: (a) VPN protocols where it's correct;
        (b) hosts without CAP_NET_ADMIN where the iptables counter
        install failed silently. Discards anything inside the kernel-
        buffer-absorption regime so dashboards don't display fabricated
        multi-Gbps values.
        """
        if not duration or duration <= 0:
            return
        mbps = (n * 8) / duration / 1_000_000
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
            "throughput[%s]: %.2f Mbps (%d bytes in %.2fs, methodology=wait_closed)",
            proto,
            mbps,
            n,
            duration,
        )

    async def stop(self) -> None:
        # Snapshot the values then clear so an exception in wait_closed
        # leaves _servers empty (start() can be re-called).
        servers = list(self._servers.values())
        self._servers.clear()
        for srv in servers:
            srv.close()
        for srv in servers:
            # Servers may already be in the process of shutting down by
            # the time we reach this loop (SIGTERM races) — suppress.
            with contextlib.suppress(Exception):
                await srv.wait_closed()

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
        # "GET /throughput?bytes=8388608 HTTP/1.1"
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
