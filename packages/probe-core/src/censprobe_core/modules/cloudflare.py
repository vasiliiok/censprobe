"""
modules/cloudflare.py — Cloudflare infrastructure censorship probes.

Category: "cloudflare"

WARP context (Dec 2024+): Cloudflare made MASQUE (HTTP/3 over QUIC, UDP 443)
the default WARP tunnel protocol, replacing WireGuard. WireGuard remains as
a user-selectable fallback. Russia's TSPU has dropped UDP 443 since ~2022,
which means the *primary* WARP path is broken on most RU uplinks — the
control-plane TCP probes plus the QUIC/MASQUE UDP probe together tell the
operator whether WARP can work at all from this server.

Test families:
  cloudflare_quic_*           — UDP 443 QUIC reachability (incl. WARP MASQUE
                                 anycast at 162.159.197.x).
  cloudflare_warp_*_tcp /
  cloudflare_warp_engage_api,
  cloudflare_warp_connectivity_check,
  cloudflare_warp_zt_orchestration
                              — TCP 443 to WARP control-plane hostnames and the
                                 MASQUE / WireGuard anycast IP ranges; proves
                                 IP-level reachability independent of DNS.
  cloudflare_warp_masque_udp_* — UDP probes to MASQUE fallback ports
                                 (4443/8443). Silent timeout = INCONCLUSIVE;
                                 ICMP rejections surface as BLOCKED.
                                 WireGuard probes (UDP 2408/4500) were
                                 dropped 2026-05-14 — no shared key means
                                 a real WG server's silent-drop branch is
                                 indistinguishable from censorship, so
                                 every probe always returned INCONCLUSIVE.
                                 IP-level reach for 162.159.193.0/24 is
                                 covered by cloudflare_warp_*_tcp.
  cloudflare_http_*           — HTTPS to workers.dev, pages.dev, cloudflare-dns.com
                                 as platform-level censorship canaries.

QUIC verdict:
  Cloudflare's QUIC stack responds to a valid Version Negotiation trigger with a
  Version Negotiation packet (RFC 9000 §6.2). We send a minimal QUIC Long Header
  packet with an unrecognised (GREASE) version and wait up to 3 s:
    response received → OK   (UDP 443 passes TSPU)
    timeout          → IP_DROPPED + QUIC_DROPPED method (UDP 443 silently dropped)
    ICMP unreachable → INCONCLUSIVE (source/routing issue, not TSPU)

WARP tunnel UDP verdict (both MASQUE-fallback and WireGuard ports):
  Real servers silently drop packets that don't authenticate, so we cannot
  expect a positive response. We surface:
    EHOSTUNREACH / "no route" / EPERM → BLOCKED + IP_DROPPED (network
                                          actively refuses the outbound path)
    ICMP Port Unreachable             → INCONCLUSIVE (Cloudflare anycast
                                          PoP doesn't bind this fallback
                                          port; network path is open)
    timeout                           → INCONCLUSIVE (server-silence is the
                                          protocol's normal behaviour)
    QUIC VN reply on a MASQUE port    → OK (port reachable + speaks HTTP/3)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import time
from typing import Any

import httpx

from censprobe_core._evidence import describe_exception
from censprobe_core._tcp_kernel_rtt import read_kernel_rtt_us
from censprobe_core.models import BlockingMethod, TestResult, Verdict
from censprobe_core.server_meta import is_censoring_vantage
from censprobe_core.utils import stamp_test_elapsed

logger = logging.getLogger(__name__)

# These are protocol-level deadlines, not operator preferences, so they
# live as module constants rather than CloudflareModuleConfig fields:
#   * _CONNECT_TIMEOUT — TCP handshake budget for WARP control-plane
#     probes. Generous because the targets live behind Cloudflare's
#     anycast edge and a transient SYN drop is normal.
#   * _QUIC_TIMEOUT — QUIC VN response window. RFC 9000 §6.2 mandates
#     the reply but doesn't bound its latency; 3 s matches the
#     observed Cloudflare anycast PoP RTT plus a small safety margin.
#   * _WG_UDP_TIMEOUT — short on purpose. A WireGuard server silently
#     drops handshakes whose mac1 doesn't match its static pubkey
#     (which we can't compute). Waiting longer just delays the
#     INCONCLUSIVE verdict.
# An operator wanting to dial these from a high-RTT vantage can patch
# them locally; promoting to censprobe.yaml would be config bloat for
# knobs nobody has ever needed to tune.
_CONNECT_TIMEOUT = 10.0
_QUIC_TIMEOUT = 3.0
_WG_UDP_TIMEOUT = 2.0


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


async def run_cloudflare_tests(cfg: dict[str, Any] | None = None) -> list[TestResult]:
    """Run all Cloudflare infrastructure probes.

    ``cfg`` is the parsed contents of ``targets/cloudflare.yaml``; the
    runner pre-loads it and passes it in so this module stays free of
    any workspace/path knowledge. ``None`` is treated as an empty config
    — every for-loop below becomes a no-op rather than crashing.
    """
    cfg = cfg or {}
    results: list[TestResult] = []

    tasks: list[asyncio.Task[TestResult]] = []

    # QUIC probes (parallel)
    for qt in cfg.get("quic_targets", []):
        tasks.append(asyncio.create_task(_test_quic(qt["host"], qt["port"], qt["name"])))

    # WARP TCP probes (parallel)
    for wt in cfg.get("warp_targets", []):
        tasks.append(asyncio.create_task(_test_warp_tcp(wt["host"], wt["port_tcp"], wt["name"])))

    # WARP tunnel UDP probes — covers both MASQUE fallback ports and
    # WireGuard ports. The probe payload is shaped per the declared
    # `protocol` so on-path fingerprinting hardware sees a plausible
    # packet shape (matters in TSPU paths that classify by content).
    for ut in cfg.get("warp_tunnel_udp_targets", []):
        tasks.append(
            asyncio.create_task(
                _test_warp_udp(
                    ut["host"],
                    ut["port_udp"],
                    ut.get("protocol", "wireguard"),
                    ut["name"],
                )
            )
        )

    # HTTP probes (parallel)
    for ht in cfg.get("http_targets", []):
        for url in ht.get("urls", []):
            tasks.append(
                asyncio.create_task(_test_http(ht["domain"], url, ht.get("expected_status", 200)))
            )

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for r in completed:
        if isinstance(r, TestResult):
            results.append(r)
        elif isinstance(r, Exception):
            # Same anti-pattern fix as ``telegram._test_dc_reachability``
            # (which previously silenced TypeErrors at DEBUG and shipped
            # zero DC results for every report). A probe coroutine that
            # raised here used to vanish into a debug log; now it
            # surfaces as a real ERROR row so the dashboard reflects the
            # failure instead of dropping it on the floor.
            logger.warning(
                "cloudflare probe crashed (%s): %s",
                type(r).__name__,
                r,
                exc_info=r,
            )
            results.append(
                TestResult(
                    test="cloudflare_probe_crashed",
                    category="cloudflare",
                    target="(internal)",
                    verdict=Verdict.ERROR,
                    evidence={"error": repr(r), "error_type": type(r).__name__},
                    confidence=0.0,
                    notes="Probe coroutine raised; see listener log for traceback.",
                )
            )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# QUIC / UDP 443
# ─────────────────────────────────────────────────────────────────────────────

_QUIC_INITIAL_MIN_SIZE = 1200  # RFC 9000 §14.1 — anti-amplification floor


def _build_quic_vn_trigger() -> bytes:
    """
    Build a QUIC Long Header datagram with a GREASE (unknown) version.

    Per RFC 9000 §6.2, a QUIC v1 server MUST respond to a packet with an
    unknown version with a Version Negotiation packet — provided the datagram
    is large enough. RFC 9000 §14.1 requires a client to expand any datagram
    carrying an Initial packet to at least 1200 bytes; servers (Cloudflare,
    Google) drop short datagrams as anti-amplification. So we pad with zeros
    to 1200 bytes — the trailing zeros are valid PADDING frames.

    The Length varint covers PacketNumber + Payload — RFC 9000 §17.2.
    We emit a 1-byte PacketNumber + 1-byte Payload, so Length=2.
    (Pre-2026-05-14 this was encoded as Length=1, technically malformed
    Initial framing; most stacks reply to the GREASE version regardless,
    but stricter QUIC implementations may drop the packet before
    reaching the VN logic.)
    """
    dcid = os.urandom(8)
    scid = os.urandom(4)
    header = (
        b"\xc0"  # Long Header + Fixed Bit
        b"\x0a\x0a\x0a\x0a"  # GREASE version
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + b"\x00"  # Token Length = 0
        + b"\x40\x02"  # Length (varint 2-byte form) = 2 — PN(1) + Payload(1)
        + b"\x00"  # Packet Number (1 byte)
        + b"\x00"  # 1-byte payload (PADDING frame)
    )
    return header + b"\x00" * (_QUIC_INITIAL_MIN_SIZE - len(header))


@stamp_test_elapsed
async def _test_quic(host: str, port: int, name: str) -> TestResult:
    """
    Send a QUIC VN trigger to host:port/UDP and wait for any server response.

    Verdict:
      OK           — got a datagram back (UDP 443 is not blocked by TSPU)
      QUIC_DROPPED — timeout (TSPU likely dropping UDP 443 packets)
      INCONCLUSIVE — socket/routing error not attributable to TSPU
    """
    probe = _build_quic_vn_trigger()
    received_data: bytes | None = None

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            # ``create_datagram_endpoint`` always hands us a DatagramTransport
            # — narrowed via isinstance + raise (not assert, which python -O
            # strips) so a future asyncio change surfaces loudly.
            if not isinstance(transport, asyncio.DatagramTransport):
                raise RuntimeError(f"expected DatagramTransport, got {type(transport).__name__}")
            transport.sendto(probe)

        def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
            if not self.fut.done():
                self.fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not self.fut.done():
                self.fut.set_exception(exc)

        def connection_lost(self, exc: Exception | None) -> None:
            if not self.fut.done():
                self.fut.cancel()

    t0 = time.monotonic()
    transport = None
    try:
        loop = asyncio.get_running_loop()
        transport, proto = await loop.create_datagram_endpoint(
            _Proto,
            remote_addr=(host, port),
            family=socket.AF_INET,
        )
        received_data = await asyncio.wait_for(proto.fut, timeout=_QUIC_TIMEOUT)
        rtt_ms = (time.monotonic() - t0) * 1000

        # Minimal response validation: first byte MSB = 1 → Long Header (VN or other)
        is_vn = (
            len(received_data) >= 5
            and (received_data[0] & 0x80)
            and received_data[1:5] == b"\x00\x00\x00\x00"
        )
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"udp://{host}:{port}",
            verdict=Verdict.OK,
            rtt_ms=rtt_ms,
            evidence={
                "response_bytes": len(received_data),
                "is_version_negotiation": is_vn,
                "note": "UDP 443 passes TSPU — QUIC/HTTP3 accessible",
            },
        )

    except TimeoutError:
        # Vantage gating: timeout → QUIC_DROPPED is a censor-specific
        # attribution. Outside the configured censoring countries a
        # UDP 443 timeout is far more likely to be a transient anycast
        # loss / source-port collision than a censor; surface as
        # INCONCLUSIVE so the scoring layer doesn't tally it as a
        # censorship technique.
        if is_censoring_vantage():
            return TestResult(
                test=name,
                category="cloudflare",
                target=f"udp://{host}:{port}",
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.QUIC_DROPPED,
                evidence={
                    "error": "udp_timeout",
                    "timeout_sec": _QUIC_TIMEOUT,
                },
                notes=(
                    "No QUIC VN response — UDP 443 blocked or filtered "
                    "(HTTP3/QUIC unusable from this server)"
                ),
                confidence=0.75,
            )
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"udp://{host}:{port}",
            verdict=Verdict.INCONCLUSIVE,
            evidence={
                "error": "udp_timeout",
                "timeout_sec": _QUIC_TIMEOUT,
                "reason": "non_ru_vantage_no_quic_drop_attribution",
            },
            notes="UDP 443 timeout from non-RU vantage — not attributed to TSPU.",
            confidence=0.3,
        )

    except OSError as e:
        # ICMP Unreachable (ECONNREFUSED on Linux for UDP) → host/port rejection,
        # but not TSPU blocking.
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"udp://{host}:{port}",
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": str(e), "reason": "socket_error"},
            notes="UDP socket error — cannot attribute to TSPU",
        )

    except Exception as e:
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"udp://{host}:{port}",
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": str(e)},
        )

    finally:
        if transport:
            transport.close()


# ─────────────────────────────────────────────────────────────────────────────
# WARP TCP reachability
# ─────────────────────────────────────────────────────────────────────────────


@stamp_test_elapsed
async def _test_warp_tcp(host: str, port: int, name: str) -> TestResult:
    """
    TCP connect to WARP endpoint. Verifies IP-level reachability independent of
    WireGuard protocol (WG is UDP 2408; this is the HTTPS registration endpoint).
    """
    t0 = time.monotonic()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
        # Prefer kernel tcpi_rtt over wall-clock — wall-clock includes
        # event-loop scheduling overhead and gets 10-100× inflated under
        # Phase A load. See ``_tcp_kernel_rtt`` module docstring. Read
        # BEFORE the writer.close() below — TIME_WAIT zeros tcpi_rtt.
        kernel_rtt_us = read_kernel_rtt_us(writer)
        wallclock_ms = (time.monotonic() - t0) * 1000
        rtt_ms = kernel_rtt_us / 1000.0 if kernel_rtt_us is not None else wallclock_ms
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"tcp://{host}:{port}",
            verdict=Verdict.OK,
            rtt_ms=rtt_ms,
            evidence={
                "tcp_connect_ms": round(rtt_ms, 1),
                "wallclock_ms": round(wallclock_ms, 1),
            },
        )
    except TimeoutError:
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"tcp://{host}:{port}",
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.IP_DROPPED,
            evidence={"error": "tcp_timeout"},
            notes="TCP timeout to WARP endpoint — IP likely blocked",
        )
    except ConnectionRefusedError:
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"tcp://{host}:{port}",
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.TCP_REFUSED,
            evidence={"error": "connection_refused"},
        )
    except OSError as e:
        err = str(e).lower()
        if "network is unreachable" in err or "no route" in err:
            return TestResult(
                test=name,
                category="cloudflare",
                target=f"tcp://{host}:{port}",
                verdict=Verdict.INCONCLUSIVE,
                evidence={"error": str(e), "reason": "no_route_local"},
                notes="No route to host — local connectivity issue, not TSPU",
            )
        method = BlockingMethod.TCP_RST_INJECTION if "reset" in err else None
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"tcp://{host}:{port}",
            verdict=Verdict.BLOCKED,
            method=method,
            evidence={"error": str(e)},
        )
    finally:
        if writer:
            # Best-effort connection teardown — peer may already have
            # closed the connection during a probe failure.
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()


# ─────────────────────────────────────────────────────────────────────────────
# WARP tunnel UDP reachability — MASQUE fallback ports + WireGuard ports
# ─────────────────────────────────────────────────────────────────────────────


def _build_wg_handshake_init() -> bytes:
    """
    Build a WireGuard handshake-initiation packet (per wireguard.com whitepaper
    §5.4.2). 148 bytes total.

    Cloudflare WARP servers validate mac1 against their static public key and
    silently drop anything that doesn't match — we don't expect a reply. The
    well-formed shape just lowers the chance an intermediate device does
    protocol-based dropping before our packet leaves the network.
    """
    return (
        b"\x01"  # message_type = handshake init
        + b"\x00\x00\x00"  # reserved
        + os.urandom(4)  # sender_index
        + os.urandom(32)  # unencrypted ephemeral
        + os.urandom(48)  # encrypted static (32B + 16B Poly1305 tag)
        + os.urandom(28)  # encrypted timestamp (12B TAI64N + 16B Poly1305 tag)
        + os.urandom(16)  # mac1
        + b"\x00" * 16  # mac2
    )


def _build_masque_probe_packet() -> bytes:
    """
    Build a packet plausibly shaped like a QUIC Initial / Long Header datagram
    used by MASQUE / HTTP-3 transport.

    Reuses `_build_quic_vn_trigger`: the GREASE-version Long Header is what a
    QUIC server expects on UDP 443 / MASQUE-fallback ports. A real Cloudflare
    MASQUE server on these alt ports won't respond without proper TLS
    encryption, but the packet shape passes through QUIC-aware classifiers
    that would otherwise drop random UDP bytes.
    """
    return _build_quic_vn_trigger()


def _build_warp_ok_result(
    name: str,
    target: str,
    protocol: str,
    data: bytes,
    rtt_ms: float,
) -> TestResult:
    """Decide between MASQUE-VN-confirmed and generic UDP-reply outcomes."""
    # MASQUE fallback ports run a real QUIC server, so a Version
    # Negotiation reply to our GREASE-version trigger is the expected
    # positive signal. WireGuard would only reply to a packet with a
    # correct mac1, which we can't compute without the server pubkey —
    # any reply on a WG port is suspicious.
    is_masque_vn = (
        protocol == "masque"
        and len(data) >= 5
        and (data[0] & 0x80)
        and data[1:5] == b"\x00\x00\x00\x00"
    )
    if is_masque_vn:
        note = "QUIC VN reply — MASQUE port reachable and running HTTP/3"
        confidence = 0.9
    else:
        note = (
            "Got UDP reply (unexpected for unauthenticated probe; on-path device may be answering)"
        )
        confidence = 0.6
    return TestResult(
        test=name,
        category="cloudflare",
        target=target,
        verdict=Verdict.OK,
        rtt_ms=rtt_ms,
        evidence={
            "protocol": protocol,
            "response_bytes": len(data),
            "note": note,
        },
        confidence=confidence,
    )


def _warp_udp_timeout_result(name: str, target: str, protocol: str) -> TestResult:
    return TestResult(
        test=name,
        category="cloudflare",
        target=target,
        verdict=Verdict.INCONCLUSIVE,
        evidence={
            "protocol": protocol,
            "error": "udp_timeout",
            "timeout_sec": _WG_UDP_TIMEOUT,
            "reason": "tunnel_silently_drops_invalid",
        },
        notes=(
            f"UDP timeout on a {protocol} port is the protocol's default "
            "behaviour — cannot be attributed to censorship without a "
            "positive control signal."
        ),
        confidence=0.1,
    )


def _warp_udp_icmp_unreachable_result(name: str, target: str, protocol: str) -> TestResult:
    # Linux surfaces ICMP Port Unreachable as ECONNREFUSED on connected UDP.
    # Cloudflare's anycast members don't bind every advertised fallback
    # port, so ICMP-unreachable here is NOT censorship — it's "this PoP
    # doesn't speak this port". INCONCLUSIVE (not REFUSED) keeps the
    # dashboard "blocked" count clean while the ICMP signal lives in
    # evidence as forensic data: it proves the network path is open,
    # only the application-port mapping is missing.
    return TestResult(
        test=name,
        category="cloudflare",
        target=target,
        verdict=Verdict.INCONCLUSIVE,
        evidence={
            "protocol": protocol,
            "error": "icmp_unreachable",
            "reason": "pop_doesnt_bind_fallback_port",
        },
        notes=(
            "ICMP Port Unreachable. Network path open; this Cloudflare "
            "anycast member is just not advertising this fallback port. "
            "Not a censorship signal."
        ),
        confidence=0.3,
    )


def _classify_warp_udp_oserror(e: OSError, name: str, target: str, protocol: str) -> TestResult:
    err = str(e).lower()
    if "network is unreachable" in err or "no route" in err or "permission denied" in err:
        return TestResult(
            test=name,
            category="cloudflare",
            target=target,
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.IP_DROPPED,
            evidence={"protocol": protocol, "error": str(e)},
            notes="Network rejection on outbound UDP — IP-level filter.",
        )
    return TestResult(
        test=name,
        category="cloudflare",
        target=target,
        verdict=Verdict.INCONCLUSIVE,
        evidence={"protocol": protocol, "error": str(e)},
    )


@stamp_test_elapsed
async def _test_warp_udp(
    host: str,
    port: int,
    protocol: str,
    name: str,
) -> TestResult:
    """
    Probe a WARP tunnel UDP port (either MASQUE fallback port or WireGuard).

    Payload is chosen by `protocol` so fingerprinting middleboxes see a
    plausible packet for the port — random bytes would get dropped earlier.

    Verdicts:
      BLOCKED      — sendto raised (EHOSTUNREACH / "no route" / EPERM): the
                     local network stack refuses the outbound path before the
                     packet leaves the host.
      OK           — got a datagram back. On a MASQUE port a QUIC VN reply
                     to our GREASE-version trigger is the expected positive
                     signal (HTTP/3 server is up); on a WG port any reply is
                     unusual (we can't form a valid mac1 without the server
                     pubkey) so confidence stays lower.
      INCONCLUSIVE — silent timeout (MASQUE/WG silently drop unauthenticated
                     handshakes, can't attribute to censorship), or ICMP
                     Port Unreachable (Cloudflare anycast PoP doesn't bind
                     this fallback port — network path is open, so this is
                     not a censorship signal).
    """
    if protocol == "masque":
        probe = _build_masque_probe_packet()
    else:  # wireguard or unknown — fall back to WG shape
        probe = _build_wg_handshake_init()

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            # ``create_datagram_endpoint`` always hands us a DatagramTransport
            # — narrowed via isinstance + raise (not assert, which python -O
            # strips) so a future asyncio change surfaces loudly.
            if not isinstance(transport, asyncio.DatagramTransport):
                raise RuntimeError(f"expected DatagramTransport, got {type(transport).__name__}")
            try:
                transport.sendto(probe)
            except OSError as e:
                if not self.fut.done():
                    self.fut.set_exception(e)

        def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
            if not self.fut.done():
                self.fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not self.fut.done():
                self.fut.set_exception(exc)

        def connection_lost(self, exc: Exception | None) -> None:
            if not self.fut.done():
                self.fut.cancel()

    target = f"udp://{host}:{port}"
    t0 = time.monotonic()
    transport = None
    try:
        loop = asyncio.get_running_loop()
        transport, proto = await loop.create_datagram_endpoint(
            _Proto,
            remote_addr=(host, port),
            family=socket.AF_INET,
        )
        data = await asyncio.wait_for(proto.fut, timeout=_WG_UDP_TIMEOUT)
        rtt_ms = (time.monotonic() - t0) * 1000
        return _build_warp_ok_result(name, target, protocol, data, rtt_ms)
    except TimeoutError:
        return _warp_udp_timeout_result(name, target, protocol)
    except ConnectionRefusedError:
        return _warp_udp_icmp_unreachable_result(name, target, protocol)
    except OSError as e:
        return _classify_warp_udp_oserror(e, name, target, protocol)
    except Exception as e:
        return TestResult(
            test=name,
            category="cloudflare",
            target=target,
            verdict=Verdict.INCONCLUSIVE,
            evidence={"protocol": protocol, "error": str(e)},
        )
    finally:
        if transport:
            transport.close()


# ─────────────────────────────────────────────────────────────────────────────
# HTTP/HTTPS platform tests
# ─────────────────────────────────────────────────────────────────────────────


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").replace("/", "_")


@stamp_test_elapsed
async def _test_http(domain: str, url: str, expected_status: int) -> TestResult:
    """HTTPS GET to a Cloudflare platform URL."""
    test_name = f"cloudflare_http_{_slug(domain)}"
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
            verify=True,
        ) as client:
            r = await client.get(url)
        rtt_ms = (time.monotonic() - t0) * 1000

        if r.status_code in (403, 429, 451):
            return TestResult(
                test=test_name,
                category="cloudflare",
                target=url,
                verdict=Verdict.SERVER_REFUSED,
                rtt_ms=rtt_ms,
                evidence={"status": r.status_code},
            )

        verdict = Verdict.OK if r.status_code == expected_status else Verdict.ANOMALY
        return TestResult(
            test=test_name,
            category="cloudflare",
            target=url,
            verdict=verdict,
            rtt_ms=rtt_ms,
            evidence={"status": r.status_code, "expected": expected_status},
        )

    except httpx.ConnectTimeout:
        return TestResult(
            test=test_name,
            category="cloudflare",
            target=url,
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.IP_DROPPED,
            evidence={"error": "connect_timeout"},
        )
    except httpx.ConnectError as e:
        err_text = describe_exception(e)
        err_lower = err_text.lower()
        method = (
            BlockingMethod.TLS_HANDSHAKE_FAILURE
            if ("ssl" in err_lower or "certificate" in err_lower)
            else BlockingMethod.IP_DROPPED
        )
        return TestResult(
            test=test_name,
            category="cloudflare",
            target=url,
            verdict=Verdict.BLOCKED,
            method=method,
            evidence={"error": err_text},
        )
    except Exception as e:
        return TestResult(
            test=test_name,
            category="cloudflare",
            target=url,
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": describe_exception(e)},
        )
