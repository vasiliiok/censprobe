"""
modules/protocols.py — VPN protocol signature tests from the probe side.

Solo sends raw handshake packets to a control-point (listener) and checks
whether they arrive and get a valid response.

Tests:
  - OpenVPN:        P_CONTROL_HARD_RESET_CLIENT_V2 UDP packet
  - WireGuard:      Handshake initiation (type=0x01, 148 bytes) UDP
  - Shadowsocks:    TCP connect + random header (signature detection probe)
  - VLESS+Reality:  TCP connect + TLS ClientHello with Reality SNI
  - Hysteria 2:     UDP QUIC Initial packet with salamander XOR

If control_endpoints is None (solo-only mode), returns INCONCLUSIVE.
When listener is running, control_endpoints comes from protocols.yaml.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import struct
import time
from typing import Optional

from censprobe_core.models import BlockingMethod, TestResult, Verdict

logger = logging.getLogger(__name__)

_UDP_TIMEOUT = 5.0
_TCP_TIMEOUT = 6.0


async def run_protocol_tests(
    control_endpoints: list[dict] | None = None,
) -> list[TestResult]:
    """
    Run VPN protocol signature tests.

    In solo-without-listener mode, these return INCONCLUSIVE because there
    is no server to respond. When listener is deployed, pass control_endpoints
    from protocols.yaml so probes can measure actual reachability.

    control_endpoints: list of {"protocol": "openvpn", "ip": "...", "port": 1194, ...}
    """
    if not control_endpoints:
        return [
            TestResult(
                test="protocols_listener_not_configured",
                category="protocols",
                target="n/a",
                verdict=Verdict.INCONCLUSIVE,
                evidence={"reason": "No listener endpoint configured. Run listener container first."},
                notes="Protocol tests require listener container to be running",
            )
        ]

    results = []
    for ep in control_endpoints:
        protocol = ep.get("protocol", "unknown")
        ip = ep.get("ip", "")
        port = ep.get("port", 0)
        if not ip or not port:
            continue

        if protocol == "openvpn":
            r = await _test_openvpn_handshake(ip, port)
        elif protocol == "wireguard":
            r = await _test_wireguard_handshake(ip, port)
        elif protocol == "amneziawg":
            # AmneziaWG handshake is structurally identical to WireGuard
            # (same UDP packet structure; junk params only matter for key derivation)
            r = await _test_wireguard_handshake(ip, port)
            r.test = r.test.replace("wireguard", "amneziawg")
        elif protocol == "shadowsocks":
            r = await _test_shadowsocks_signature(ip, port)
        elif protocol == "vless_reality":
            server_name = ep.get("server_name", "apimaps.yandex.ru")
            r = await _test_vless_reality_tls(ip, port, server_name)
        elif protocol == "hysteria2":
            obfs_password = ep.get("obfs_password", "")
            r = await _test_hysteria2_quic(ip, port, obfs_password)
        else:
            r = TestResult(
                test=f"protocol_{protocol}",
                category="protocols",
                target=f"{ip}:{port}",
                verdict=Verdict.INCONCLUSIVE,
                evidence={"reason": f"Protocol '{protocol}' not supported in solo probe"},
            )
        results.append(r)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN
# ─────────────────────────────────────────────────────────────────────────────

async def _test_openvpn_handshake(ip: str, port: int) -> TestResult:
    """
    Send OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 packet (opcode 0x38) via UDP.
    Expect any response — a server reply means ТСПУ hasn't blocked this signature.

    Packet format (simplified):
      byte 0: opcode<<3 | key_id  → 0x38 = P_CONTROL_HARD_RESET_CLIENT_V2
      bytes 1-8: session ID (random)
      byte 9:    ack array length (0)
      bytes 10-13: packet ID (1)
    """
    test_name = f"protocol_openvpn_{ip}_{port}"
    target = f"{ip}:{port}/udp"

    session_id = os.urandom(8)
    packet_id = struct.pack(">I", 1)
    opcode_keyid = bytes([0x38])   # P_CONTROL_HARD_RESET_CLIENT_V2, key_id=0
    ack_len = bytes([0])
    packet = opcode_keyid + session_id + ack_len + packet_id

    return await _udp_probe(
        test_name=test_name,
        target=target,
        ip=ip,
        port=port,
        payload=packet,
        protocol_name="openvpn",
        block_method=BlockingMethod.OPENVPN_SIGNATURE_BLOCKED,
    )


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard
# ─────────────────────────────────────────────────────────────────────────────

async def _test_wireguard_handshake(ip: str, port: int) -> TestResult:
    """
    Send WireGuard Handshake Initiation (type=0x01, 148 bytes) via UDP.
    A real listener responds with type=0x02. No response = blocked.

    Sends a syntactically valid-length packet with random crypto material.
    ТСПУ can detect WireGuard by packet length+type before cryptographic checks.
    """
    test_name = f"protocol_wireguard_{ip}_{port}"
    target = f"{ip}:{port}/udp"

    # WG Initiation: type(4) + reserved(4) + ephemeral(32) + static_enc(48) + timestamp(28) + mac1(16) + mac2(16) = 148 bytes
    wg_type = struct.pack("<I", 1)   # type = 1 (handshake initiation)
    wg_reserved = bytes(4)
    wg_body = os.urandom(140)        # rest is random (not cryptographically valid)
    packet = wg_type + wg_reserved + wg_body  # 148 bytes total

    return await _udp_probe(
        test_name=test_name,
        target=target,
        ip=ip,
        port=port,
        payload=packet,
        protocol_name="wireguard",
        block_method=BlockingMethod.WIREGUARD_SIGNATURE_BLOCKED,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Shadowsocks 2022 — TCP signature probe
# ─────────────────────────────────────────────────────────────────────────────

async def _test_shadowsocks_signature(ip: str, port: int) -> TestResult:
    """
    TCP connect to Shadowsocks port + send a random 32-byte salt header.

    ТСПУ may detect SS by:
    - Actively probing the SS server (active probing attack)
    - Blocking all traffic to known SS ports

    If TCP connect succeeds → HANDSHAKE_ONLY (port is open).
    If connection refused or RST → BLOCKED.
    If server sends a response → OK (not expected, ss silently drops bad data).
    """
    test_name = f"protocol_shadowsocks_{ip}_{port}"
    target = f"{ip}:{port}/tcp"
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    try:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=_TCP_TIMEOUT,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            rtt = (time.monotonic() - t0) * 1000
            return TestResult(
                test=test_name,
                category="protocols",
                target=target,
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.SHADOWSOCKS_ACTIVE_PROBED,
                rtt_ms=rtt,
                evidence={"error": str(e), "protocol": "shadowsocks"},
            )

        rtt = (time.monotonic() - t0) * 1000

        # Send random salt (SS-2022 header)
        writer.write(os.urandom(32))
        try:
            await asyncio.wait_for(writer.drain(), timeout=2.0)
        except Exception:
            pass

        # Try to read — SS won't reply to garbage, but some ISP middleboxes will
        try:
            resp = await asyncio.wait_for(reader.read(64), timeout=2.0)
            verdict = Verdict.OK if resp else Verdict.HANDSHAKE_ONLY
        except asyncio.TimeoutError:
            verdict = Verdict.HANDSHAKE_ONLY  # port open, no response = expected SS behaviour
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=verdict,
            rtt_ms=rtt,
            evidence={"protocol": "shadowsocks", "tcp_connect": "ok"},
        )

    except Exception as e:
        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=Verdict.ERROR,
            evidence={"error": str(e), "protocol": "shadowsocks"},
        )


# ─────────────────────────────────────────────────────────────────────────────
# VLESS + Reality — TLS fingerprint probe
# ─────────────────────────────────────────────────────────────────────────────

async def _test_vless_reality_tls(ip: str, port: int, server_name: str) -> TestResult:
    """
    Attempt TLS connection with Reality SNI to the VLESS port.

    Reality disguises itself as a legitimate HTTPS server (e.g. maps.yandex.ru).
    ТСПУ cannot distinguish Reality traffic from normal HTTPS without the private key.

    If TLS completes → HANDSHAKE_ONLY (Reality works).
    If TLS is RST/refused → BLOCKED.
    """
    test_name = f"protocol_vless_reality_{ip}_{port}"
    target = f"{ip}:{port}/tcp+tls"
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    def _tls_probe() -> tuple[bool, Optional[float], str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        try:
            with socket.create_connection((ip, port), timeout=_TCP_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                    rtt = (time.monotonic() - t0) * 1000
                    # TLS completed — Reality handshake succeeded (server responded as masquerade)
                    alpn = ssock.selected_alpn_protocol()
                    return True, rtt, alpn or ""
        except ssl.SSLError as e:
            rtt = (time.monotonic() - t0) * 1000
            # SSL error but TCP connected = port open, TLS fingerprint may be suspicious
            return True, rtt, f"ssl_error:{e.reason}"
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            return False, None, "connection_failed"

    try:
        hs_ok, rtt, detail = await loop.run_in_executor(None, _tls_probe)
        verdict = Verdict.HANDSHAKE_ONLY if hs_ok else Verdict.BLOCKED
        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=verdict,
            rtt_ms=rtt,
            evidence={
                "protocol": "vless_reality",
                "server_name": server_name,
                "detail": detail,
            },
        )
    except Exception as e:
        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=Verdict.ERROR,
            evidence={"error": str(e), "protocol": "vless_reality"},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Hysteria 2 — QUIC Initial packet probe
# ─────────────────────────────────────────────────────────────────────────────

async def _test_hysteria2_quic(ip: str, port: int, obfs_password: str) -> TestResult:
    """
    Send a minimal QUIC Initial packet with salamander XOR obfuscation.

    Hysteria 2 uses QUIC (UDP) with salamander obfuscation (XOR with BLAKE2b key).
    ТСПУ may block QUIC by:
    - Dropping all UDP on port 443
    - Detecting QUIC Long Header packet structure

    If we get any UDP response → reachable (HANDSHAKE_ONLY).
    If timeout → BLOCKED or QUIC_DROPPED.
    """
    test_name = f"protocol_hysteria2_{ip}_{port}"
    target = f"{ip}:{port}/udp+quic"
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    def _quic_probe() -> tuple[bool, Optional[float]]:
        import hashlib

        # Salamander XOR key from obfs_password (BLAKE2b-256)
        if obfs_password:
            key = hashlib.blake2b(obfs_password.encode(), digest_size=32).digest()
        else:
            key = bytes(32)

        # Minimal QUIC v1 Long Header Initial packet
        dcid = os.urandom(8)
        scid = os.urandom(8)
        raw = (
            b"\xc0"                     # QUIC Long Header, Initial
            + b"\x00\x00\x00\x01"       # QUIC version 1
            + bytes([len(dcid)]) + dcid # DCID
            + bytes([len(scid)]) + scid # SCID
            + b"\x00"                   # token length 0
            + b"\x40\x19"              # packet length (varint 25)
            + b"\x00\x00\x00\x01"      # packet number
            + os.urandom(20)           # payload (random CRYPTO frame data)
        )

        # Apply salamander XOR obfuscation
        if any(key):
            obfuscated = bytes(b ^ key[i % 32] for i, b in enumerate(raw))
        else:
            obfuscated = raw

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_UDP_TIMEOUT)
        try:
            sock.sendto(obfuscated, (ip, port))
            try:
                data, _ = sock.recvfrom(1500)
                rtt = (time.monotonic() - t0) * 1000
                return True, rtt
            except socket.timeout:
                return False, None
        finally:
            sock.close()

    try:
        reachable, rtt = await loop.run_in_executor(None, _quic_probe)
        verdict = Verdict.HANDSHAKE_ONLY if reachable else Verdict.BLOCKED
        method = BlockingMethod.QUIC_DROPPED if not reachable else None
        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=verdict,
            method=method,
            rtt_ms=rtt,
            evidence={"protocol": "hysteria2", "transport": "quic+salamander"},
        )
    except Exception as e:
        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=Verdict.ERROR,
            evidence={"error": str(e), "protocol": "hysteria2"},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Generic UDP probe helper
# ─────────────────────────────────────────────────────────────────────────────

async def _udp_probe(
    test_name: str,
    target: str,
    ip: str,
    port: int,
    payload: bytes,
    protocol_name: str,
    block_method: BlockingMethod,
) -> TestResult:
    """Generic UDP probe: send payload, wait for response."""
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        await loop.sock_sendto(sock, payload, (ip, port))

        try:
            response, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 512),
                timeout=_UDP_TIMEOUT,
            )
            rtt_ms = (time.monotonic() - t0) * 1000
            sock.close()

            return TestResult(
                test=test_name,
                category="protocols",
                target=target,
                verdict=Verdict.OK if response else Verdict.BLOCKED,
                rtt_ms=rtt_ms,
                evidence={
                    "protocol": protocol_name,
                    "payload_bytes": len(payload),
                    "response_bytes": len(response),
                    "response_hex": response[:16].hex(),
                },
            )

        except asyncio.TimeoutError:
            sock.close()
            rtt_ms = (time.monotonic() - t0) * 1000
            return TestResult(
                test=test_name,
                category="protocols",
                target=target,
                verdict=Verdict.BLOCKED,
                method=block_method,
                rtt_ms=rtt_ms,
                evidence={
                    "protocol": protocol_name,
                    "payload_bytes": len(payload),
                    "error": "udp_timeout_no_response",
                },
            )

    except Exception as e:
        return TestResult(
            test=test_name,
            category="protocols",
            target=target,
            verdict=Verdict.ERROR,
            evidence={"error": str(e), "protocol": protocol_name},
        )
