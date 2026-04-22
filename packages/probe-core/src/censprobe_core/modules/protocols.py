"""
modules/protocols.py — VPN protocol signature tests from the probe side.

Solo sends raw handshake packets to a control-point (listener) and checks
whether they arrive and get a valid response.

For M1 (solo-only), these tests target a placeholder/no-op endpoint.
The real tests run when listener is deployed (M5).

Tests:
  - OpenVPN: P_CONTROL_HARD_RESET_CLIENT_V2 UDP packet
  - WireGuard: handshake initiation (type=0x01, 148 bytes)
  - Note: Shadowsocks/VLESS+Reality/Hysteria2 require actual server — deferred to M5/M6
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import socket
import struct
import time
from typing import Optional

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_UDP_TIMEOUT = 5.0


async def run_protocol_tests(
    control_endpoints: list[dict] | None = None,
) -> list[TestResult]:
    """
    Run VPN protocol signature tests.

    In M1 (solo without listener), these tests are skipped or return INCONCLUSIVE
    because there's no listener to respond to them.

    control_endpoints: list of {"protocol": "openvpn", "ip": "...", "port": 1194}
    """
    if not control_endpoints:
        # No listener configured — return informational results
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
        ip = ep.get("ip")
        port = ep.get("port")
        if not ip or not port:
            continue

        if protocol == "openvpn":
            r = await _test_openvpn_handshake(ip, port)
        elif protocol == "wireguard":
            r = await _test_wireguard_handshake(ip, port)
        else:
            r = TestResult(
                test=f"protocol_{protocol}",
                category="protocols",
                target=f"{ip}:{port}",
                verdict=Verdict.INCONCLUSIVE,
                evidence={"reason": f"Protocol {protocol} not yet implemented in probe"},
            )
        results.append(r)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN
# ─────────────────────────────────────────────────────────────────────────────

async def _test_openvpn_handshake(ip: str, port: int) -> TestResult:
    """
    Send OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 packet (opcode 0x38) via UDP.
    Expect P_CONTROL_HARD_RESET_SERVER_V2 (opcode 0x40) response.

    Packet format (simplified):
      byte 0: opcode<<3 | key_id  → 0x38 = P_CONTROL_HARD_RESET_CLIENT_V2
      bytes 1-8: session ID (random)
      bytes 9-12: ack array length (0)
      bytes 13-16: packet ID (1)
    """
    test_name = f"protocol_openvpn_{ip}_{port}"
    target = f"{ip}:{port}/udp"

    session_id = os.urandom(8)
    packet_id = struct.pack(">I", 1)
    opcode_keyid = bytes([0x38])  # P_CONTROL_HARD_RESET_CLIENT_V2, key_id=0
    ack_len = bytes([0])          # no acks
    packet = opcode_keyid + session_id + ack_len + packet_id

    return await _udp_probe(
        test_name=test_name,
        target=target,
        ip=ip,
        port=port,
        payload=packet,
        expected_opcode=0x40,  # P_CONTROL_HARD_RESET_SERVER_V2
        protocol_name="openvpn",
        block_method=BlockingMethod.OPENVPN_SIGNATURE_BLOCKED,
    )


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard
# ─────────────────────────────────────────────────────────────────────────────

async def _test_wireguard_handshake(ip: str, port: int) -> TestResult:
    """
    Send WireGuard Handshake Initiation (type=0x01, 148 bytes) via UDP.
    A real listener responds with type=0x02 (Handshake Response).
    No response = WireGuard signature blocked by ТСПУ.

    Note: This sends a syntactically valid but cryptographically random packet.
    A real WireGuard server would reject it after decryption, but ТСПУ may
    drop it before it reaches the server — that's what we're measuring.
    """
    test_name = f"protocol_wireguard_{ip}_{port}"
    target = f"{ip}:{port}/udp"

    # WireGuard Initiation: type(4) + reserved(4) + ephemeral(32) + static_enc(48) + timestamp(28) + mac1(16) + mac2(16) = 148 bytes
    # All random except type field
    wg_type = struct.pack("<I", 1)  # type = 1 (handshake initiation)
    wg_reserved = bytes(4)           # reserved = 0
    wg_body = os.urandom(140)        # rest is random (not cryptographically valid)
    packet = wg_type + wg_reserved + wg_body  # total: 148 bytes

    return await _udp_probe(
        test_name=test_name,
        target=target,
        ip=ip,
        port=port,
        payload=packet,
        expected_opcode=None,   # WG response type = 0x02 in little-endian
        protocol_name="wireguard",
        block_method=BlockingMethod.WIREGUARD_SIGNATURE_BLOCKED,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Generic UDP probe
# ─────────────────────────────────────────────────────────────────────────────

async def _udp_probe(
    test_name: str,
    target: str,
    ip: str,
    port: int,
    payload: bytes,
    expected_opcode: Optional[int],
    protocol_name: str,
    block_method: BlockingMethod,
) -> TestResult:
    """Generic UDP probe: send payload, wait for response."""
    loop = asyncio.get_event_loop()
    t0 = time.monotonic()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(_UDP_TIMEOUT)

        await loop.sock_sendto(sock, payload, (ip, port))

        try:
            response, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 512),
                timeout=_UDP_TIMEOUT,
            )
            rtt_ms = (time.monotonic() - t0) * 1000
            sock.close()

            has_response = len(response) > 0
            return TestResult(
                test=test_name,
                category="protocols",
                target=target,
                verdict=Verdict.OK if has_response else Verdict.BLOCKED,
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
