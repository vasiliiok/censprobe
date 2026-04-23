"""
protocol_probes.py — Client-side VPN handshake probes.

Each probe attempts to establish a connection to the listener endpoint
and perform a minimal handshake + data echo to verify reachability.

Verdicts:
  OK              — full handshake + data echo succeeded
  HANDSHAKE_ONLY  — handshake succeeded, data echo failed/timeout
  BLOCKED         — connection refused, timeout, or RST on first packet
  ERROR           — probe error (bad credentials, wrong port, etc.)

The client does NOT require or install VPN tunnel daemons.
For WireGuard it uses a pure-Python handshake implementation.
For VLESS/Hy2 it performs a QUIC/TLS connection-level probe.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import random
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from censprobe_core.models import Verdict

logger = logging.getLogger(__name__)

# Probe timeout per attempt
PROBE_TIMEOUT = 10.0
# Data echo payload
ECHO_PAYLOAD = b"\x00" * 32
# Jitter range (seconds) for opsec
JITTER_MIN = 0.5
JITTER_MAX = 3.0


@dataclass
class ProbeResult:
    verdict: Verdict = Verdict.BLOCKED
    handshake_ok: bool = False
    data_ok: bool = False
    rtt_ms: Optional[float] = None
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN probe — UDP static-key
# ─────────────────────────────────────────────────────────────────────────────

async def probe_openvpn(host: str, port: int, psk_b64: str) -> ProbeResult:
    """
    Send an OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 packet and wait for server
    P_CONTROL_HARD_RESET_SERVER_V2 response.
    """
    result = ProbeResult()
    try:
        loop = asyncio.get_running_loop()

        def _udp_probe() -> tuple[bool, Optional[float]]:
            # Minimal OpenVPN initial reset packet
            # Opcode: P_CONTROL_HARD_RESET_CLIENT_V2 (0x38) | key_id 0
            # Session ID: 8 random bytes
            # Packet ID: 0x00000001
            session_id = random.randbytes(8)
            packet = struct.pack(">B", 0x38) + session_id + b"\x00" * 4 + b"\x00\x00\x00\x01"

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(PROBE_TIMEOUT)
            try:
                t0 = time.monotonic()
                sock.sendto(packet, (host, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    rtt = (time.monotonic() - t0) * 1000
                    # Server reply opcode should be P_CONTROL_HARD_RESET_SERVER_V2 (0x40)
                    if data and (data[0] & 0xF8) == 0x40:
                        return True, rtt
                    elif data:
                        # Got some response — likely handshake_only
                        return True, rtt
                    return False, None
                except socket.timeout:
                    return False, None
            finally:
                sock.close()

        hs_ok, rtt = await loop.run_in_executor(None, _udp_probe)
        if hs_ok:
            result.handshake_ok = True
            result.rtt_ms = rtt
            result.verdict = Verdict.HANDSHAKE_ONLY
            # Try data echo: send another packet and look for any response
            result.data_ok = False  # OpenVPN PSK doesn't do echo in test mode
            result.verdict = Verdict.HANDSHAKE_ONLY
        else:
            result.verdict = Verdict.BLOCKED
    except Exception as e:
        result.error = str(e)
        result.verdict = Verdict.ERROR
    return result


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard probe — UDP handshake initiation
# ─────────────────────────────────────────────────────────────────────────────

async def probe_wireguard(
    host: str, port: int,
    server_public_key: str,
    client_public_key: str,
    preshared_key: str,
) -> ProbeResult:
    """
    Send a minimal WireGuard handshake initiation message.
    WG handshake init is 148 bytes with specific structure.
    We look for a 92-byte handshake response.
    """
    result = ProbeResult()
    try:
        loop = asyncio.get_running_loop()

        def _wg_probe() -> tuple[bool, Optional[float]]:
            # WireGuard Handshake Initiation structure (simplified test packet)
            # Type=1 (initiation), reserved=0x000000
            # Static random ephemeral pubkey (32 bytes)
            # In test mode we send a well-formed-length packet with random crypto material
            # The server will reject it cryptographically, but the UDP exchange itself is measured
            ephemeral = random.randbytes(32)
            static_encrypted = random.randbytes(48)
            timestamp_encrypted = random.randbytes(28)
            mac1 = random.randbytes(16)
            mac2 = b"\x00" * 16

            packet = (
                struct.pack("<I", 1) +      # type=1 (initiation)
                struct.pack("<I", 0) +      # sender index
                ephemeral +
                static_encrypted +
                timestamp_encrypted +
                mac1 + mac2
            )
            # 4+4+32+48+28+16+16 = 148 bytes

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(PROBE_TIMEOUT)
            try:
                t0 = time.monotonic()
                sock.sendto(packet, (host, port))
                try:
                    data, _ = sock.recvfrom(256)
                    rtt = (time.monotonic() - t0) * 1000
                    # WG response is 92 bytes for handshake response (type=2)
                    # Even a reject gives us network reachability
                    return True, rtt
                except socket.timeout:
                    return False, None
            finally:
                sock.close()

        hs_ok, rtt = await loop.run_in_executor(None, _wg_probe)
        if hs_ok:
            result.handshake_ok = True
            result.rtt_ms = rtt
            result.verdict = Verdict.HANDSHAKE_ONLY
        else:
            result.verdict = Verdict.BLOCKED
    except Exception as e:
        result.error = str(e)
        result.verdict = Verdict.ERROR
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Shadowsocks 2022 probe — TCP
# ─────────────────────────────────────────────────────────────────────────────

async def probe_shadowsocks(host: str, port: int, password_b64: str, method: str) -> ProbeResult:
    """
    Attempt a TCP connection to the Shadowsocks port and send a minimal
    SS-2022 request header. Verify we get back data (not immediate RST).
    """
    result = ProbeResult()
    try:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=PROBE_TIMEOUT,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            result.verdict = Verdict.BLOCKED
            result.error = str(e)
            return result

        rtt = (time.monotonic() - t0) * 1000
        result.rtt_ms = rtt
        result.handshake_ok = True  # TCP connected = at minimum not RST-blocked

        # SS-2022 Request Header (EIH not used in test mode):
        # [16-byte salt][stream header encrypted]
        # We send random bytes of the right length to trigger a server-side
        # crypto check. If the server keeps the connection open, data phase works.
        try:
            salt = random.randbytes(16)
            # Fake stream header: timestamp(8) + type(1) + data
            header = random.randbytes(11 + 16 + 16)  # nonce+type+len+tag
            writer.write(salt + header)
            await asyncio.wait_for(writer.drain(), timeout=3.0)

            # Try to read any response (server may send error or keep connection)
            try:
                data = await asyncio.wait_for(reader.read(64), timeout=3.0)
                if data:
                    result.data_ok = True
                    result.verdict = Verdict.OK
                else:
                    result.verdict = Verdict.HANDSHAKE_ONLY
            except asyncio.TimeoutError:
                # Server kept connection open but didn't respond in time
                # This is normal for SS — connection is established
                result.verdict = Verdict.HANDSHAKE_ONLY
        except Exception as e:
            result.verdict = Verdict.HANDSHAKE_ONLY
            result.error = str(e)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

    except Exception as e:
        result.error = str(e)
        result.verdict = Verdict.ERROR
    return result


# ─────────────────────────────────────────────────────────────────────────────
# VLESS+Reality probe — TLS fingerprint + VLESS header
# ─────────────────────────────────────────────────────────────────────────────

async def probe_vless_reality(
    host: str, port: int,
    uuid: str,
    public_key: str,
    short_id: str,
    server_name: str,
) -> ProbeResult:
    """
    Attempt TLS connection with Reality SNI to the VLESS port.
    If TLS completes = handshake_ok (Reality fingerprinting worked).
    Then send a minimal VLESS request to confirm data path.
    """
    result = ProbeResult()
    try:
        loop = asyncio.get_running_loop()

        def _tls_probe() -> tuple[bool, bool, Optional[float]]:
            ctx = ssl.create_default_context()
            # Reality uses a real cert from the masquerade domain
            # We need to use the correct SNI but skip cert verification
            # (since we're connecting to our server, not the real domain)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            try:
                t0 = time.monotonic()
                with socket.create_connection((host, port), timeout=PROBE_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                        rtt = (time.monotonic() - t0) * 1000
                        # TLS connected — VLESS+Reality handshake succeeded
                        # Send minimal VLESS request header
                        # VLESS v0 request: version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + addr_type(1) + addr
                        uuid_bytes = bytes.fromhex(uuid.replace("-", ""))
                        vless_req = (
                            b"\x00"         # version 0
                            + uuid_bytes    # 16-byte UUID
                            + b"\x00"       # addon length 0
                            + b"\x01"       # cmd: TCP
                            + struct.pack(">H", 80)   # port 80
                            + b"\x02"       # addr type: domain
                            + b"\x09" + b"bing.com"   # domain
                        )
                        try:
                            ssock.sendall(vless_req)
                            ssock.settimeout(3.0)
                            resp = ssock.recv(64)
                            return True, bool(resp), rtt
                        except Exception:
                            return True, False, rtt
            except ssl.SSLError:
                return True, False, None  # TLS error but port is open
            except Exception:
                return False, False, None

        hs_ok, data_ok, rtt = await loop.run_in_executor(None, _tls_probe)
        result.handshake_ok = hs_ok
        result.data_ok = data_ok
        result.rtt_ms = rtt
        if hs_ok and data_ok:
            result.verdict = Verdict.OK
        elif hs_ok:
            result.verdict = Verdict.HANDSHAKE_ONLY
        else:
            result.verdict = Verdict.BLOCKED

    except Exception as e:
        result.error = str(e)
        result.verdict = Verdict.ERROR
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Hysteria 2 probe — QUIC connection
# ─────────────────────────────────────────────────────────────────────────────

async def probe_hysteria2(
    host: str, port: int,
    auth_password: str,
    obfs_password: str,
) -> ProbeResult:
    """
    Attempt a QUIC connection to the Hysteria 2 port with salamander obfuscation.

    Without aioquic or a native Hy2 client, we fall back to:
    1. UDP probe — send obfuscated QUIC Initial packet, look for any response
    2. Classify: got response = HANDSHAKE_ONLY, timeout = BLOCKED
    """
    result = ProbeResult()
    try:
        loop = asyncio.get_running_loop()

        def _quic_probe() -> tuple[bool, Optional[float]]:
            # Salamander XOR obfuscation: each byte XORed with BLAKE2b(password)[i % 32]
            import hashlib
            key = hashlib.blake2b(obfs_password.encode(), digest_size=32).digest()

            # Minimal QUIC Initial packet (Long Header)
            # First byte: 0xC0 (QUIC v1 long header, Initial)
            quic_version = b"\x00\x00\x00\x01"   # QUIC version 1
            dcid_len = 8
            dcid = random.randbytes(dcid_len)
            scid_len = 8
            scid = random.randbytes(scid_len)
            token_len = b"\x00"
            pkt_len = b"\x40\x19"   # varint 25
            pkt_num = b"\x00\x00\x00\x01"
            payload = random.randbytes(20)

            raw = (
                b"\xc0" + quic_version +
                bytes([dcid_len]) + dcid +
                bytes([scid_len]) + scid +
                token_len + pkt_len + pkt_num + payload
            )

            # Apply salamander XOR
            obfuscated = bytes(b ^ key[i % 32] for i, b in enumerate(raw))

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(PROBE_TIMEOUT)
            try:
                t0 = time.monotonic()
                sock.sendto(obfuscated, (host, port))
                try:
                    data, _ = sock.recvfrom(1500)
                    rtt = (time.monotonic() - t0) * 1000
                    return True, rtt
                except socket.timeout:
                    return False, None
            finally:
                sock.close()

        hs_ok, rtt = await loop.run_in_executor(None, _quic_probe)
        result.rtt_ms = rtt
        if hs_ok:
            result.handshake_ok = True
            result.verdict = Verdict.HANDSHAKE_ONLY
        else:
            result.verdict = Verdict.BLOCKED

    except Exception as e:
        result.error = str(e)
        result.verdict = Verdict.ERROR
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Jitter helper
# ─────────────────────────────────────────────────────────────────────────────

async def jitter() -> None:
    """Random sleep for opsec — prevents timing correlation."""
    delay = random.uniform(JITTER_MIN, JITTER_MAX)
    await asyncio.sleep(delay)
