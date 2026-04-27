"""
modules/cloudflare.py — Cloudflare infrastructure censorship probes.

Category: "cloudflare"

Tests (in order):
  cloudflare_quic_*       — UDP 443 QUIC reachability
                            Russia's TSPU drops UDP 443 since ~2022, breaking HTTP3
                            and all QUIC-based protocols on Cloudflare.
  cloudflare_warp_api     — HTTPS to engage.cloudflareclient.com (WARP registration).
                            If blocked → Cloudflare WARP cannot be set up.
  cloudflare_warp_*_tcp   — TCP 443 to Cloudflare WARP anycast IPs.
                            Confirms IP-level reachability independent of hostname.
  cloudflare_http_*       — HTTPS to workers.dev, pages.dev, cloudflare-dns.com.
                            Platform-level blocking canaries.

Blocked vs INCONCLUSIVE for QUIC:
  Cloudflare's QUIC stack responds to a valid Version Negotiation trigger with a
  Version Negotiation packet (RFC 9000 §6.2).  We send a minimal QUIC Long Header
  packet with an unrecognised (GREASE) version and wait up to 3 s:
    response received → OK   (UDP 443 passes TSPU)
    timeout          → QUIC_DROPPED  (UDP 443 silently dropped by TSPU)
    ICMP unreachable → INCONCLUSIVE  (source/routing issue, not TSPU)
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from pathlib import Path
from typing import Optional

import httpx
import yaml

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_WORKSPACE = Path("/workspace")
_CONNECT_TIMEOUT = 10.0
_QUIC_TIMEOUT    = 3.0   # seconds to wait for QUIC VN response


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run_cloudflare_tests() -> list[TestResult]:
    """Run all Cloudflare infrastructure probes."""
    cfg = _load_config()
    results: list[TestResult] = []

    tasks: list[asyncio.Task] = []

    # QUIC probes (parallel)
    for qt in cfg.get("quic_targets", []):
        tasks.append(asyncio.create_task(
            _test_quic(qt["host"], qt["port"], qt["name"])
        ))

    # WARP TCP probes (parallel)
    for wt in cfg.get("warp_targets", []):
        tasks.append(asyncio.create_task(
            _test_warp_tcp(wt["host"], wt["port_tcp"], wt["name"])
        ))

    # HTTP probes (parallel)
    for ht in cfg.get("http_targets", []):
        for url in ht.get("urls", []):
            tasks.append(asyncio.create_task(
                _test_http(ht["domain"], url, ht.get("expected_status", 200))
            ))

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for r in completed:
        if isinstance(r, TestResult):
            results.append(r)
        elif isinstance(r, Exception):
            logger.debug("cloudflare probe error: %s", r)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# QUIC / UDP 443
# ─────────────────────────────────────────────────────────────────────────────

def _build_quic_vn_trigger() -> bytes:
    """
    Build a minimal QUIC Long Header packet with a GREASE (unknown) version.

    Per RFC 9000 §6.2, a QUIC v1 server MUST respond to a packet with an
    unknown version with a Version Negotiation packet — provided it can parse
    the DCID/SCID lengths.  A response proves UDP 443 is not dropped by TSPU.

    Format (all big-endian):
      1B  : 0xC0  Long Header + Fixed Bit
      4B  : GREASE version 0x0a0a0a0a
      1B  : DCID length (8)
      8B  : random DCID
      1B  : SCID length (4)
      4B  : random SCID
      1B  : Token Length = 0
      2B  : Length varint = 0x4001 (2-byte form, value=1)
      1B  : Packet Number = 0
      1B  : Payload = 0x00
    Total: 21 bytes
    """
    dcid = os.urandom(8)
    scid = os.urandom(4)
    return (
        b'\xc0'                     # Long Header + Fixed Bit
        b'\x0a\x0a\x0a\x0a'        # GREASE version
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
        + b'\x00'                   # Token Length = 0
        + b'\x40\x01'              # Length (varint 2-byte form) = 1
        + b'\x00'                   # Packet Number
        + b'\x00'                   # 1-byte payload
    )


async def _test_quic(host: str, port: int, name: str) -> TestResult:
    """
    Send a QUIC VN trigger to host:port/UDP and wait for any server response.

    Verdict:
      OK           — got a datagram back (UDP 443 is not blocked by TSPU)
      QUIC_DROPPED — timeout (TSPU likely dropping UDP 443 packets)
      INCONCLUSIVE — socket/routing error not attributable to TSPU
    """
    probe = _build_quic_vn_trigger()
    received_data: Optional[bytes] = None

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self):
            self.fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

        def connection_made(self, transport):
            transport.sendto(probe)

        def datagram_received(self, data: bytes, addr):
            if not self.fut.done():
                self.fut.set_result(data)

        def error_received(self, exc: Exception):
            if not self.fut.done():
                self.fut.set_exception(exc)

        def connection_lost(self, exc):
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
            and received_data[1:5] == b'\x00\x00\x00\x00'
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

    except asyncio.TimeoutError:
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"udp://{host}:{port}",
            verdict=Verdict.IP_DROPPED,
            method=BlockingMethod.QUIC_DROPPED,
            evidence={
                "error": "udp_timeout",
                "timeout_sec": _QUIC_TIMEOUT,
            },
            notes="No QUIC VN response — UDP 443 blocked or filtered (HTTP3/QUIC unusable from this server)",
            confidence=0.75,
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
        rtt_ms = (time.monotonic() - t0) * 1000
        return TestResult(
            test=name,
            category="cloudflare",
            target=f"tcp://{host}:{port}",
            verdict=Verdict.OK,
            rtt_ms=rtt_ms,
            evidence={"tcp_connect_ms": round(rtt_ms, 1)},
        )
    except asyncio.TimeoutError:
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
            verdict=Verdict.REFUSED,
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
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# HTTP/HTTPS platform tests
# ─────────────────────────────────────────────────────────────────────────────

def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").replace("/", "_")


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

        if r.status_code in (403, 451):
            return TestResult(
                test=test_name,
                category="cloudflare",
                target=url,
                verdict=Verdict.GEOBLOCK_NOT_CENSORSHIP,
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
            test=test_name, category="cloudflare", target=url,
            verdict=Verdict.BLOCKED, method=BlockingMethod.IP_DROPPED,
            evidence={"error": "connect_timeout"},
        )
    except httpx.ConnectError as e:
        err = str(e).lower()
        method = (
            BlockingMethod.TLS_HANDSHAKE_FAILURE
            if ("ssl" in err or "certificate" in err)
            else BlockingMethod.IP_DROPPED
        )
        return TestResult(
            test=test_name, category="cloudflare", target=url,
            verdict=Verdict.BLOCKED, method=method,
            evidence={"error": str(e)},
        )
    except Exception as e:
        return TestResult(
            test=test_name, category="cloudflare", target=url,
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": str(e)},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Config loader
# ─────────────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    path = _WORKSPACE / "targets" / "cloudflare.yaml"
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception as e:
        logger.warning("Could not load targets/cloudflare.yaml: %s", e)
        return {}
