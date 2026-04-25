"""
modules/telegram.py — Full Telegram connectivity measurement (Часть 2.5.7).

7 blocks:
  1. DC reachability — 5 DCs × {v4,v6} × {443,80,5222,2001}
     Each DC: TCP connect + MTProto ReqPqMulti init → valid response?
  2. Web — web.telegram.org, k.web.telegram.org, a.web.telegram.org
  3. Auxiliary domains — core, my, translations, t.me, telegram.org, etc.
  4. CDN — cdn1–cdn5.cdn-telegram.org
  5. Voice — UDP to DC IPs on voice ports + STUN binding
  6. Throttling — CDN bandwidth vs baseline
  7. MTProxy — if configured

Telegram health score = weighted_avg(dc:40%, web:20%, cdn:15%, voice:15%, throttling:10%)
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import struct
import time
from pathlib import Path
from typing import Optional

import httpx
import yaml

from censprobe_core.models import TestResult, Verdict, BlockingMethod
from censprobe_core.baseline import BaselineComparator

logger = logging.getLogger(__name__)

_WORKSPACE = Path("/workspace")
_TIMEOUT = 8.0


def _load_telegram_config() -> dict:
    path = _WORKSPACE / "targets" / "telegram.yaml"
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}


async def run_telegram_tests(
    comparator: BaselineComparator,
    test_voice: bool = True,
) -> list[TestResult]:
    """Run all Telegram test blocks."""
    cfg = _load_telegram_config()
    results: list[TestResult] = []

    # Block 1: DC reachability
    dc_results = await _test_dc_reachability(cfg.get("api_datacenters", []))
    results.extend(dc_results)

    # Block 2: Web
    web_results = await _test_https_domains(cfg.get("web", []), "telegram_web")
    results.extend(web_results)

    # Block 3: Auxiliary
    aux_results = await _test_https_domains(cfg.get("auxiliary", []), "telegram_aux")
    results.extend(aux_results)

    # Block 4: CDN
    cdn_results = await _test_https_domains(cfg.get("cdn", []), "telegram_cdn")
    results.extend(cdn_results)

    # Block 5: Voice (UDP + STUN)
    if test_voice:
        voice_results = await _test_voice(cfg.get("api_datacenters", []))
        results.extend(voice_results)

    # Compute health score. THROTTLED specifically means bandwidth was
    # measured low, NOT "partial reachability" — using it here would
    # mis-attribute the technique. Use ANOMALY for the partially-reachable
    # band.
    health = _compute_health_score(results, cfg.get("health_weights", {}))
    if health >= 0.7:
        health_verdict = Verdict.OK
    elif health >= 0.3:
        health_verdict = Verdict.ANOMALY
    else:
        health_verdict = Verdict.BLOCKED
    results.append(TestResult(
        test="telegram_health_score",
        category="telegram",
        target="telegram",
        verdict=health_verdict,
        evidence={
            "health_score": round(health, 3),
            "health_pct": round(health * 100, 1),
        },
    ))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Block 1: DC reachability
# ─────────────────────────────────────────────────────────────────────────────

async def _test_dc_reachability(dcs: list[dict]) -> list[TestResult]:
    """Test each DC on all IP versions and MTProto ports."""
    results = []
    tasks = []

    for dc in dcs:
        dc_id = dc["id"]
        for ip_ver, ip_key in [("v4", "ipv4"), ("v6", "ipv6")]:
            ip = dc.get(ip_key)
            if not ip:
                continue
            for port in dc.get("ports", [443]):
                tasks.append(
                    _test_dc_port(dc_id, ip_ver, ip, port)
                )

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for r in completed:
        if isinstance(r, TestResult):
            results.append(r)
        elif isinstance(r, Exception):
            logger.debug("DC test error: %s", r)

    return results


async def _test_dc_port(dc_id: int, ip_ver: str, ip: str, port: int) -> TestResult:
    """TCP connect + MTProto ReqPqMulti to one DC endpoint."""
    test_name = f"telegram_dc{dc_id}_{ip_ver}_{port}"
    target = f"{ip}:{port}"

    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=_TIMEOUT,
        )
        rtt_connect = (time.monotonic() - t0) * 1000

        # Send MTProto auth_key_id=0 (unencrypted) ReqPqMulti
        # constructor for req_pq_multi = 0xbe7e8ef1
        # MTProto payload: auth_key_id(8) + message_id(8) + message_len(4)
        # + ctor(4) = 24B. Telegram requires a transport framing header on
        # TCP — a bare MTProto payload is dropped by the DC without reply.
        # Abridged transport: first-byte 0xef (connection header), then
        # per-message length in 4-byte units (24 / 4 = 6).
        # struct format: q = signed 64-bit; auth_key_id and message_id are
        # nominally unsigned but fit in signed range for the foreseeable
        # future, and Telegram doesn't care about sign on the wire.
        msg_id = int(time.time() * 2**32)
        # Clamp to signed 64-bit range so struct.pack doesn't blow up if
        # the system clock skews into the post-2038-ish range while still
        # using 'q' (signed) for compatibility with existing servers.
        msg_id &= (1 << 63) - 1
        mtproto = struct.pack("<qqi", 0, msg_id, 4) + b"\xf1\x8e\x7e\xbe"
        assert len(mtproto) == 24 and (len(mtproto) % 4) == 0
        writer.write(b"\xef" + bytes([len(mtproto) // 4]) + mtproto)
        await writer.drain()

        # Expect response within timeout
        response: bytes = b""
        try:
            response = await asyncio.wait_for(reader.read(64), timeout=5.0)
            rtt_total = (time.monotonic() - t0) * 1000
            has_response = len(response) > 0
        except asyncio.TimeoutError:
            has_response = False
            rtt_total = (time.monotonic() - t0) * 1000

        verdict = Verdict.OK if has_response else Verdict.ANOMALY
        return TestResult(
            test=test_name,
            category="telegram",
            target=target,
            verdict=verdict,
            rtt_ms=rtt_total,
            evidence={
                "tcp_connect_ms": round(rtt_connect, 1),
                "mtproto_response": has_response,
                "response_bytes": len(response),
            },
        )

    except asyncio.TimeoutError:
        return TestResult(
            test=test_name, category="telegram", target=target,
            verdict=Verdict.BLOCKED, method=BlockingMethod.IP_DROPPED,
            evidence={"error": "tcp_timeout"},
        )
    except ConnectionRefusedError:
        return TestResult(
            test=test_name, category="telegram", target=target,
            verdict=Verdict.REFUSED,
            evidence={"error": "connection_refused"},
        )
    except OSError as e:
        err = str(e).lower()
        method = BlockingMethod.TCP_RST_INJECTION if "reset" in err else None
        return TestResult(
            test=test_name, category="telegram", target=target,
            verdict=Verdict.BLOCKED, method=method,
            evidence={"error": str(e)},
        )
    finally:
        # Always close the writer if we opened one, including the path
        # where drain()/read() raised after open_connection succeeded —
        # without this the FD lingers until GC and a hung DC port can
        # exhaust the descriptor table over a long run.
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Blocks 2/3/4: HTTPS domains
# ─────────────────────────────────────────────────────────────────────────────

async def _test_https_domains(domains: list[str], prefix: str) -> list[TestResult]:
    """Test HTTPS connectivity to a list of domains in parallel."""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(_TIMEOUT),
        http2=True,
        follow_redirects=True,
        verify=True,
    ) as client:
        async def _probe(domain: str) -> TestResult:
            url = f"https://{domain}/"
            test_name = f"{prefix}_{_slug(domain)}"
            try:
                t0 = time.monotonic()
                r = await client.get(url, headers={"User-Agent": _ua_tg()})
                rtt = (time.monotonic() - t0) * 1000
                verdict = Verdict.OK if r.status_code < 500 else Verdict.ANOMALY
                return TestResult(
                    test=test_name,
                    category="telegram",
                    target=url,
                    verdict=verdict,
                    rtt_ms=rtt,
                    evidence={"status": r.status_code},
                )
            except httpx.ConnectTimeout:
                return TestResult(
                    test=test_name, category="telegram", target=url,
                    verdict=Verdict.BLOCKED, method=BlockingMethod.IP_DROPPED,
                    evidence={"error": "connect_timeout"},
                )
            except httpx.ConnectError as e:
                # httpx has no SSLError class — SSL failures arrive wrapped in
                # ConnectError; classify by cause / message.
                err_msg = str(e).lower()
                is_tls = (
                    isinstance(getattr(e, "__cause__", None), ssl.SSLError)
                    or "ssl" in err_msg or "certificate" in err_msg
                )
                method = (
                    BlockingMethod.TLS_HANDSHAKE_FAILURE if is_tls
                    else BlockingMethod.IP_DROPPED
                )
                return TestResult(
                    test=test_name, category="telegram", target=url,
                    verdict=Verdict.BLOCKED, method=method,
                    evidence={"error": str(e)},
                )
            except Exception as e:
                return TestResult(
                    test=test_name, category="telegram", target=url,
                    verdict=Verdict.ERROR, evidence={"error": str(e)},
                )

        return list(await asyncio.gather(*[_probe(d) for d in domains]))


# ─────────────────────────────────────────────────────────────────────────────
# Block 5: Voice (UDP + STUN)
# ─────────────────────────────────────────────────────────────────────────────

# Telegram voice ports (approximate — RTP over UDP)
_VOICE_PORTS = [7670, 7680, 9085, 9086]


async def _test_voice(dcs: list[dict]) -> list[TestResult]:
    """
    Test UDP connectivity for Telegram voice calls.
    Sends STUN Binding Request to DC IPs on voice ports.

    Runs probes in parallel — they all use independent UDP sockets and
    each blocks for at most ~3 s on receive, so serializing them just
    multiplies the total wall-clock time without any benefit.
    """
    tasks: list = []
    for dc in dcs[:2]:  # Test first 2 DCs only to avoid too many UDP probes
        dc_id = dc["id"]
        ip = dc.get("ipv4")
        if not ip:
            continue
        for port in _VOICE_PORTS[:2]:  # 2 ports per DC
            tasks.append(_stun_probe(dc_id, ip, port))

    if not tasks:
        return []

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[TestResult] = []
    for r in completed:
        if isinstance(r, TestResult):
            results.append(r)
        elif isinstance(r, Exception):
            logger.debug("Voice probe failed: %s", r)
    return results


async def _stun_probe(dc_id: int, ip: str, port: int) -> TestResult:
    """Send STUN Binding Request and check for response.

    Note: Telegram VoIP uses its own MTProto-over-UDP protocol, not RFC
    5389 STUN. A standard STUN binding request is silently dropped by
    the DC regardless of censorship, so "no reply" is NOT evidence of
    blocking — treat it as INCONCLUSIVE with a marker. A valid STUN
    reply would be an active positive signal (e.g. middlebox answering
    on our behalf); we keep the parser for that case.
    """
    test_name = f"telegram_voice_dc{dc_id}_udp_{port}"
    target = f"{ip}:{port}/udp"

    # STUN Binding Request: type=0x0001, length=0, magic=0x2112A442, txid=random
    import os
    txid = os.urandom(12)
    stun_req = struct.pack(">HHI", 0x0001, 0x0000, 0x2112A442) + txid

    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, stun_req, (ip, port))

        try:
            data, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 512),
                timeout=3.0,
            )
            rtt = (time.monotonic() - t0) * 1000
            # STUN Binding Response type = 0x0101 AND magic cookie must match our txid transaction.
            is_stun_response = (
                len(data) >= 20
                and struct.unpack(">H", data[:2])[0] == 0x0101
                and data[4:8] == b"\x21\x12\xa4\x42"
                and data[8:20] == txid
            )
            verdict = Verdict.OK if is_stun_response else Verdict.ANOMALY
            return TestResult(
                test=test_name, category="telegram", target=target,
                verdict=verdict,
                rtt_ms=rtt,
                evidence={"stun_response": is_stun_response, "bytes_received": len(data)},
            )
        except asyncio.TimeoutError:
            return TestResult(
                test=test_name, category="telegram", target=target,
                verdict=Verdict.INCONCLUSIVE, confidence=0.1,
                evidence={
                    "status": "no_reply_expected",
                    "reason": "Telegram VoIP uses MTProto/UDP, not STUN; "
                              "timeout is not evidence of censorship.",
                },
                notes="STUN probe to Telegram VoIP port is informational only.",
            )

    except Exception as e:
        return TestResult(
            test=test_name, category="telegram", target=target,
            verdict=Verdict.ERROR, evidence={"error": str(e)},
        )
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Health score computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_health_score(results: list[TestResult], weights: dict) -> float:
    """
    Compute overall Telegram health score [0.0, 1.0].
    weights from telegram.yaml health_weights section.
    """
    w_dc  = weights.get("dc_reachability", 0.40)
    w_web = weights.get("web_access", 0.20)
    w_cdn = weights.get("cdn_access", 0.15)
    w_voice = weights.get("voice_health", 0.15)
    w_thr = weights.get("throttling_absence", 0.10)

    dc_results   = [r for r in results if r.test.startswith("telegram_dc") and "health" not in r.test]
    web_results  = [r for r in results if r.test.startswith("telegram_web")]
    cdn_results  = [r for r in results if r.test.startswith("telegram_cdn")]
    voice_results = [r for r in results if r.test.startswith("telegram_voice")]

    dc_score  = _ok_ratio(dc_results)
    web_score = _ok_ratio(web_results)
    cdn_score = _ok_ratio(cdn_results)
    voice_score = _ok_ratio(voice_results)
    throttle_score = 1.0  # placeholder — throttling module handles this separately

    return (
        dc_score * w_dc +
        web_score * w_web +
        cdn_score * w_cdn +
        voice_score * w_voice +
        throttle_score * w_thr
    )


def _ok_ratio(results: list[TestResult]) -> float:
    if not results:
        return 0.5  # no data → neutral
    ok = sum(1 for r in results if r.verdict in (Verdict.OK,))
    return ok / len(results)


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").lower()


def _ua_tg() -> str:
    return "TelegramBot (censprobe, 0.1)"
