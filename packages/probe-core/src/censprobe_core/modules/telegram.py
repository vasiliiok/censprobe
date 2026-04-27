"""
modules/telegram.py — Full Telegram connectivity measurement (Часть 2.5.7).

5 blocks implemented (6 and 7 are placeholders):
  1. DC reachability — 5 DCs × {v4,v6} × {443,80,5222,2001}
     Each DC: TCP connect + MTProto ReqPqMulti init → valid response?
  2. Web — web.telegram.org, k.web.telegram.org, a.web.telegram.org
  3. Auxiliary domains — core, my, translations, t.me, telegram.org, etc.
  4. CDN — cdn1–cdn5.cdn-telegram.org
  5. Voice — UDP to DC IPs on voice ports + STUN binding
  6. Throttling — CDN bandwidth vs baseline (not implemented; throttle_score=1.0)
  7. MTProxy — if configured (not implemented)

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

    # Reconcile BLOCKED results against the baseline: convert BLOCKED→INCONCLUSIVE
    # when the control baseline ALSO shows the endpoint unreachable. This handles:
    #   • port 2001 — unreachable from most networks (not just Russia)
    #   • cdn1/cdn2/cdn3/cdn5 — serve wrong cert or NXDOMAIN from DE
    #   • k.web / a.web — NXDOMAIN outside Russia
    # compare_telegram() returns OK when both solo AND baseline are unreachable
    # (i.e., the situation is consistent — no new blocking).
    reconciled: list[TestResult] = []
    for r in results:
        if r.verdict == Verdict.BLOCKED:
            cmp_verdict = comparator.compare_telegram(r.test, reachable=False, rtt_ms=None)
            if cmp_verdict == Verdict.OK:
                r = r.model_copy(update={
                    "verdict": Verdict.INCONCLUSIVE,
                    "confidence": 0.0,
                    "evidence": {**r.evidence, "reason": "baseline_also_unreachable"},
                    "notes": "Unreachable from control baseline too — not censorship.",
                })
        reconciled.append(r)
    results = reconciled

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

        # TCP connect succeeded → DC port is reachable. This is the primary
        # censorship signal: if ТСПУ blocks Telegram, the SYN is dropped or
        # RST-injected and we never reach this point.
        #
        # Attempt an optional MTProto ReqPqMulti probe (abridged transport).
        # Modern Telegram DCs require obfuscated transport and silently drop
        # bare abridged frames, so a timeout here is NOT evidence of blocking —
        # it is the expected behavior on a clean network. We send it anyway
        # for positive confirmation when a DC does respond (some versions do).
        #
        # struct format: q = signed 64-bit; auth_key_id and message_id are
        # nominally unsigned but fit in signed range for the foreseeable future.
        msg_id = int(time.time() * 2**32)
        # Clamp to signed 64-bit range so struct.pack doesn't blow up if
        # the system clock skews into the post-2038-ish range while still
        # using 'q' (signed) for compatibility with existing servers.
        msg_id &= (1 << 63) - 1
        mtproto = struct.pack("<qqi", 0, msg_id, 4) + b"\xf1\x8e\x7e\xbe"
        assert len(mtproto) == 24 and (len(mtproto) % 4) == 0
        writer.write(b"\xef" + bytes([len(mtproto) // 4]) + mtproto)
        await writer.drain()

        mtproto_response = False
        response: bytes = b""
        try:
            response = await asyncio.wait_for(reader.read(64), timeout=5.0)
            mtproto_response = len(response) > 0
        except asyncio.TimeoutError:
            pass  # expected — DC requires obfuscated transport

        # Report TCP connect RTT, not the total time that includes the 5s
        # MTProto probe wait. rtt_total would always be ≥5000ms (probe timeout)
        # and would show as extremely high latency even for nearby DCs.
        rtt_total_ms = (time.monotonic() - t0) * 1000

        # Verdict is based on TCP reachability, not MTProto response.
        # A DC that accepts TCP but ignores bare MTProto is REACHABLE (OK).
        verdict = Verdict.OK
        return TestResult(
            test=test_name,
            category="telegram",
            target=target,
            verdict=verdict,
            rtt_ms=rtt_connect,  # TCP connect latency, not probe total
            evidence={
                "tcp_connect_ms": round(rtt_connect, 1),
                "mtproto_response": mtproto_response,
                "response_bytes": len(response),
                "probe_total_ms": round(rtt_total_ms, 1),
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
        # "Network is unreachable" / "No route to host" / "Address family not
        # supported" — the probe host has no IPv6 or no path to this network.
        # This is a local capability gap, NOT evidence of censorship; returning
        # BLOCKED here would lower health scores for servers that simply lack
        # IPv6, which is misleading.
        if any(s in err for s in ("network is unreachable", "no route to host",
                                   "address family not supported", "unreachable")):
            return TestResult(
                test=test_name, category="telegram", target=target,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.0,
                evidence={"error": str(e), "reason": "network_unreachable_local"},
                notes="Local probe has no route to this address — not censorship.",
            )
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
            # A valid STUN Binding Response means an intermediate device answered
            # on Telegram's behalf (unlikely but a positive reachability signal).
            # Any other data → the port is reachable but Telegram sent MTProto/UDP
            # back (or junk) — treat as INCONCLUSIVE, NOT ANOMALY, because
            # "got bytes but not a STUN reply" is the expected on-path behaviour.
            if is_stun_response:
                verdict = Verdict.OK
            else:
                verdict = Verdict.INCONCLUSIVE
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
    throttle_score = 1.0  # placeholder — throttling module handles this separately

    # Voice probes use STUN which Telegram DCs silently ignore (they expect
    # MTProto/UDP). All voice results are INCONCLUSIVE by design — they carry
    # no information about blocking. Redistributing the voice weight across
    # the other components avoids a permanent 7.5% cap (0.5 × 0.15) that
    # would otherwise prevent a perfectly healthy server from scoring 100%.
    voice_decisive = [r for r in voice_results if r.verdict != Verdict.INCONCLUSIVE]
    if not voice_decisive:
        # No decisive voice data — fold voice weight into remaining components.
        active_w = w_dc + w_web + w_cdn + w_thr
        if active_w == 0:
            return 1.0
        total_w = active_w + w_voice
        return (
            dc_score * w_dc +
            web_score * w_web +
            cdn_score * w_cdn +
            throttle_score * w_thr
        ) * (total_w / active_w)

    voice_score = _ok_ratio(voice_results)
    return (
        dc_score * w_dc +
        web_score * w_web +
        cdn_score * w_cdn +
        voice_score * w_voice +
        throttle_score * w_thr
    )


def _ok_ratio(results: list[TestResult]) -> float:
    # INCONCLUSIVE results carry no signal — exclude them from both
    # numerator and denominator so they don't drag the ratio toward 0.
    # Voice probes always return INCONCLUSIVE (Telegram ignores STUN),
    # so without this exclusion the voice block would always score 0.0
    # and unjustly subtract 7.5 % from every server's health score.
    decisive = [r for r in results if r.verdict != Verdict.INCONCLUSIVE]
    if not decisive:
        return 0.5  # no decisive data → neutral
    ok = sum(1 for r in decisive if r.verdict == Verdict.OK)
    return ok / len(decisive)


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").lower()


def _ua_tg() -> str:
    return "TelegramBot (censprobe, 0.1)"
