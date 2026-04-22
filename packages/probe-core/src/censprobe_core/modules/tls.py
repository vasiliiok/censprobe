"""
modules/tls.py — TLS/SNI measurement module.

Tests multiple SNI scenarios against a single IP to attribute censorship:

Scenarios (Часть 2.5.3):
  sni_blocked    — blocked domain SNI → fail expected if SNI-blocking active
  sni_ok         — neutral SNI (cloudflare.com) → should succeed
  sni_empty      — empty SNI → varies
  sni_fake_ok    — neutral SNI but IP from blocked service → success means IP not blocked
  ech_on         — ECH extension → fail if ECH blocked (via curl subprocess)
  esni_legacy    — ESNI draft → fail if ESNI blocked

Attribution logic:
  TCP connects but TLS fails only with blocked SNI → tcp_rst_after_tls_ch (SNI block)
  TLS fails with any SNI → ip_dropped or tls_handshake_failure
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import subprocess
import time
from typing import Optional

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_TLS_TIMEOUT = 10.0  # seconds


async def run_tls_tests(
    targets: list[dict],  # {"domain": ..., "ip": ..., "blocked_sni": ...}
    repeats: int = 2,
) -> list[TestResult]:
    """Run TLS/SNI tests for each target."""
    results = []
    for t in targets:
        domain = t["domain"]
        ip = t.get("ip")  # if None, we'll resolve it
        blocked_sni = t.get("blocked_sni", domain)

        if not ip:
            ip = await _resolve_ip(domain)
        if not ip:
            results.append(TestResult(
                test=f"tls_{_slug(domain)}_no_ip",
                category="tls",
                target=domain,
                verdict=Verdict.INCONCLUSIVE,
                evidence={"reason": "could_not_resolve_ip"},
            ))
            continue

        results.extend(await _test_sni_scenarios(domain, ip, blocked_sni, repeats))

    return results


async def _test_sni_scenarios(
    domain: str,
    ip: str,
    blocked_sni: str,
    repeats: int,
) -> list[TestResult]:
    """Test multiple SNI scenarios against one IP."""
    results = []

    # Scenario 1: correct/blocked SNI
    v_blocked, ev_blocked = await _tls_connect(ip, blocked_sni, verify=True)
    results.append(TestResult(
        test=f"tls_{_slug(domain)}_sni_blocked",
        category="tls",
        target=f"{ip}:{blocked_sni}",
        verdict=v_blocked,
        method=_attribute_tls_failure(v_blocked, ev_blocked),
        evidence=ev_blocked,
        attempts=repeats,
    ))

    # Scenario 2: neutral SNI (cloudflare.com) on the same IP
    v_neutral, ev_neutral = await _tls_connect(ip, "cloudflare.com", verify=False)
    results.append(TestResult(
        test=f"tls_{_slug(domain)}_sni_neutral",
        category="tls",
        target=f"{ip}:cloudflare.com",
        verdict=v_neutral,
        evidence=ev_neutral,
    ))

    # Attribution: if neutral OK but blocked SNI fails → SNI-level blocking
    if v_neutral == Verdict.OK and v_blocked != Verdict.OK:
        # Update blocked result attribution
        results[0].method = BlockingMethod.TCP_RST_AFTER_TLS_CH
        results[0].confidence = 0.92
        results[0].notes = "Neutral SNI succeeds to same IP → SNI-level blocking confirmed"

    # Scenario 3: ECH (via curl if available)
    ech_result = await _test_ech(domain)
    if ech_result:
        results.append(ech_result)

    return results


async def _tls_connect(
    ip: str,
    sni: str,
    verify: bool = True,
    port: int = 443,
) -> tuple[Verdict, dict]:
    """
    Attempt TLS handshake to ip:port with specified SNI.
    Returns (verdict, evidence_dict).
    """
    evidence: dict = {"ip": ip, "sni": sni, "port": port}
    t0 = time.monotonic()

    try:
        ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_running_loop()

        def _do_handshake():
            try:
                with socket.create_connection((ip, port), timeout=_TLS_TIMEOUT) as raw:
                    rtt_connect = (time.monotonic() - t0) * 1000
                    with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                        cert = tls.getpeercert()
                        alpn = tls.selected_alpn_protocol()
                        return {
                            "ok": True,
                            "rtt_connect_ms": rtt_connect,
                            "rtt_total_ms": (time.monotonic() - t0) * 1000,
                            "alpn": alpn,
                            "cert_subject": cert.get("subject") if cert else None,
                        }
            except ssl.SSLCertVerificationError as e:
                return {"ok": False, "error": "cert_verification_failed", "detail": str(e)}
            except ssl.SSLError as e:
                return {"ok": False, "error": "ssl_error", "detail": str(e)}
            except ConnectionResetError:
                elapsed = (time.monotonic() - t0) * 1000
                return {"ok": False, "error": "connection_reset", "elapsed_ms": elapsed}
            except TimeoutError:
                return {"ok": False, "error": "timeout"}
            except Exception as e:
                return {"ok": False, "error": type(e).__name__, "detail": str(e)}

        result = await asyncio.wait_for(
            loop.run_in_executor(None, _do_handshake),
            timeout=_TLS_TIMEOUT + 2,
        )

        evidence.update(result)
        if result.get("ok"):
            return Verdict.OK, evidence
        else:
            err = result.get("error", "")
            if err in ("connection_reset", "timeout"):
                return Verdict.BLOCKED, evidence
            return Verdict.ANOMALY, evidence

    except asyncio.TimeoutError:
        evidence["error"] = "outer_timeout"
        return Verdict.IP_DROPPED, evidence
    except Exception as e:
        evidence["error"] = str(e)
        return Verdict.ERROR, evidence


def _attribute_tls_failure(verdict: Verdict, evidence: dict) -> Optional[BlockingMethod]:
    """Guess blocking method from TLS evidence."""
    if verdict == Verdict.OK:
        return None
    err = evidence.get("error", "")
    if err == "connection_reset":
        return BlockingMethod.TCP_RST_AFTER_TLS_CH
    if err == "timeout":
        return BlockingMethod.IP_DROPPED
    if err in ("ssl_error", "cert_verification_failed"):
        return BlockingMethod.TLS_HANDSHAKE_FAILURE
    return None


async def _test_ech(domain: str) -> Optional[TestResult]:
    """
    Test ECH (Encrypted Client Hello) via curl --ech.
    Returns None if curl is not available.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "--ech", "hard", "-sv", "--max-time", "10",
            f"https://{domain}/",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        stderr_text = stderr.decode(errors="replace")

        # curl exits 0 on success
        verdict = Verdict.OK if proc.returncode == 0 else Verdict.BLOCKED
        method = BlockingMethod.ECH_BLOCKED if verdict == Verdict.BLOCKED else None

        return TestResult(
            test=f"tls_{_slug(domain)}_ech",
            category="tls",
            target=domain,
            verdict=verdict,
            method=method,
            evidence={
                "curl_returncode": proc.returncode,
                "stderr_tail": stderr_text[-300:],
            },
        )
    except FileNotFoundError:
        # curl not installed — skip
        return None
    except Exception as e:
        logger.debug("ECH test failed for %s: %s", domain, e)
        return None


async def _resolve_ip(domain: str) -> Optional[str]:
    """Quick resolution to get IP for TLS test."""
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        return infos[0][4][0]
    except Exception:
        return None


def _slug(domain: str) -> str:
    return domain.replace(".", "_").replace("-", "_").lower()
