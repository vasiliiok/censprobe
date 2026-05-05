"""
modules/telegram.py — Telegram connectivity measurement (Часть 2.5.7).

Blocks:
  1. DC reachability — 5 DCs × {v4,v6} × {443,80,5222}
     Each DC: TCP connect + MTProto ReqPqMulti init → valid response?
     v6 endpoints are skipped on probe hosts without IPv6; a single
     ``telegram_ipv6_skipped`` result is emitted so the dashboard can
     surface the skip instead of silently dropping ~25 v6 probes.
  2. Web — web.telegram.org, webk.telegram.org, weba.telegram.org
  3. Auxiliary domains — core, my, translations, t.me, telegram.org, etc.
  4. CDN — cdn.telegram.org + cdn1/cdn4/cdn5.cdn-telegram.org

Reconcile of broken Telegram endpoints (cdn1/cdn5 serve *.t.me cert →
fail hostname check) is decided inline via cert-pattern validation: if
the presented cert chains to a system-trusted CA AND its SAN/CN matches
``owned_cert_patterns`` from telegram.yaml, the failure is reclassified
BLOCKED → INCONCLUSIVE (authentic-but-misrouted Telegram cert, not a
censor MITM). TSPU cannot forge a valid Let's Encrypt / Sectigo
signature for *.t.me, so this check is robust against in-path actors.

Telegram health score = weighted_avg(dc:55%, web:25%, cdn:20%).
Voice (STUN/UDP) and throttling weights were removed: STUN to Telegram VoIP
ports never produces a positive signal (Telegram uses MTProto/UDP, not RFC
5389 STUN), and Method-A throttling was retired in favour of within-run
relative SNI throttling (Method B in modules/throttling.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
import ssl
import struct
import time
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from censprobe_core.models import BlockingMethod, TestResult, Verdict

logger = logging.getLogger(__name__)

_TIMEOUT = 8.0


async def run_telegram_tests(cfg: dict[str, Any] | None = None) -> list[TestResult]:
    """Run all Telegram test blocks.

    ``cfg`` is the parsed contents of ``targets/telegram.yaml``; the runner
    pre-loads it and passes it in so this module stays free of any
    workspace/path knowledge. ``None`` is treated as an empty config — all
    DC/web/CDN blocks then degrade to no-op rather than crashing, and the
    dashboard surfaces the missing data as zero results.
    """
    cfg = cfg or {}
    results: list[TestResult] = []

    owned_patterns = _compile_owned_patterns(cfg.get("owned_cert_patterns", []))

    # Probe-host IPv6 capability: gates the DC v6 ladder. We do this once
    # per run rather than catching EAFNOSUPPORT N times inside _test_dc_port,
    # so the dashboard sees a single explicit "v6 skipped" marker instead of
    # ~25 indistinguishable INCONCLUSIVE entries that hide the real reason.
    ipv6_available = await _host_has_ipv6()
    if not ipv6_available:
        logger.info(
            "[telegram] Probe host has no IPv6 — skipping all DC v6 endpoints. "
            "Emitting telegram_ipv6_skipped marker for dashboard visibility."
        )
        results.append(
            TestResult(
                test="telegram_ipv6_skipped",
                category="telegram",
                target="ipv6",
                verdict=Verdict.INCONCLUSIVE,
                evidence={
                    "reason": "host_has_no_ipv6",
                    "skipped_endpoints": _count_v6_endpoints(cfg.get("api_datacenters", [])),
                },
                notes="IPv6 unavailable on probe host — DC v6 endpoints not tested.",
                confidence=0.0,
            )
        )

    # Block 1: DC reachability
    dc_results = await _test_dc_reachability(
        cfg.get("api_datacenters", []),
        skip_ipv6=not ipv6_available,
    )
    results.extend(dc_results)

    # Block 2: Web
    web_results = await _test_https_domains(cfg.get("web", []), "telegram_web", owned_patterns)
    results.extend(web_results)

    # Block 3: Auxiliary
    aux_results = await _test_https_domains(
        cfg.get("auxiliary", []), "telegram_aux", owned_patterns
    )
    results.extend(aux_results)

    # Block 4: CDN
    cdn_results = await _test_https_domains(cfg.get("cdn", []), "telegram_cdn", owned_patterns)
    results.extend(cdn_results)

    # Compute health score. ANOMALY (not BLOCKED) covers the
    # partially-reachable band so a single dead CDN doesn't tip the whole
    # server into "blocked".
    health = _compute_health_score(results, cfg.get("health_weights", {}))
    if health >= 0.7:
        health_verdict = Verdict.OK
    elif health >= 0.3:
        health_verdict = Verdict.ANOMALY
    else:
        health_verdict = Verdict.BLOCKED
    results.append(
        TestResult(
            test="telegram_health_score",
            category="telegram",
            target="telegram",
            verdict=health_verdict,
            evidence={
                "health_score": round(health, 3),
                "health_pct": round(health * 100, 1),
            },
        )
    )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Block 1: DC reachability
# ─────────────────────────────────────────────────────────────────────────────


def _enumerate_dc_endpoints(
    dcs: list[dict[str, Any]],
    skip_ipv6: bool,
) -> list[tuple[int, str, str, int]]:
    """Flatten (dc_id, ip_ver, ip, port) tuples for every reachable DC endpoint."""
    out: list[tuple[int, str, str, int]] = []
    for dc in dcs:
        dc_id = dc["id"]
        for ip_ver, ip_key in (("v4", "ipv4"), ("v6", "ipv6")):
            if ip_ver == "v6" and skip_ipv6:
                continue
            ip = dc.get(ip_key)
            if not ip:
                continue
            for port in dc.get("ports", [443]):
                out.append((dc_id, ip_ver, ip, port))
    return out


async def _test_dc_reachability(
    dcs: list[dict[str, Any]],
    skip_ipv6: bool = False,
) -> list[TestResult]:
    """Test each DC on all IP versions and MTProto ports.

    skip_ipv6: when the probe host has no IPv6, omit v6 endpoints entirely
    instead of emitting INCONCLUSIVE per (DC × port). The summary marker is
    emitted by the caller (run_telegram_tests).
    """
    endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6)
    tasks = [_test_dc_port(*e) for e in endpoints]
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    results: list[TestResult] = []
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
        except TimeoutError:
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

    except TimeoutError:
        return TestResult(
            test=test_name,
            category="telegram",
            target=target,
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.IP_DROPPED,
            evidence={"error": "tcp_timeout"},
        )
    except ConnectionRefusedError:
        return TestResult(
            test=test_name,
            category="telegram",
            target=target,
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
        if any(
            s in err
            for s in (
                "network is unreachable",
                "no route to host",
                "address family not supported",
                "unreachable",
            )
        ):
            return TestResult(
                test=test_name,
                category="telegram",
                target=target,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.0,
                evidence={"error": str(e), "reason": "network_unreachable_local"},
                notes="Local probe has no route to this address — not censorship.",
            )
        method = BlockingMethod.TCP_RST_INJECTION if "reset" in err else None
        return TestResult(
            test=test_name,
            category="telegram",
            target=target,
            verdict=Verdict.BLOCKED,
            method=method,
            evidence={"error": str(e)},
        )
    finally:
        # Always close the writer if we opened one, including the path
        # where drain()/read() raised after open_connection succeeded —
        # without this the FD lingers until GC and a hung DC port can
        # exhaust the descriptor table over a long run.
        if writer is not None:
            # Peer may have already torn down the connection on the
            # MTProto error path — close races are expected.
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()


# ─────────────────────────────────────────────────────────────────────────────
# Blocks 2/3/4: HTTPS domains
# ─────────────────────────────────────────────────────────────────────────────


async def _test_https_domains(
    domains: list[str],
    prefix: str,
    owned_patterns: list[re.Pattern[str]],
) -> list[TestResult]:
    """Test HTTPS connectivity to a list of domains in parallel.

    On a TLS failure we re-handshake without verification and check the
    presented cert against ``owned_patterns``: a system-trusted cert with
    a SAN/CN matching the Telegram-owned family means the endpoint is
    authentically Telegram (just misrouted) rather than a censor MITM,
    so the verdict is reclassified BLOCKED → INCONCLUSIVE.
    """
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
                    test=test_name,
                    category="telegram",
                    target=url,
                    verdict=Verdict.BLOCKED,
                    method=BlockingMethod.IP_DROPPED,
                    evidence={"error": "connect_timeout"},
                )
            except httpx.ConnectError as e:
                # httpx has no SSLError class — SSL failures arrive wrapped in
                # ConnectError; classify by cause / message.
                err_msg = str(e).lower()
                is_tls = (
                    isinstance(getattr(e, "__cause__", None), ssl.SSLError)
                    or "ssl" in err_msg
                    or "certificate" in err_msg
                )
                if is_tls:
                    return await _classify_tls_failure(
                        test_name,
                        url,
                        domain,
                        owned_patterns,
                        err_msg=str(e),
                    )
                return TestResult(
                    test=test_name,
                    category="telegram",
                    target=url,
                    verdict=Verdict.BLOCKED,
                    method=BlockingMethod.IP_DROPPED,
                    evidence={"error": str(e)},
                )
            except Exception as e:
                return TestResult(
                    test=test_name,
                    category="telegram",
                    target=url,
                    verdict=Verdict.ERROR,
                    evidence={"error": str(e)},
                )

        return list(await asyncio.gather(*[_probe(d) for d in domains]))


async def _classify_tls_failure(
    test_name: str,
    url: str,
    domain: str,
    owned_patterns: list[re.Pattern[str]],
    err_msg: str,
) -> TestResult:
    """On TLS failure, distinguish authentic-but-misrouted Telegram cert
    from a censor MITM.

    Procedure:
      1. Re-handshake to the resolved IP with verify=False to capture the
         server's cert.
      2. Validate the chain through the system trust store independently
         of hostname (so a wrong-host cert from a real CA still passes
         this step).
      3. Compare cert SAN/CN against the ``*.telegram.org`` family.

    Pass step 2 + 3 → INCONCLUSIVE (Telegram serving wrong cert, not a
    censor: TSPU cannot mint a chain to a public CA for *.t.me).
    Otherwise BLOCKED tls_handshake_failure.
    """
    blocked_result = TestResult(
        test=test_name,
        category="telegram",
        target=url,
        verdict=Verdict.BLOCKED,
        method=BlockingMethod.TLS_HANDSHAKE_FAILURE,
        evidence={"error": err_msg},
    )

    cert_der, chain_valid = await _capture_cert(domain)
    if cert_der is None:
        return blocked_result

    matched_name = _match_owned_cert(cert_der, owned_patterns)
    if chain_valid and matched_name is not None:
        return TestResult(
            test=test_name,
            category="telegram",
            target=url,
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.0,
            evidence={
                "error": err_msg,
                "reason": "wrong_cert_owned_family",
                "cert_san_match": matched_name,
            },
            notes=(
                "TLS hostname check failed but cert is system-trusted and "
                "belongs to the Telegram-owned domain family — authentic "
                "but misrouted endpoint, not censorship."
            ),
        )

    return blocked_result


# ─────────────────────────────────────────────────────────────────────────────
# IPv6 capability check
# ─────────────────────────────────────────────────────────────────────────────


async def _host_has_ipv6() -> bool:
    """Quick check: can this host establish an IPv6 TCP connection?

    Mirrors server_meta._check_ipv6 but kept module-local to avoid coupling
    the telegram module to detect_server_meta. Used to decide whether to
    skip the DC v6 ladder entirely.
    """
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        loop = asyncio.get_running_loop()
        sock.settimeout(3.0)
        await loop.run_in_executor(
            None,
            lambda: sock.connect(("2606:4700:4700::1111", 80)),
        )
        return True
    except Exception:
        return False
    finally:
        sock.close()


def _count_v6_endpoints(dcs: list[dict[str, Any]]) -> int:
    """How many (DC, port) v6 endpoints are skipped when IPv6 is unavailable?

    Used as evidence on the telegram_ipv6_skipped marker so dashboards can
    show "N v6 probes skipped on this host" rather than guessing.
    """
    n = 0
    for dc in dcs:
        if dc.get("ipv6"):
            n += len(dc.get("ports", [443]))
    return n


# ─────────────────────────────────────────────────────────────────────────────
# Cert-pattern reconcile (replaces the old baseline-comparator approach)
# ─────────────────────────────────────────────────────────────────────────────


def _compile_owned_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile glob-style patterns from telegram.yaml into anchored regexes.

    "*" matches a single DNS label (any chars except dot). "*.t.me" therefore
    matches "cdn.t.me" but not "evil.example.t.me", which is the standard
    cert-wildcard semantics (RFC 6125).
    """
    compiled: list[re.Pattern[str]] = []
    for p in patterns:
        regex = re.escape(p).replace(r"\*", r"[^.]+")
        compiled.append(re.compile(f"^{regex}$", re.IGNORECASE))
    return compiled


async def _capture_cert(domain: str) -> tuple[bytes | None, bool]:
    """Re-handshake with verify=False; return (cert_der, chain_valid).

    Two TLS contexts are used so we can answer the chain-trust question
    *without* the hostname check that just rejected the original handshake:

      * cert_der: from a verify=False handshake, captures whatever the
        server presented even if hostname/chain were wrong.
      * chain_valid: a separate handshake with verify_mode=CERT_REQUIRED
        but check_hostname=False; reports whether the chain itself is
        trusted by the system CA bundle.

    Returns (None, False) on connect/handshake errors that prevent
    capturing any cert at all.
    """
    # Resolve via DoH (Cloudflare) so a poisoned system resolver can't
    # silently redirect the cert capture to the censor's host. If DoH
    # is also unreachable we fall back to getaddrinfo and tag the
    # evidence so the verdict path is auditable. The TLS module's
    # _resolve_ip does the same thing; importing it would create a
    # cycle, so duplicate the lookup here.
    ip = await _doh_resolve(domain)
    if ip is None:
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, domain)
        except OSError:
            return None, False

    def _do_capture() -> tuple[bytes | None, bool]:
        # Pass 1: capture cert bytes regardless of validity.
        cert_der: bytes | None = None
        try:
            ctx_capture = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_capture.check_hostname = False
            ctx_capture.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=5.0) as raw:
                with ctx_capture.wrap_socket(raw, server_hostname=domain) as tls:
                    cert_der = tls.getpeercert(binary_form=True)
        except Exception:
            return None, False

        if not cert_der:
            return None, False

        # Pass 2: ask the system trust store whether the chain validates,
        # ignoring hostname mismatch. A separate handshake is the cleanest
        # way: stdlib doesn't expose a "verify chain only" API on an
        # already-completed handshake.
        chain_valid = False
        try:
            ctx_chain = ssl.create_default_context()
            ctx_chain.check_hostname = False
            with socket.create_connection((ip, 443), timeout=5.0) as raw:
                with ctx_chain.wrap_socket(raw, server_hostname=domain):
                    chain_valid = True
        except ssl.SSLCertVerificationError:
            chain_valid = False
        except Exception:
            chain_valid = False

        return cert_der, chain_valid

    try:
        return await asyncio.wait_for(asyncio.to_thread(_do_capture), timeout=10.0)
    except Exception:
        return None, False


async def _doh_resolve(domain: str) -> str | None:
    """Resolve `domain` via Cloudflare DoH; returns first A or None."""
    # Soft DoH lookup; any error means we fall back to other resolution
    # paths in the caller, never propagated.
    with contextlib.suppress(Exception):
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as c:
            r = await c.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            if r.status_code == 200:
                for ans in r.json().get("Answer", []):
                    if ans.get("type") == 1 and ans.get("data"):
                        return str(ans["data"])
    return None


def _match_owned_cert(cert_der: bytes, patterns: list[re.Pattern[str]]) -> str | None:
    """Return the first SAN/CN matching any owned pattern, else None."""
    if not patterns:
        return None
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        return None

    candidates: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        candidates.extend(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            # x509 .value is str | bytes; cert.subject CN entries are always
            # str in practice, but mypy needs the explicit cast.
            value = attr.value
            if isinstance(value, str):
                candidates.append(value)

    for name in candidates:
        for pat in patterns:
            if pat.match(name):
                return name
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Health score computation
# ─────────────────────────────────────────────────────────────────────────────


def _compute_health_score(results: list[TestResult], weights: dict[str, float]) -> float:
    """
    Compute overall Telegram health score [0.0, 1.0].
    weights from telegram.yaml health_weights section (dc/web/cdn).
    """
    w_dc = float(weights.get("dc_reachability", 0.55))
    w_web = float(weights.get("web_access", 0.25))
    w_cdn = float(weights.get("cdn_access", 0.20))

    dc_results = [r for r in results if r.test.startswith("telegram_dc")]
    web_results = [r for r in results if r.test.startswith("telegram_web")]
    cdn_results = [r for r in results if r.test.startswith("telegram_cdn")]

    dc_score = _ok_ratio(dc_results)
    web_score = _ok_ratio(web_results)
    cdn_score = _ok_ratio(cdn_results)

    total_w = w_dc + w_web + w_cdn
    if total_w == 0:
        return 1.0
    # Renormalize in case the YAML weights drift from sum=1 (defensive —
    # otherwise a partial weights dict caps the maximum score below 1.0).
    return (dc_score * w_dc + web_score * w_web + cdn_score * w_cdn) / total_w


def _ok_ratio(results: list[TestResult]) -> float:
    # INCONCLUSIVE results carry no signal (e.g. probe host without IPv6,
    # globally-broken cdn1/cdn5 endpoints reclassified by cert-pattern check)
    # — exclude them from both numerator and denominator so they don't drag
    # the ratio toward 0. But if EVERY result is INCONCLUSIVE (e.g. censor
    # nuked all CDN endpoints AND each one happened to present a Telegram-
    # owned cert) we must NOT default to "neutral 50%" — that artificially
    # inflates the health score for a fully-broken Telegram. Return 0.0
    # instead; the dashboard reads "no decisive evidence of reachability".
    decisive = [r for r in results if r.verdict != Verdict.INCONCLUSIVE]
    if not decisive:
        return 0.0
    ok = sum(1 for r in decisive if r.verdict == Verdict.OK)
    return ok / len(decisive)


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").lower()


def _ua_tg() -> str:
    return "TelegramBot (censprobe, 0.1)"
