"""
modules/tls.py — TLS/SNI measurement module.

For every target (IP, domain) we try three handshakes:

  ``tls_<domain>_sni_blocked`` — handshake with SNI=domain, verifying the
    chain via the system trust store. ТСПУ SNI-blocking surfaces here as
    connection_reset / timeout while a clean network completes.

  ``tls_<domain>_sni_neutral`` — handshake with a neutral SNI selected per
    IP family (cloudflare.com / www.akamai.com / aws.amazon.com — see
    ``_pick_neutral_sni``) against the same IP, no cert verification. Used
    to prove the IP itself is reachable and isolate SNI-level filtering
    from IP-level dropping.

  ``tls_<domain>_ech`` — emitted only when ``ech_advertised: true`` is set
    on the target's YAML entry. Uses the ECH-capable curl-ech binary plus
    the server's published ECHConfigList (HTTPS-RR fetched via DoH).

Attribution: blocked-SNI failure + neutral-SNI TCP success →
tcp_rst_after_tls_ch (the SNI is what tripped the censor). Failure on both
SNIs collapses to ip_dropped / tls_handshake_failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
import ssl
import time
from typing import Any

import httpx

from censprobe_core.models import BlockingMethod, TestResult, Verdict
from censprobe_core.utils import stamp_test_elapsed

# Process-wide DoH client. Instantiating httpx.AsyncClient per resolve()
# call meant a fresh TLS handshake to 1.1.1.1 every time, which inflated
# both the DoH RTT and the wall-clock cost of TLS phase. Reusing one
# client across the whole probe run lets the TCP/TLS connection to
# Cloudflare stay warm.
_DOH_CLIENT: httpx.AsyncClient | None = None


def _get_doh_client() -> httpx.AsyncClient:
    global _DOH_CLIENT
    if _DOH_CLIENT is None:
        _DOH_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    return _DOH_CLIENT


logger = logging.getLogger(__name__)

# Default per-handshake timeout used by callers that import the helpers
# directly (tests, the ECH sub-probe). The main entry point overrides it
# via the ``timeout`` parameter threaded through the call chain, read
# from CensprobeConfig.modules.tls — see :func:`run_tls_tests`. Previously
# this was a *mutable module-level global* that ``run_tls_tests`` clobbered
# and helpers read implicitly; that anti-pattern produced silent staleness
# between parallel test-suite invocations. Replaced 2026-05-14 with an
# explicit parameter that has a sensible default constant.
_DEFAULT_TLS_TIMEOUT_SEC = 10.0


# ─────────────────────────────────────────────────────────────────────────────
# Neutral-SNI selection per IP family
# ─────────────────────────────────────────────────────────────────────────────
#
# The pair test needs a "control" SNI that, on the same IP, proves the IP is
# reachable. Hard-coding "cloudflare.com" worked for Cloudflare edges but
# produced INCONCLUSIVE/ssl_error on every non-Cloudflare CDN: Akamai and
# AWS edges return TLSV1_ALERT_INTERNAL_ERROR / handshake_failure when the
# requested SNI is not on their provisioned customer list. The downstream
# attribution logic already counts that ssl_error as "TCP up" for blocking
# inference, but every report shipped with 4–6 spurious INCONCLUSIVE tls
# rows on Akamai-hosted RFE/RT/TikTok and AWS-hosted ExpressVPN.
#
# Per-family selection picks an SNI that the family is statistically much
# more likely to terminate cleanly:
#   * Akamai → ``www.akamai.com`` (Akamai's own corp site is delivered on
#     the same edge fleet, so its cert is generally provisioned alongside
#     customer certs)
#   * AWS CloudFront → ``aws.amazon.com`` (also CloudFront-hosted)
#   * Cloudflare → ``cloudflare.com`` (Cloudflare's own front)
#   * Anything else → ``cloudflare.com`` as the default control
#
# The CIDR list is intentionally conservative — false-classifying an IP
# into the wrong family just degrades to the default ``cloudflare.com``
# behaviour, which is what we already had.
_AKAMAI_CIDRS = tuple(
    ipaddress.ip_network(c)
    for c in (
        "2.16.0.0/13",  # Akamai EU
        "23.0.0.0/12",  # Akamai US (23.0-23.15)
        "23.32.0.0/11",  # Akamai NA (23.32-23.63) — verified rDNS *.akamaitechnologies.com
        "92.122.0.0/15",  # Akamai EU (92.122-92.123) — Frankfurt edges seen for currenttime.tv
        "104.64.0.0/10",  # Akamai NA (large block, 104.64-104.127)
        "184.24.0.0/13",  # Akamai (184.24-184.31)
        "184.50.0.0/15",  # Akamai (184.50-184.51) — AS20940 verified via rDNS
        "184.84.0.0/14",  # Akamai EU (184.84-184.87) — Frankfurt edges for rferl.org / tiktok.com
    )
)

_CLOUDFRONT_CIDRS = tuple(
    ipaddress.ip_network(c)
    for c in (
        # AWS CloudFront published ranges (subset). Adding more from
        # https://ip-ranges.amazonaws.com/ip-ranges.json (service =
        # CLOUDFRONT) is the maintenance path; here we cover the prefixes
        # observed across our own solo-run JSONs.
        "13.32.0.0/15",
        "13.35.0.0/16",
        "13.224.0.0/14",
        "13.249.0.0/16",  # ExpressVPN-hosting prefix seen in ya-zone-a
        "18.64.0.0/14",
        "18.160.0.0/13",
        "52.84.0.0/15",
        "54.182.0.0/16",
        "54.192.0.0/16",
        "54.230.0.0/16",
        "54.239.128.0/18",
        "99.84.0.0/16",
        "99.86.0.0/16",
        "108.138.0.0/15",
        "108.156.0.0/14",
        "143.204.0.0/16",
        "204.246.164.0/22",
        "205.251.192.0/19",
    )
)

_DEFAULT_NEUTRAL_SNI = "cloudflare.com"
_AKAMAI_NEUTRAL_SNI = "www.akamai.com"
_CLOUDFRONT_NEUTRAL_SNI = "aws.amazon.com"


def _pick_neutral_sni(ip: str) -> str:
    """Return the most likely-to-handshake neutral SNI for ``ip``.

    Falls back to ``cloudflare.com`` whenever the IP can't be classified
    or doesn't fall inside a known CDN range — the historical default
    behaviour, preserved as the safe baseline.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _DEFAULT_NEUTRAL_SNI
    for net in _AKAMAI_CIDRS:
        if addr in net:
            return _AKAMAI_NEUTRAL_SNI
    for net in _CLOUDFRONT_CIDRS:
        if addr in net:
            return _CLOUDFRONT_NEUTRAL_SNI
    return _DEFAULT_NEUTRAL_SNI


async def run_tls_tests(
    targets: list[dict[str, Any]],  # {"domain": ..., "ip": ..., "blocked_sni": ...}
    repeats: int = 2,
) -> list[TestResult]:
    """Run TLS/SNI tests for each target in parallel (bounded).

    Concurrency cap and per-handshake timeout come from
    :class:`censprobe_core.config.TlsModuleConfig`. The timeout is
    threaded through the helper chain as a parameter rather than via
    a module-level mutable global (replaced 2026-05-14 — the previous
    global was race-prone across parallel test invocations).
    """
    from censprobe_core.config import get_config

    cfg = get_config().modules.tls
    timeout = cfg.timeout_sec
    sem = asyncio.Semaphore(cfg.max_parallel)

    # Per-run state reset: the resolve-path breadcrumb dict accumulates
    # across runs if not cleared (no per-instance binding because the
    # helpers are module-level). Clearing at run-start keeps long-lived
    # test suites and re-imports honest.
    _LAST_RESOLVE_PATH.clear()

    async def _one(t: dict[str, Any]) -> list[TestResult]:
        async with sem:
            domain = t["domain"]
            ip = t.get("ip")
            blocked_sni = t.get("blocked_sni", domain)
            ech_advertised = bool(t.get("ech_advertised", False))

            if not ip:
                ip = await _resolve_ip(domain)
            if not ip:
                return [
                    TestResult(
                        test=f"tls_{_slug(domain)}_no_ip",
                        category="tls",
                        target=domain,
                        verdict=Verdict.INCONCLUSIVE,
                        evidence={"reason": "could_not_resolve_ip"},
                    )
                ]

            return await _test_sni_scenarios(
                domain,
                ip,
                blocked_sni,
                repeats,
                ech_advertised=ech_advertised,
                timeout=timeout,
            )

    grouped = await asyncio.gather(*[_one(t) for t in targets])
    results: list[TestResult] = []
    for group in grouped:
        results.extend(group)
    return results


async def _tls_connect_with_repeats(
    ip: str,
    sni: str,
    *,
    verify: bool,
    repeats: int,
    timeout: float = _DEFAULT_TLS_TIMEOUT_SEC,
) -> tuple[Verdict, dict[str, Any], int]:
    """Run _tls_connect up to `repeats` times; first OK wins, last failure
    is returned otherwise. Returns (final_verdict, evidence, attempts_made).

    Multiple attempts mitigate transient packet loss before declaring an
    SNI-blocked verdict — a real ТСПУ RST is consistent across retries,
    a genuine packet drop is not.
    """
    repeats = max(1, repeats)
    last_evidence: dict[str, Any] = {}
    last_verdict = Verdict.INCONCLUSIVE
    for attempt in range(1, repeats + 1):
        v, ev = await _tls_connect(ip, sni, verify=verify, timeout=timeout)
        last_verdict, last_evidence = v, ev
        if v == Verdict.OK:
            return v, ev, attempt
    return last_verdict, last_evidence, repeats


def _attribute_sni_blocking(
    blocked_result: TestResult,
    *,
    v_blocked: Verdict,
    ev_blocked: dict[str, Any],
    v_neutral: Verdict,
    ev_neutral: dict[str, Any],
) -> None:
    """If neutral SNI proves TCP reachability but blocked SNI fails → SNI-level blocking.

    Two cases where neutral confirms TCP is up:
      1. v_neutral == OK (the chosen neutral SNI is provisioned on this
         edge: handshake passed, cert irrelevant)
      2. v_neutral == INCONCLUSIVE with error="ssl_error" (server-side
         rejection — e.g. Google rejecting the neutral SNI with
         unrecognized_name TLS alert when the IP belongs to a CDN family
         we have no neutral SNI for). The alert proves TCP connected and
         TLS began; the rejection is the remote server's policy, not the
         censor. So IP is reachable.

    Without this second branch, SNI-blocking of Google/Meta/VK would never
    be attributed as TCP_RST_AFTER_TLS_CH on edges that don't terminate
    our control SNI cleanly. ``_pick_neutral_sni`` reduces (but does not
    eliminate) such mismatches.
    """
    neutral_tcp_ok = v_neutral == Verdict.OK or (
        v_neutral == Verdict.INCONCLUSIVE and ev_neutral.get("error") == "ssl_error"
    )
    if not neutral_tcp_ok or v_blocked == Verdict.OK:
        return
    if ev_blocked.get("error", "") not in ("connection_reset", "timeout"):
        return

    blocked_result.method = BlockingMethod.TCP_RST_AFTER_TLS_CH
    # Slightly lower confidence when neutral was server-rejected
    # (ssl_error) rather than fully OK — TCP is proven but TLS state
    # on the neutral path is less certain.
    blocked_result.confidence = 0.92 if v_neutral == Verdict.OK else 0.82
    blocked_result.notes = (
        "Neutral SNI succeeds to same IP → SNI-level blocking confirmed"
        if v_neutral == Verdict.OK
        else "Neutral SNI TCP-connects (server-side rejection confirms IP reachable) "
        "but blocked SNI fails → likely SNI-level blocking"
    )


async def _test_sni_scenarios(
    domain: str,
    ip: str,
    blocked_sni: str,
    repeats: int,
    *,
    ech_advertised: bool = False,
    timeout: float = _DEFAULT_TLS_TIMEOUT_SEC,
) -> list[TestResult]:
    """Test multiple SNI scenarios against one IP.

    The ECH scenario only runs when the target's YAML entry has
    ``ech_advertised: true``. Domains without an ECHConfig in their HTTPS DNS
    record otherwise emit a permanent INCONCLUSIVE on every run; gating the
    test by the YAML flag turns those into "not tested" instead of "tested
    and noise" — operators audit the flag list, not the dashboard.
    """
    results = []

    # Scenario 1: correct/blocked SNI (with retries). verify=True means the
    # system trust store validates the chain — a real ТСПУ MITM substitutes
    # a cert with no path to a trusted root and surfaces here as
    # ssl.SSLCertVerificationError → Verdict.ANOMALY with TLS_HANDSHAKE_FAILURE.
    # Baseline cert-chain hash comparison was removed: CDN edges rotate
    # leaf certs continuously and within seconds, so any control-vs-solo
    # hash diff is overwhelmingly cert rotation, not MITM.
    v_blocked, ev_blocked, attempts_blocked = await _tls_connect_with_repeats(
        ip,
        blocked_sni,
        verify=True,
        repeats=repeats,
        timeout=timeout,
    )

    # Record which resolver path produced the IP we just tested. A
    # "system_resolver_fallback" path means DoH was unreachable and
    # we're potentially measuring the censor's hijacked IP, which
    # changes the interpretation of an OK verdict.
    resolve_path = _LAST_RESOLVE_PATH.get(domain)
    if resolve_path:
        ev_blocked["resolve_path"] = resolve_path

    base_verdict = v_blocked
    base_method = _attribute_tls_failure(v_blocked, ev_blocked)

    results.append(
        TestResult(
            test=f"tls_{_slug(domain)}_sni_blocked",
            category="tls",
            target=f"{ip}:{blocked_sni}",
            verdict=base_verdict,
            method=base_method,
            evidence=ev_blocked,
            attempts=attempts_blocked,
        )
    )

    # Scenario 2: neutral SNI on the same IP. Per-IP-family lookup —
    # Cloudflare gets cloudflare.com, Akamai gets www.akamai.com, AWS
    # CloudFront gets aws.amazon.com. Hardcoding cloudflare.com produced
    # spurious INCONCLUSIVE/ssl_error on every Akamai- and CloudFront-
    # hosted target because those edges reject SNIs they aren't
    # provisioned for. We do NOT verify the cert here: even on the
    # right family the IP-vs-host pairing won't satisfy verify=True.
    neutral_sni = _pick_neutral_sni(ip)
    v_neutral, ev_neutral, attempts_neutral = await _tls_connect_with_repeats(
        ip,
        neutral_sni,
        verify=False,
        repeats=repeats,
        timeout=timeout,
    )
    # ssl_error on the neutral SNI means the server sent an INTERNAL_ERROR
    # alert — happens when the chosen neutral SNI still isn't provisioned
    # on this exact edge member (CDNs partition customer certs across
    # subsets of their fleet). Server rejection ≠ network censorship; the
    # downstream attribution treats INCONCLUSIVE+ssl_error as "TCP up".
    if v_neutral == Verdict.ANOMALY and ev_neutral.get("error") == "ssl_error":
        v_neutral = Verdict.INCONCLUSIVE
    results.append(
        TestResult(
            test=f"tls_{_slug(domain)}_sni_neutral",
            category="tls",
            target=f"{ip}:{neutral_sni}",
            verdict=v_neutral,
            evidence=ev_neutral,
            attempts=attempts_neutral,
        )
    )

    _attribute_sni_blocking(
        results[0],
        v_blocked=v_blocked,
        ev_blocked=ev_blocked,
        v_neutral=v_neutral,
        ev_neutral=ev_neutral,
    )

    # Scenario 3: ECH — only when the YAML entry says the domain advertises
    # an ECHConfig. Without this gate, every non-ECH domain emits a permanent
    # INCONCLUSIVE/no_ech_in_https_record line on every run.
    if ech_advertised:
        ech_result = await _test_ech(domain)
        if ech_result:
            results.append(ech_result)

    return results


def _tls_handshake_blocking(
    ip: str,
    sni: str,
    port: int,
    ctx: ssl.SSLContext,
    t0: float,
    timeout: float = _DEFAULT_TLS_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Blocking TLS handshake; never raises — returns an evidence dict."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            rtt_connect = (time.monotonic() - t0) * 1000
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                cert = tls.getpeercert()
                return {
                    "ok": True,
                    "rtt_connect_ms": rtt_connect,
                    "rtt_total_ms": (time.monotonic() - t0) * 1000,
                    "alpn": tls.selected_alpn_protocol(),
                    "cert_subject_cn": _extract_cn(cert.get("subject")) if cert else None,
                    "cert_issuer_cn": _extract_cn(cert.get("issuer")) if cert else None,
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


async def _tls_connect(
    ip: str,
    sni: str,
    verify: bool = True,
    port: int = 443,
    timeout: float = _DEFAULT_TLS_TIMEOUT_SEC,
) -> tuple[Verdict, dict[str, Any]]:
    """
    Attempt TLS handshake to ip:port with specified SNI.
    Returns (verdict, evidence_dict).
    """
    evidence: dict[str, Any] = {"ip": ip, "sni": sni, "port": port}
    t0 = time.monotonic()

    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _tls_handshake_blocking, ip, sni, port, ctx, t0, timeout),
            timeout=timeout + 2,
        )
    except TimeoutError:
        evidence["error"] = "outer_timeout"
        # outer_timeout = the wrapper waited past ``timeout``+2 — the inner
        # blocking handshake never returned. Treat as BLOCKED with IP_DROPPED
        # method (same as a pure connect-stage SYN drop on the wire).
        return Verdict.BLOCKED, evidence
    except Exception as e:
        evidence["error"] = str(e)
        return Verdict.ERROR, evidence

    evidence.update(result)
    if result.get("ok"):
        return Verdict.OK, evidence
    if result.get("error", "") in ("connection_reset", "timeout"):
        return Verdict.BLOCKED, evidence
    return Verdict.ANOMALY, evidence


def _attribute_tls_failure(verdict: Verdict, evidence: dict[str, Any]) -> BlockingMethod | None:
    """Guess blocking method from TLS evidence."""
    if verdict == Verdict.OK:
        return None
    err = evidence.get("error", "")
    if err == "connection_reset":
        return BlockingMethod.TCP_RST_AFTER_TLS_CH
    if err in ("timeout", "outer_timeout"):
        return BlockingMethod.IP_DROPPED
    if err in ("ssl_error", "cert_verification_failed"):
        return BlockingMethod.TLS_HANDSHAKE_FAILURE
    return None


async def _run_subprocess(
    cmd: list[str],
    timeout: float,
    *,
    capture_stdout: bool = True,
    capture_stderr: bool = True,
) -> tuple[int | None, bytes, bytes]:
    """Run subprocess with timeout, ensuring no zombie / leaked child.

    Returns (returncode, stdout, stderr). returncode is None if killed for
    timeout. Caller is responsible for interpreting failure.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE if capture_stdout else asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out or b"", err or b""
    except TimeoutError:
        # Critical: kill + reap so we don't leak the child process.
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        # wait() can race with kill — we only need to reap, not propagate.
        with contextlib.suppress(Exception):
            await proc.wait()
        return None, b"", b""


_DNS_JSON_MIME = "application/dns-json"


def _parse_ech_from_text_rdata(rdata: str) -> str | None:
    """Pull ``ech=<base64>`` out of a text-formatted HTTPS rdata field.

    Used by Google's DoH JSON ("1 . alpn=h2 ech=AEX+... ipv4hint=...") and
    occasionally Cloudflare. Returns the base64 string verbatim (validated).
    """
    import base64

    for part in rdata.split():
        if part.startswith("ech="):
            ech_b64 = part[4:]
            base64.b64decode(ech_b64, validate=True)
            return ech_b64
    return None


def _parse_ech_from_hex_rdata(rdata: str) -> str | None:
    """Decode SvcParamKey=5 (ECH) out of Cloudflare DoH's raw hex rdata.

    Format: ``\\# <length> <hex bytes>``. The wire layout is
    ``SvcPriority(2)`` + DNS-encoded ``TargetName`` (ends at 0x00) +
    SvcParams (key(2)+len(2)+value(len)*).
    """
    import base64

    if not rdata.startswith("\\#"):
        return None
    parts = rdata.split()
    if len(parts) < 3:
        return None
    raw = bytes.fromhex("".join(parts[2:]))
    i = 2
    while i < len(raw) and raw[i] != 0:
        i += raw[i] + 1
    i += 1  # consume root label 0x00
    while i + 4 <= len(raw):
        key = int.from_bytes(raw[i : i + 2], "big")
        vlen = int.from_bytes(raw[i + 2 : i + 4], "big")
        val = raw[i + 4 : i + 4 + vlen]
        if key == 5:
            return base64.b64encode(val).decode()
        i += 4 + vlen
    return None


async def _try_google_ech(dom: str) -> str | None:
    client = _get_doh_client()
    resp = await client.get(
        "https://dns.google/resolve",
        params={"name": dom, "type": "HTTPS"},
        headers={"Accept": _DNS_JSON_MIME},
        timeout=5.0,
    )
    if resp.status_code != 200:
        return None
    for answer in resp.json().get("Answer", []):
        if answer.get("type") != 65:
            continue
        ech = _parse_ech_from_text_rdata(answer.get("data", ""))
        if ech is not None:
            return ech
    return None


async def _try_cloudflare_ech(dom: str) -> str | None:
    """Cloudflare DoH returns HTTPS records as raw hex ``\\# <len> <hex>``."""
    client = _get_doh_client()
    resp = await client.get(
        "https://cloudflare-dns.com/dns-query",
        params={"name": dom, "type": "HTTPS"},
        headers={"Accept": _DNS_JSON_MIME},
        timeout=5.0,
    )
    if resp.status_code != 200:
        return None
    for answer in resp.json().get("Answer", []):
        if answer.get("type") != 65:
            continue
        rdata = answer.get("data", "").strip()
        ech = _parse_ech_from_text_rdata(rdata) or _parse_ech_from_hex_rdata(rdata)
        if ech is not None:
            return ech
    return None


async def _fetch_ech_config(domain: str) -> str | None:
    """
    Fetch the ECHConfig for *domain* from its HTTPS DNS record (type 65) via DoH.

    curl's auto-HTTPSRR resolution only works when the system resolver
    supports HTTPS records (c-ares 1.21+ and a compatible upstream). In
    practice, the default system resolver in Docker containers often does
    not return HTTPS records, so curl reports "ECH: requested but no
    ECHConfig available" for domains that do advertise ECH. We fetch it
    ourselves via DoH and pass it to curl explicitly via --ech ecl:<base64>.

    DoH provider notes:
      - Google (dns.google/resolve): returns parsed text like
        "1 . alpn=h2 ech=AEX+... ipv4hint=..." — easy to parse.
      - Cloudflare (cloudflare-dns.com/dns-query): returns raw wire-format
        hex like "\\# 133 00 01 00 00 ..." — cannot be parsed with a simple
        ech= split. We try Google first, Cloudflare as fallback for
        raw-hex parsing.

    Returns the raw base64-encoded ECHConfigList from the first HTTPS record
    that carries one, or None if the domain has no ECH deployment.
    """
    for attempt in (_try_google_ech, _try_cloudflare_ech):
        try:
            result = await attempt(domain)
            if result is not None:
                return result
        except Exception as e:
            logger.debug("ECHConfig fetch failed for %s via %s: %s", domain, attempt.__name__, e)
    return None


@stamp_test_elapsed
async def _test_ech(domain: str) -> TestResult | None:
    """
    Test ECH (Encrypted Client Hello) via curl --ech.

    curl only supports --ech when linked against a TLS backend with ECH
    (BoringSSL in the curl-ech binary shipped by the Dockerfile). Debian's
    system curl has no ECH support — we detect this and return INCONCLUSIVE.

    We first fetch the HTTPS DNS record for the domain to get the ECHConfig.
    If the server doesn't advertise ECH (no ech= in the HTTPS record), there's
    nothing to test and we return INCONCLUSIVE. If it does, we pass the config
    explicitly to curl via --ech ecl:<base64>. curl's auto-HTTPSRR resolution
    requires c-ares + a resolver that returns HTTPS records, which is unreliable
    in container DNS environments — fetching it ourselves is more robust.
    """
    test_name = f"tls_{_slug(domain)}_ech"
    if not await _curl_supports_ech():
        return TestResult(
            test=test_name,
            category="tls",
            target=domain,
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.0,
            evidence={
                "status": "curl_without_ech",
                "reason": "local curl has no --ech feature flag in tls-features",
            },
            notes="ECH cannot be tested without a curl + TLS backend compiled with ECH.",
        )

    # Fetch ECHConfig from DNS HTTPS record via DoH.
    ech_config = await _fetch_ech_config(domain)
    if ech_config is None:
        return TestResult(
            test=test_name,
            category="tls",
            target=domain,
            verdict=Verdict.INCONCLUSIVE,
            confidence=1.0,
            evidence={"status": "no_ech_in_https_record"},
            notes="Server has no ECH config — cannot conclude about censorship.",
        )

    # Build curl command with explicit ECHConfig supplied.
    # --ech hard: fail the handshake if ECH is not used.
    # --ech ecl:<b64>: supply the server's ECHConfig directly (bypasses HTTPSRR).
    cmd = [
        _CURL_ECH_BINARY,
        "--ech",
        "hard",
        "--ech",
        f"ecl:{ech_config}",
        "-sv",
        "--max-time",
        "10",
        f"https://{domain}/",
    ]
    try:
        rc, _, stderr = await _run_subprocess(cmd, timeout=15, capture_stdout=False)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.debug("ECH test failed for %s: %s", domain, e)
        return None

    if rc is None:
        # Wall-clock timeout — neither evidence of ECH support nor blocking.
        return TestResult(
            test=test_name,
            category="tls",
            target=domain,
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.1,
            evidence={"status": "curl_timeout"},
        )

    stderr_text = stderr.decode(errors="replace")
    stderr_low = stderr_text.lower()

    # curl exit codes for "real" network blocking we treat as suspicious:
    #   7  = couldn't connect, 28 = timeout, 35 = SSL handshake fail,
    #   52 = empty reply (RST after CH), 56 = recv failure (mid-handshake RST)
    NETWORK_BLOCKED_RCS = {7, 28, 35, 52, 56}
    # Phrases that indicate the *server* simply doesn't have ECH config —
    # not censorship.
    ECH_NOT_AVAILABLE_PHRASES = (
        "ech is not available",
        "no ech configuration",
        "no echconfig",
        "not advertising ech",
        "ech retry-config",
    )

    verdict: Verdict
    method: BlockingMethod | None = None
    notes: str | None = None
    confidence: float = 1.0
    if rc == 0:
        verdict = Verdict.OK
    elif any(p in stderr_low for p in ECH_NOT_AVAILABLE_PHRASES):
        verdict = Verdict.INCONCLUSIVE
        notes = "Server has no ECH config — cannot conclude about censorship."
    elif rc in NETWORK_BLOCKED_RCS:
        verdict = Verdict.BLOCKED
        method = BlockingMethod.ECH_BLOCKED
    else:
        # Unrecognised non-zero — be conservative and flag as anomaly,
        # not blocked, to avoid false positives. Lower confidence so the
        # dashboard / scoring treats this catch-all bucket as soft signal.
        verdict = Verdict.ANOMALY
        confidence = 0.4

    return TestResult(
        test=test_name,
        category="tls",
        target=domain,
        verdict=verdict,
        method=method,
        confidence=confidence,
        evidence={
            "curl_returncode": rc,
            "ech_config_source": "https_record_doh",
            "stderr_tail": stderr_text[-300:],
        },
        notes=notes,
    )


# Cache whether any local curl binary supports ECH, and which one to use.
# We prefer curl-ech (our custom build dropped in by the Dockerfile multi-stage)
# over the system curl (OpenSSL 3.0 on Debian 12, no ECH).
_CURL_ECH_CACHE: bool | None = None
_CURL_ECH_BINARY: str = "curl"  # name / path of the ECH-capable binary
_CURL_ECH_CACHE_LOCK = asyncio.Lock()


async def _curl_supports_ech() -> bool:
    """Cached check: is there a curl binary with ECH in its Features line?

    Probes candidates in preference order:
      1. curl-ech  — our custom build (OpenSSL 3.4+ with enable-ech),
                     installed by the multi-stage Dockerfile builder stage.
      2. curl      — system curl (Debian 12 → OpenSSL 3.0, no ECH support).

    The result AND the winning binary name are cached process-wide so the
    probes for every domain in the run hit the same binary without re-running
    `curl -V` each time.
    """
    global _CURL_ECH_CACHE, _CURL_ECH_BINARY
    if _CURL_ECH_CACHE is not None:
        return _CURL_ECH_CACHE
    async with _CURL_ECH_CACHE_LOCK:
        if _CURL_ECH_CACHE is not None:
            return _CURL_ECH_CACHE

        for candidate in ("curl-ech", "curl"):
            try:
                rc, out, _ = await _run_subprocess(
                    [candidate, "-V"],
                    timeout=3,
                    capture_stderr=False,
                )
            except FileNotFoundError:
                continue
            except Exception:  # noqa: S112 — try next candidate on any failure
                continue

            if rc is None:
                continue

            text = out.decode(errors="replace").lower()
            feat_line = next(
                (line for line in text.splitlines() if line.startswith("features:")),
                "",
            )
            tokens = feat_line.replace("features:", "").split()
            if "ech" in tokens:
                _CURL_ECH_CACHE = True
                _CURL_ECH_BINARY = candidate
                logger.debug("ECH-capable curl found: %s", candidate)
                return True

        _CURL_ECH_CACHE = False
        return False


async def _resolve_ip(domain: str) -> str | None:
    """Resolve `domain` to a single IPv4 for the TLS test.

    Why DoH-first: if the local resolver is poisoned (a real possibility
    when probing blocked domains in RU), `getaddrinfo` returns a hijacked
    IP and the SNI test ends up measuring the censor's redirect host, not
    the real one. We try Cloudflare DoH first and only fall back to
    `getaddrinfo` if the DoH path is itself unreachable.

    Records which path was used in module state so callers can include
    it in evidence — the system-resolver fallback against a poisoned ISP
    means the "OK" result is pointing at the censor's host, not the real
    one, and reviewers need to see that.
    """
    # 1) DoH (Cloudflare) — cleartext-immune to local DNS poisoning.
    # Any failure (timeout, TLS error, blocked) just falls through to the
    # system-resolver path, which the caller's evidence dict will surface.
    with contextlib.suppress(Exception):
        client = _get_doh_client()
        r = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
        )
        if r.status_code == 200:
            data = r.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 1 and ans.get("data"):
                    _LAST_RESOLVE_PATH[domain] = "doh"
                    return str(ans["data"])

    # 2) System resolver fallback — bounded so a hung resolver can't stall.
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM),
            timeout=5.0,
        )
        _LAST_RESOLVE_PATH[domain] = "system_resolver_fallback"
        return str(infos[0][4][0])
    except Exception:
        _LAST_RESOLVE_PATH[domain] = "no_resolution"
        return None


# Per-domain breadcrumb of which resolver answered for the TLS test.
# Read by _test_sni_scenarios so the evidence dict tells reviewers
# whether they're looking at a DoH-truthed host or a possibly-poisoned
# system-resolver answer.
_LAST_RESOLVE_PATH: dict[str, str] = {}


def _extract_cn(rdn_seq: Any) -> str | None:
    """
    Pull out commonName from ssl.getpeercert()'s 'subject' / 'issuer' field.

    Format from stdlib is a nested tuple:
      ((('commonName', 'meduza.io'),), (('organizationName', '...'),), ...)
    """
    if not rdn_seq:
        return None
    # rdn_seq is a stdlib-shaped tuple-of-tuples; if it's malformed for any
    # reason we treat it as missing-CN rather than crashing the TLS module.
    with contextlib.suppress(Exception):
        for rdn in rdn_seq:
            for attr in rdn:
                if len(attr) == 2 and attr[0] == "commonName":
                    return str(attr[1])
    return None


def _slug(domain: str) -> str:
    return domain.replace(".", "_").replace("-", "_").lower()
