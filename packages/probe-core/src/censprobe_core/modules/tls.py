"""
modules/tls.py — TLS/SNI measurement module.

For every target (IP, domain) we try three handshakes:

  ``tls_<domain>_sni_blocked`` — handshake with SNI=domain, verifying the
    chain via the system trust store. ТСПУ SNI-blocking surfaces here as
    connection_reset / timeout while a clean network completes.

  ``tls_<domain>_sni_neutral`` — handshake with SNI="cloudflare.com" against
    the same IP, no cert verification. Used to prove the IP itself is
    reachable and isolate SNI-level filtering from IP-level dropping.

  ``tls_<domain>_ech`` — emitted only when ``ech_advertised: true`` is set
    on the target's YAML entry. Uses the ECH-capable curl-ech binary plus
    the server's published ECHConfigList (HTTPS-RR fetched via DoH).

Attribution: blocked-SNI failure + neutral-SNI TCP success →
tcp_rst_after_tls_ch (the SNI is what tripped the censor). Failure on both
SNIs collapses to ip_dropped / tls_handshake_failure.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time

import httpx

from censprobe_core.models import TestResult, Verdict, BlockingMethod

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

# TLS timeout fallback used by the few callers (internal helpers, ECH
# probe) that aren't on the run_tls_tests entry path. The main entry
# reads from CensprobeConfig.modules.tls — see run_tls_tests below.
_TLS_TIMEOUT = 10.0


async def run_tls_tests(
    targets: list[dict],  # {"domain": ..., "ip": ..., "blocked_sni": ...}
    repeats: int = 2,
) -> list[TestResult]:
    """Run TLS/SNI tests for each target in parallel (bounded).

    Concurrency cap and per-handshake timeout come from
    :class:`censprobe_core.config.TlsModuleConfig`. The internal
    helpers below still reference the module-level ``_TLS_TIMEOUT``
    fallback for back-compat with tests that import them directly.
    """
    from censprobe_core.config import get_config

    cfg = get_config().modules.tls
    global _TLS_TIMEOUT
    _TLS_TIMEOUT = cfg.timeout_sec
    sem = asyncio.Semaphore(cfg.max_parallel)

    async def _one(t: dict) -> list[TestResult]:
        async with sem:
            domain = t["domain"]
            ip = t.get("ip")
            blocked_sni = t.get("blocked_sni", domain)
            ech_advertised = bool(t.get("ech_advertised", False))

            if not ip:
                ip = await _resolve_ip(domain)
            if not ip:
                return [TestResult(
                    test=f"tls_{_slug(domain)}_no_ip",
                    category="tls",
                    target=domain,
                    verdict=Verdict.INCONCLUSIVE,
                    evidence={"reason": "could_not_resolve_ip"},
                )]

            return await _test_sni_scenarios(
                domain, ip, blocked_sni, repeats, ech_advertised=ech_advertised,
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
) -> tuple[Verdict, dict, int]:
    """Run _tls_connect up to `repeats` times; first OK wins, last failure
    is returned otherwise. Returns (final_verdict, evidence, attempts_made).

    Multiple attempts mitigate transient packet loss before declaring an
    SNI-blocked verdict — a real ТСПУ RST is consistent across retries,
    a genuine packet drop is not.
    """
    repeats = max(1, repeats)
    last_evidence: dict = {}
    last_verdict = Verdict.INCONCLUSIVE
    for attempt in range(1, repeats + 1):
        v, ev = await _tls_connect(ip, sni, verify=verify)
        last_verdict, last_evidence = v, ev
        if v == Verdict.OK:
            return v, ev, attempt
    return last_verdict, last_evidence, repeats


async def _test_sni_scenarios(
    domain: str,
    ip: str,
    blocked_sni: str,
    repeats: int,
    *,
    ech_advertised: bool = False,
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
        ip, blocked_sni, verify=True, repeats=repeats,
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

    results.append(TestResult(
        test=f"tls_{_slug(domain)}_sni_blocked",
        category="tls",
        target=f"{ip}:{blocked_sni}",
        verdict=base_verdict,
        method=base_method,
        evidence=ev_blocked,
        attempts=attempts_blocked,
    ))

    # Scenario 2: neutral SNI (cloudflare.com) on the same IP. We do NOT
    # verify the cert here — Cloudflare's edge will not present a cert
    # valid for a non-cloudflare IP, so verify=True would always fail.
    v_neutral, ev_neutral, attempts_neutral = await _tls_connect_with_repeats(
        ip, "cloudflare.com", verify=False, repeats=repeats,
    )
    # ssl_error on the neutral SNI means the server sent an INTERNAL_ERROR
    # alert — this happens when a Cloudflare IP doesn't serve cloudflare.com
    # (the target domain is hosted on Cloudflare but on a different IP range
    # than cloudflare.com's frontend). Server rejection ≠ network censorship.
    if v_neutral == Verdict.ANOMALY and ev_neutral.get("error") == "ssl_error":
        v_neutral = Verdict.INCONCLUSIVE
    results.append(TestResult(
        test=f"tls_{_slug(domain)}_sni_neutral",
        category="tls",
        target=f"{ip}:cloudflare.com",
        verdict=v_neutral,
        evidence=ev_neutral,
        attempts=attempts_neutral,
    ))

    # Attribution: if neutral SNI proves TCP reachability but blocked SNI
    # fails → SNI-level blocking.
    #
    # Two cases where neutral confirms TCP is up:
    #   1. v_neutral == OK (Cloudflare-hosted: cert irrelevant, handshake passed)
    #   2. v_neutral == INCONCLUSIVE with error="ssl_error" (server-side rejection
    #      like Google rejecting "cloudflare.com" SNI with unrecognized_name TLS
    #      alert). The alert proves TCP connected and TLS began; the rejection is
    #      the remote server's policy, not the censor. So IP is reachable.
    #
    # Without this second branch, SNI-blocking of Google/Meta/VK would never
    # be attributed as TCP_RST_AFTER_TLS_CH because "cloudflare.com" SNI always
    # gets an ssl_error from non-Cloudflare servers.
    neutral_tcp_ok = v_neutral == Verdict.OK or (
        v_neutral == Verdict.INCONCLUSIVE
        and ev_neutral.get("error") == "ssl_error"
    )
    if neutral_tcp_ok and v_blocked != Verdict.OK:
        err = ev_blocked.get("error", "")
        if err in ("connection_reset", "timeout"):
            results[0].method = BlockingMethod.TCP_RST_AFTER_TLS_CH
            # Slightly lower confidence when neutral was server-rejected
            # (ssl_error) rather than fully OK — TCP is proven but TLS
            # state on the neutral path is less certain.
            results[0].confidence = 0.92 if v_neutral == Verdict.OK else 0.82
            results[0].notes = (
                "Neutral SNI succeeds to same IP → SNI-level blocking confirmed"
                if v_neutral == Verdict.OK
                else "Neutral SNI TCP-connects (server-side rejection confirms IP reachable) "
                     "but blocked SNI fails → likely SNI-level blocking"
            )

    # Scenario 3: ECH — only when the YAML entry says the domain advertises
    # an ECHConfig. Without this gate, every non-ECH domain emits a permanent
    # INCONCLUSIVE/no_ech_in_https_record line on every run.
    if ech_advertised:
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


def _attribute_tls_failure(verdict: Verdict, evidence: dict) -> BlockingMethod | None:
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
    except asyncio.TimeoutError:
        # Critical: kill + reap so we don't leak the child process.
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        try:
            await proc.wait()
        except Exception:
            pass
        return None, b"", b""


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
    import base64

    async def _try_google(dom: str) -> str | None:
        client = _get_doh_client()
        resp = await client.get(
            "https://dns.google/resolve",
            params={"name": dom, "type": "HTTPS"},
            headers={"Accept": "application/dns-json"},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return None
        for answer in resp.json().get("Answer", []):
            if answer.get("type") != 65:
                continue
            # Google returns parsed text: "1 . alpn=h2 ech=AEX+... ipv4hint=..."
            for part in answer.get("data", "").split():
                if part.startswith("ech="):
                    ech_b64 = part[4:]
                    base64.b64decode(ech_b64, validate=True)
                    return ech_b64
        return None

    async def _try_cloudflare_hex(dom: str) -> str | None:
        """
        Cloudflare DoH returns HTTPS records as raw hex: "\\# <len> <hex bytes>".
        Parse SvcParam key=5 (ECH) from the wire format and base64-encode it.
        """
        client = _get_doh_client()
        resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": dom, "type": "HTTPS"},
            headers={"Accept": "application/dns-json"},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return None
        for answer in resp.json().get("Answer", []):
            if answer.get("type") != 65:
                continue
            rdata = answer.get("data", "").strip()
            # Text format (shouldn't happen for Cloudflare, but handle it)
            for part in rdata.split():
                if part.startswith("ech="):
                    ech_b64 = part[4:]
                    base64.b64decode(ech_b64, validate=True)
                    return ech_b64
            # Raw hex format: "\# <length> <hex>"
            if not rdata.startswith("\\#"):
                continue
            parts = rdata.split()
            if len(parts) < 3:
                continue
            raw = bytes.fromhex("".join(parts[2:]))
            # SVCB/HTTPS wire: 2-byte SvcPriority, DNS-name TargetName, then SvcParams
            # Skip SvcPriority (2 bytes) + TargetName (DNS encoded, ends at first 0x00)
            i = 2
            while i < len(raw) and raw[i] != 0:
                i += raw[i] + 1  # skip label (length + bytes)
            i += 1  # consume root label 0x00
            # Parse SvcParams: key(2) + len(2) + value(len)
            while i + 4 <= len(raw):
                key = int.from_bytes(raw[i:i+2], "big")
                vlen = int.from_bytes(raw[i+2:i+4], "big")
                val = raw[i+4:i+4+vlen]
                if key == 5:  # ECH SvcParamKey
                    return base64.b64encode(val).decode()
                i += 4 + vlen
        return None

    for attempt in (_try_google, _try_cloudflare_hex):
        try:
            result = await attempt(domain)
            if result is not None:
                return result
        except Exception as e:
            logger.debug("ECHConfig fetch failed for %s via %s: %s", domain, attempt.__name__, e)
    return None


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
            category="tls", target=domain,
            verdict=Verdict.INCONCLUSIVE, confidence=0.0,
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
            category="tls", target=domain,
            verdict=Verdict.INCONCLUSIVE, confidence=1.0,
            evidence={"status": "no_ech_in_https_record"},
            notes="Server has no ECH config — cannot conclude about censorship.",
        )

    # Build curl command with explicit ECHConfig supplied.
    # --ech hard: fail the handshake if ECH is not used.
    # --ech ecl:<b64>: supply the server's ECHConfig directly (bypasses HTTPSRR).
    cmd = [
        _CURL_ECH_BINARY,
        "--ech", "hard",
        "--ech", f"ecl:{ech_config}",
        "-sv", "--max-time", "10",
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
            test=test_name, category="tls", target=domain,
            verdict=Verdict.INCONCLUSIVE, confidence=0.1,
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
_CURL_ECH_BINARY: str = "curl"          # name / path of the ECH-capable binary
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
                    [candidate, "-V"], timeout=3, capture_stderr=False,
                )
            except FileNotFoundError:
                continue
            except Exception:
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
    try:
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
                    return ans["data"]
    except Exception:
        pass

    # 2) System resolver fallback — bounded so a hung resolver can't stall.
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM),
            timeout=5.0,
        )
        _LAST_RESOLVE_PATH[domain] = "system_resolver_fallback"
        return infos[0][4][0]
    except Exception:
        _LAST_RESOLVE_PATH[domain] = "no_resolution"
        return None


# Per-domain breadcrumb of which resolver answered for the TLS test.
# Read by _test_sni_scenarios so the evidence dict tells reviewers
# whether they're looking at a DoH-truthed host or a possibly-poisoned
# system-resolver answer.
_LAST_RESOLVE_PATH: dict[str, str] = {}


def _extract_cn(rdn_seq) -> str | None:
    """
    Pull out commonName from ssl.getpeercert()'s 'subject' / 'issuer' field.

    Format from stdlib is a nested tuple:
      ((('commonName', 'meduza.io'),), (('organizationName', '...'),), ...)
    """
    if not rdn_seq:
        return None
    try:
        for rdn in rdn_seq:
            for attr in rdn:
                if len(attr) == 2 and attr[0] == "commonName":
                    return attr[1]
    except Exception:
        pass
    return None


def _slug(domain: str) -> str:
    return domain.replace(".", "_").replace("-", "_").lower()
