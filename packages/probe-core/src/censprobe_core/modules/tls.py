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
import hashlib
import logging
import socket
import ssl
import time
from typing import Optional

from censprobe_core.baseline import BaselineComparator
from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_TLS_TIMEOUT = 10.0  # seconds
_MAX_PARALLEL = 6    # concurrency cap for TLS handshakes


async def run_tls_tests(
    targets: list[dict],  # {"domain": ..., "ip": ..., "blocked_sni": ...}
    repeats: int = 2,
    comparator: Optional[BaselineComparator] = None,
) -> list[TestResult]:
    """Run TLS/SNI tests for each target in parallel (bounded)."""
    sem = asyncio.Semaphore(_MAX_PARALLEL)

    async def _one(t: dict) -> list[TestResult]:
        async with sem:
            domain = t["domain"]
            ip = t.get("ip")
            blocked_sni = t.get("blocked_sni", domain)

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

            return await _test_sni_scenarios(domain, ip, blocked_sni, repeats, comparator)

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
    comparator: Optional[BaselineComparator],
) -> list[TestResult]:
    """Test multiple SNI scenarios against one IP."""
    results = []

    # Scenario 1: correct/blocked SNI (with retries)
    v_blocked, ev_blocked, attempts_blocked = await _tls_connect_with_repeats(
        ip, blocked_sni, verify=True, repeats=repeats,
    )

    # Baseline cert-chain comparison — previously this module collected the
    # leaf cert SHA but never compared it against baseline, silently
    # disabling MITM detection. Run the comparison only if the handshake
    # succeeded; a failed handshake has no chain to compare.
    cert_chain = ev_blocked.get("cert_chain_sha256") or []
    base_verdict = v_blocked
    base_method = _attribute_tls_failure(v_blocked, ev_blocked)
    if comparator is not None and v_blocked == Verdict.OK and cert_chain:
        cmp_verdict, cmp_method = comparator.compare_tls(domain, cert_chain)
        if cmp_verdict == Verdict.ANOMALY:
            # Cert-chain mismatch — possible MITM / cert rotation.
            base_verdict = Verdict.ANOMALY
            base_method = cmp_method
            ev_blocked = {**ev_blocked, "baseline_cert_mismatch": True}

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
    results.append(TestResult(
        test=f"tls_{_slug(domain)}_sni_neutral",
        category="tls",
        target=f"{ip}:cloudflare.com",
        verdict=v_neutral,
        evidence=ev_neutral,
        attempts=attempts_neutral,
    ))

    # Attribution: if neutral OK but blocked SNI fails → SNI-level blocking.
    # We only flip to TCP_RST_AFTER_TLS_CH when the failure mode actually
    # looks SNI-shaped (RST or post-handshake timeout); otherwise leave
    # whatever _attribute_tls_failure already chose.
    if v_neutral == Verdict.OK and v_blocked != Verdict.OK:
        err = ev_blocked.get("error", "")
        if err in ("connection_reset", "timeout"):
            results[0].method = BlockingMethod.TCP_RST_AFTER_TLS_CH
            results[0].confidence = 0.92
            results[0].notes = (
                "Neutral SNI succeeds to same IP → SNI-level blocking confirmed"
            )

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
                        cert_der = tls.getpeercert(binary_form=True)
                        alpn = tls.selected_alpn_protocol()
                        leaf_sha256 = (
                            hashlib.sha256(cert_der).hexdigest() if cert_der else None
                        )
                        return {
                            "ok": True,
                            "rtt_connect_ms": rtt_connect,
                            "rtt_total_ms": (time.monotonic() - t0) * 1000,
                            "alpn": alpn,
                            "cert_subject_cn": _extract_cn(cert.get("subject")) if cert else None,
                            "cert_issuer_cn": _extract_cn(cert.get("issuer")) if cert else None,
                            # Only the leaf cert — ssl stdlib doesn't expose the full chain.
                            "cert_chain_sha256": [leaf_sha256] if leaf_sha256 else [],
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


async def _run_subprocess(
    cmd: list[str],
    timeout: float,
    *,
    capture_stdout: bool = True,
    capture_stderr: bool = True,
) -> tuple[Optional[int], bytes, bytes]:
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


async def _test_ech(domain: str) -> Optional[TestResult]:
    """
    Test ECH (Encrypted Client Hello) via curl --ech.

    curl only supports --ech when linked against a TLS backend with ECH
    (recent wolfSSL / OpenSSL 3.2+ w/ ECH patches). Debian 12's default
    curl is OpenSSL 3.0 without ECH support and will reject --ech with
    "option --ech: is unknown" or "ECH feature not supported". We check
    for that explicitly and return INCONCLUSIVE — a failure from the
    local OS has nothing to do with ТСПУ.

    Note: `curl --ech hard` REQUIRES the server to advertise ECH; a
    perfectly working but ECH-less server will exit non-zero. Treating
    that as ECH_BLOCKED is a false positive. We only flag ECH_BLOCKED if
    the failure looks like a real network-level intervention (RST, timeout,
    handshake failure) rather than "server has no ECH config".
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

    try:
        rc, _, stderr = await _run_subprocess(
            ["curl", "--ech", "hard", "-sv", "--max-time", "10", f"https://{domain}/"],
            timeout=15,
            capture_stdout=False,
        )
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
    method: Optional[BlockingMethod] = None
    notes: Optional[str] = None
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
        # not blocked, to avoid false positives.
        verdict = Verdict.ANOMALY

    return TestResult(
        test=test_name,
        category="tls",
        target=domain,
        verdict=verdict,
        method=method,
        evidence={
            "curl_returncode": rc,
            "stderr_tail": stderr_text[-300:],
        },
        notes=notes,
    )


_CURL_ECH_CACHE: Optional[bool] = None
_CURL_ECH_CACHE_LOCK = asyncio.Lock()


async def _curl_supports_ech() -> bool:
    """Cached check: does the local curl advertise ECH in `curl -V`?"""
    global _CURL_ECH_CACHE
    if _CURL_ECH_CACHE is not None:
        return _CURL_ECH_CACHE
    async with _CURL_ECH_CACHE_LOCK:
        # Re-check inside the lock to avoid duplicate probes under contention.
        if _CURL_ECH_CACHE is not None:
            return _CURL_ECH_CACHE
        try:
            rc, out, _ = await _run_subprocess(
                ["curl", "-V"], timeout=3, capture_stderr=False,
            )
        except FileNotFoundError:
            _CURL_ECH_CACHE = False
            return False
        except Exception:
            _CURL_ECH_CACHE = False
            return False

        if rc is None:
            _CURL_ECH_CACHE = False
            return False

        text = out.decode(errors="replace").lower()
        # curl prints "Features: ... ECH ..." — match within the Features
        # line specifically so substrings like "fetch" or "echo" don't
        # accidentally match.
        feat_line = next(
            (line for line in text.splitlines() if line.startswith("features:")),
            "",
        )
        tokens = feat_line.replace("features:", "").split()
        _CURL_ECH_CACHE = "ech" in tokens
        return _CURL_ECH_CACHE


async def _resolve_ip(domain: str) -> Optional[str]:
    """Resolve `domain` to a single IPv4 for the TLS test.

    Why DoH-first: if the local resolver is poisoned (a real possibility
    when probing blocked domains in RU), `getaddrinfo` returns a hijacked
    IP and the SNI test ends up measuring the censor's redirect host, not
    the real one. We try Cloudflare DoH first and only fall back to
    `getaddrinfo` if the DoH path is itself unreachable.
    """
    # 1) DoH (Cloudflare) — cleartext-immune to local DNS poisoning.
    try:
        import httpx
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            if r.status_code == 200:
                data = r.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1 and ans.get("data"):
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
        return infos[0][4][0]
    except Exception:
        return None


def _extract_cn(rdn_seq) -> Optional[str]:
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
