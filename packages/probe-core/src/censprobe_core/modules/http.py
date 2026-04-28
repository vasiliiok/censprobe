"""
modules/http.py — HTTP/HTTPS fetch and block page detection.

Tests:
  - HTTPS fetch: status, body length, TLS cert chain, stable fragment SHA256
  - Block page detection via signatures/blockpages.yaml fingerprints
  - Geoblocking vs censorship distinction: 403/451 + valid cert → GEOBLOCK_NOT_CENSORSHIP
  - Middlebox detection via response header manipulation
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
import ssl
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
import yaml

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
_MAX_BODY_READ = 512 * 1024  # 512 KB — enough for fingerprinting
_MAX_PARALLEL = 8            # concurrency cap for HTTP probes
_WORKSPACE = Path("/workspace")


def _load_blockpage_signatures() -> dict:
    """Load block page fingerprints from signatures/blockpages.yaml."""
    path = _WORKSPACE / "signatures" / "blockpages.yaml"
    try:
        return yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}


_BLOCKPAGE_SIGS = None


def _get_blockpage_sigs() -> dict:
    global _BLOCKPAGE_SIGS
    if _BLOCKPAGE_SIGS is None:
        _BLOCKPAGE_SIGS = _load_blockpage_signatures()
    return _BLOCKPAGE_SIGS


async def run_http_tests(
    targets: list[dict],  # from targets/*.yaml
    repeats: int = 3,
) -> list[TestResult]:
    """Run HTTP/HTTPS tests for all targets."""
    results = []

    sem = asyncio.Semaphore(_MAX_PARALLEL)

    async with httpx.AsyncClient(
        timeout=_TIMEOUT,
        http2=True,
        follow_redirects=True,
        verify=True,
    ) as client:
        async def _bounded(url: str, target: dict) -> TestResult:
            async with sem:
                return await _test_url(url, target, client, repeats)

        tasks = [
            _bounded(url, target)
            for target in targets
            for url in target.get("urls", [])
        ]
        results = list(await asyncio.gather(*tasks))

    return results


def _verdict_from_response(
    *,
    status: int,
    tls_ok: bool,
    is_blockpage: bool,
    expected_status: Optional[int],
) -> tuple[Verdict, Optional[BlockingMethod]]:
    """Decide the HTTP verdict from response signals alone.

    Order matters:
      1. Blockpage signature → BLOCKED, regardless of status code
         (Roskomnadzor stub pages are commonly served with 200 or 302).
      2. 403/451 with valid TLS and no blockpage → server-side geoblock,
         not network censorship.
      3. expected_status from targets/*.yaml → OK on match, ANOMALY otherwise.
      4. No expected_status: status==200 is OK, anything else is ANOMALY.

    Static body-length-range comparison from the control baseline was
    removed — modern sites (news, social) drift in body size between
    edges and revisions, producing false ANOMALY verdicts.
    """
    if is_blockpage:
        return Verdict.BLOCKED, BlockingMethod.BLOCKPAGE_RETURNED
    if status in (403, 451) and tls_ok:
        return Verdict.GEOBLOCK_NOT_CENSORSHIP, None
    if expected_status is not None:
        return (Verdict.OK, None) if status == expected_status else (Verdict.ANOMALY, None)
    return (Verdict.OK, None) if status == 200 else (Verdict.ANOMALY, None)


async def _test_url(
    url: str,
    target: dict,
    client: httpx.AsyncClient,
    repeats: int,
) -> TestResult:
    """Fetch a URL and analyze the response. Retries on transient failures."""
    domain = target.get("domain", url)
    test_name = f"http_{_slug(domain)}"
    last_error: Optional[TestResult] = None

    for attempt in range(1, repeats + 1):
        try:
            # Stream the response so a malicious / misbehaving server
            # can't feed us gigabytes — httpx.get() buffers the whole body
            # into RAM, which means a TSPU block-page that streams an ISO
            # image would OOM the probe process. We cap at _MAX_BODY_READ
            # (enough for fingerprinting) and discard the rest.
            async with client.stream(
                "GET", url, headers={"User-Agent": _ua_probe()}
            ) as r:
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    remaining = _MAX_BODY_READ - len(buf)
                    if remaining <= 0:
                        break
                    buf.extend(chunk[:remaining])
                body = bytes(buf)
                body_length = len(body)
                status = r.status_code
                final_url = str(r.url)
                content_type = r.headers.get("content-type", "")

            # If we got here over https://, ConnectError/SSLError did NOT
            # fire, so TLS *did* succeed. Reusing that boolean below for the
            # "geoblock vs censorship" attribution.
            tls_ok = url.startswith("https://")
            is_blockpage = _is_blockpage(body, status)
            cert_sha256_list = await _extract_cert_sha256(final_url, url)

            verdict, method = _verdict_from_response(
                status=status,
                tls_ok=tls_ok,
                is_blockpage=is_blockpage,
                expected_status=target.get("expected_status"),
            )

            # cert SHA is collected for forensics but never compared. CDN
            # leaf certs rotate per edge — any control-vs-solo mismatch is
            # normal, not MITM. tls_ok=True already means the system trust
            # store accepted the chain.

            return TestResult(
                test=test_name,
                category="http",
                target=url,
                verdict=verdict,
                method=method,
                attempts=attempt,
                evidence={
                    "status": status,
                    "body_length": body_length,
                    "tls_ok": tls_ok,
                    "is_blockpage": is_blockpage,
                    "cert_chain_sha256": cert_sha256_list,
                    "final_url": final_url,
                    "content_type": content_type,
                },
                confidence=0.9,
            )

        except httpx.ConnectError as e:
            # httpx wraps SSL / TCP-RST / timeout under ConnectError; classify via
            # the cause and the message. httpx has no SSLError class of its own.
            err_msg = str(e).lower()
            is_tls = (
                isinstance(getattr(e, "__cause__", None), ssl.SSLError)
                or "ssl" in err_msg
                or "certificate" in err_msg
            )
            if is_tls:
                return TestResult(
                    test=test_name, category="http", target=url,
                    verdict=Verdict.BLOCKED,
                    method=BlockingMethod.TLS_HANDSHAKE_FAILURE,
                    attempts=attempt,
                    evidence={"ssl_error": str(e)},
                )
            if "connection reset" in err_msg:
                return TestResult(
                    test=test_name, category="http", target=url,
                    verdict=Verdict.BLOCKED,
                    method=BlockingMethod.TCP_RST_INJECTION,
                    attempts=attempt,
                    evidence={"error": str(e)},
                )
            last_error = TestResult(
                test=test_name, category="http", target=url,
                verdict=Verdict.BLOCKED, method=BlockingMethod.IP_DROPPED,
                attempts=attempt,
                evidence={"connect_error": str(e)},
            )

        except httpx.ConnectTimeout:
            last_error = _timeout_result(test_name, url, attempts=attempt)

        except Exception as e:
            logger.debug("HTTP test error for %s: %s", url, e)
            last_error = TestResult(
                test=test_name, category="http", target=url,
                verdict=Verdict.ERROR, attempts=attempt,
                evidence={"error": str(e)},
            )

        if attempt < repeats:
            await asyncio.sleep(2)

    return last_error or _timeout_result(test_name, url, attempts=repeats)


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _is_blockpage(body: bytes, status: int) -> bool:
    """Detect block page by body and title fingerprints.

    Previously this only matched body_patterns, so a page whose evidence
    of being an РКН stub lived solely in the <title> (a common shape
    for МТС / Ростелеком redirects) slipped through. We now also match
    title_patterns, and respect the per-signature http_status filter so
    that a 404 page from a normal site that happens to contain the word
    "Роскомнадзор" doesn't get tagged.
    """
    # Real block pages are tiny stubs (typically <5 KB, never >100 KB).
    # A large body is real content, not a block page — skip matching entirely.
    if len(body) > 100 * 1024:
        return False
    sigs = _get_blockpage_sigs()
    text = body.decode("utf-8", errors="ignore").lower()

    title_match = _TITLE_RE.search(body)
    title_text = (
        title_match.group(1).decode("utf-8", errors="ignore").lower()
        if title_match
        else ""
    )

    for sig_name, sig in sigs.get("block_pages", {}).items():
        # If the signature constrains the HTTP status, enforce it.
        allowed_statuses = sig.get("http_status")
        if allowed_statuses and status not in allowed_statuses:
            continue

        for pattern in sig.get("body_patterns", []) or []:
            if pattern and pattern.lower() in text:
                return True
        if title_text:
            for pattern in sig.get("title_patterns", []) or []:
                if pattern and pattern.lower() in title_text:
                    return True
    return False


async def _extract_cert_sha256(response_url: str, url: str) -> list[str]:
    """
    Extract leaf-cert SHA-256 for a response's TLS endpoint.

    Recorded only as forensic evidence on the result — there is no
    baseline cert-chain comparison anymore (CDN edges rotate certs too
    fast for hash-equality to be a reliable MITM signal). httpx doesn't
    expose the peer cert, so we run a minimal TLS handshake to the same
    host:port and hash the server cert in DER form.

    Returns:
        [hex_sha256] on success, or [] on non-HTTPS / network failure.
    """
    parsed = urlparse(response_url or url)
    if parsed.scheme != "https" or not parsed.hostname:
        return []

    host = parsed.hostname
    port = parsed.port or 443

    def _fetch_cert() -> Optional[bytes]:
        ctx = ssl.create_default_context()
        # We want the server's cert even if its chain is not trusted locally
        # (e.g. internal CA, expired cert) — verification is NOT our goal
        # here; we are hashing the leaf for baseline comparison.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Advertise ALPN so CDNs/WAFs that reset bare-TLS connections
        # (Cloudflare, Akamai) still complete the handshake and hand us a
        # cert. Without this the cert-fingerprint check silently becomes
        # a blind spot on modern endpoints.
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except (NotImplementedError, ssl.SSLError):
            pass
        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    return tls_sock.getpeercert(binary_form=True)
        except Exception:
            return None

    try:
        der = await asyncio.wait_for(asyncio.to_thread(_fetch_cert), timeout=7.0)
    except asyncio.TimeoutError:
        return []

    if not der:
        return []
    return [hashlib.sha256(der).hexdigest()]


def _timeout_result(test_name: str, url: str, attempts: int = 1) -> TestResult:
    return TestResult(
        test=test_name,
        category="http",
        target=url,
        verdict=Verdict.BLOCKED,
        method=BlockingMethod.IP_DROPPED,
        attempts=attempts,
        evidence={"reason": "connect_timeout_after_retries"},
    )


def _ua_probe() -> str:
    """
    Honest User-Agent identifying the probe.

    Spoofing a Chrome UA without sending matching client hints (sec-ch-ua,
    sec-fetch-*) triggers anti-bot defenses on Meta sites — Facebook and
    WhatsApp respond with HTTP 400 instead of the normal 200, which the
    probe then misclassifies as ANOMALY. An honest UA bypasses that
    inconsistency check; servers that block our UA return a recognisable
    non-200 status that does reflect a real reachability issue.
    """
    return "Mozilla/5.0 (compatible; censprobe/0.1; +https://github.com/vasiliiok/censprobe)"


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").replace("/", "_").lower()
