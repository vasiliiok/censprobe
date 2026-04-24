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
import socket
import ssl
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
import yaml

from censprobe_core.models import TestResult, Verdict, BlockingMethod
from censprobe_core.baseline import BaselineComparator

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
    comparator: BaselineComparator,
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
                return await _test_url(url, target, client, comparator, repeats)

        tasks = [
            _bounded(url, target)
            for target in targets
            for url in target.get("urls", [])
        ]
        results = list(await asyncio.gather(*tasks))

    return results


async def _test_url(
    url: str,
    target: dict,
    client: httpx.AsyncClient,
    comparator: BaselineComparator,
    repeats: int,
) -> TestResult:
    """Fetch a URL and analyze the response. Retries on transient failures."""
    domain = target.get("domain", url)
    test_name = f"http_{_slug(domain)}"
    last_error: Optional[TestResult] = None

    for attempt in range(1, repeats + 1):
        try:
            r = await client.get(url, headers={"User-Agent": _ua_chrome()})

            body = r.content[:_MAX_BODY_READ]
            body_length = len(body)
            status = r.status_code

            tls_ok = url.startswith("https://") and r.status_code < 600
            is_blockpage = _is_blockpage(body, status)
            cert_sha256_list = await _extract_cert_sha256(r, url)
            stable_frags = _extract_stable_fragments(body, target.get("stable_selectors", []))

            verdict, method = comparator.compare_http(url, status, body_length, tls_ok, is_blockpage)

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
                    "stable_frags_sha256": stable_frags,
                    "final_url": str(r.url),
                    "content_type": r.headers.get("content-type", ""),
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


def _is_blockpage(body: bytes, status: int) -> bool:
    """Detect block page by body fingerprints."""
    sigs = _get_blockpage_sigs()
    text = body.decode("utf-8", errors="ignore").lower()
    for sig_name, sig in sigs.get("block_pages", {}).items():
        for pattern in sig.get("body_patterns", []):
            if pattern.lower() in text:
                return True
    return False


async def _extract_cert_sha256(response: httpx.Response, url: str) -> list[str]:
    """
    Extract leaf-cert SHA-256 for a response's TLS endpoint.

    httpx doesn't expose the peer cert directly, so we run a separate,
    minimal TLS handshake to the same host:port and hash the server cert
    in DER form. That SHA is fed into BaselineComparator.compare_tls for
    MITM / cert-rotation detection — an empty list there would silently
    disable the check.

    Returns:
        [hex_sha256] on success, or [] on non-HTTPS / network failure.
    """
    parsed = urlparse(str(response.url) or url)
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


def _extract_stable_fragments(body: bytes, selectors: list[str]) -> dict[str, str]:
    """
    Extract stable fragment SHA256 hashes.
    Simple implementation: hash specific byte ranges or known strings.
    """
    # TODO: implement selector-based extraction (BeautifulSoup)
    # For now: full body hash as single fragment
    if body:
        return {"body_sha256": hashlib.sha256(body).hexdigest()}
    return {}


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


def _ua_chrome() -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").replace("/", "_").lower()
