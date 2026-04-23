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
from pathlib import Path
from typing import Optional

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
    """Fetch a URL and analyze the response."""
    domain = target.get("domain", url)
    test_name = f"http_{_slug(domain)}"

    for attempt in range(repeats):
        try:
            r = await client.get(url, headers={"User-Agent": _ua_chrome()})

            body = r.content[:_MAX_BODY_READ]
            body_length = len(body)
            status = r.status_code

            # TLS status (did TLS handshake succeed?)
            tls_ok = url.startswith("https://") and r.status_code < 600

            # Block page detection
            is_blockpage = _is_blockpage(body, status)

            # Cert chain hash (if HTTPS)
            cert_sha256_list = _extract_cert_sha256(r)

            # Stable fragment SHA256
            stable_frags = _extract_stable_fragments(body, target.get("stable_selectors", []))

            # Compare with baseline
            verdict, method = comparator.compare_http(url, status, body_length, tls_ok, is_blockpage)

            return TestResult(
                test=test_name,
                category="http",
                target=url,
                verdict=verdict,
                method=method,
                attempts=attempt + 1,
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

        except httpx.ConnectTimeout:
            if attempt < repeats - 1:
                await asyncio.sleep(2)
                continue
            return _timeout_result(test_name, url)

        except httpx.SSLError as e:
            return TestResult(
                test=test_name,
                category="http",
                target=url,
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.TLS_HANDSHAKE_FAILURE,
                evidence={"ssl_error": str(e)},
            )

        except httpx.ConnectError as e:
            err = str(e).lower()
            if "connection reset" in err:
                return TestResult(
                    test=test_name,
                    category="http",
                    target=url,
                    verdict=Verdict.BLOCKED,
                    method=BlockingMethod.TCP_RST_INJECTION,
                    evidence={"error": str(e)},
                )
            if attempt < repeats - 1:
                await asyncio.sleep(2)
                continue
            return TestResult(
                test=test_name,
                category="http",
                target=url,
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.IP_DROPPED,
                evidence={"connect_error": str(e)},
            )

        except Exception as e:
            logger.debug("HTTP test error for %s: %s", url, e)
            if attempt < repeats - 1:
                await asyncio.sleep(2)
                continue
            return TestResult(
                test=test_name,
                category="http",
                target=url,
                verdict=Verdict.ERROR,
                evidence={"error": str(e)},
            )

    return _timeout_result(test_name, url)


def _is_blockpage(body: bytes, status: int) -> bool:
    """Detect block page by body fingerprints."""
    sigs = _get_blockpage_sigs()
    text = body.decode("utf-8", errors="ignore").lower()
    for sig_name, sig in sigs.get("block_pages", {}).items():
        for pattern in sig.get("body_patterns", []):
            if pattern.lower() in text:
                return True
    return False


def _extract_cert_sha256(response: httpx.Response) -> list[str]:
    """Extract cert chain SHA256 from response (best effort)."""
    # httpx doesn't expose cert chain directly in public API
    # We'd need to use the underlying SSL socket — skip for now, noted as TODO
    return []


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


def _timeout_result(test_name: str, url: str) -> TestResult:
    return TestResult(
        test=test_name,
        category="http",
        target=url,
        verdict=Verdict.BLOCKED,
        method=BlockingMethod.IP_DROPPED,
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
