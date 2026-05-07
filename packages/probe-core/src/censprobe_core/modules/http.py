"""
modules/http.py — HTTP/HTTPS fetch and reachability classification.

Tests:
  - HTTPS fetch: status, body length, TLS reachability (handshake by httpx)
  - Geoblocking vs censorship distinction: 403/451 + valid cert → GEOBLOCK_NOT_CENSORSHIP
  - Network-level interference attribution: TLS handshake failure, RST, IP drop

Block-page fingerprinting was removed: modern Russian blocking happens at
TLS ClientHello (RST or timeout) before any HTTP-level stub can be served,
so HTML signatures fire on a vanishingly small tail of cases while still
carrying false-positive risk on news articles that mention РКН by name.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

from censprobe_core._evidence import describe_exception

from censprobe_core.config import get_config
from censprobe_core.models import BlockingMethod, TestResult, Verdict

logger = logging.getLogger(__name__)


async def run_http_tests(
    targets: list[dict[str, Any]],  # from targets/*.yaml
    repeats: int = 3,
) -> list[TestResult]:
    """Run HTTP/HTTPS tests for all targets.

    Timeouts, body cap, and concurrency cap come from
    :class:`censprobe_core.config.HttpModuleConfig`.
    """
    cfg = get_config().modules.http
    timeout = httpx.Timeout(
        connect=cfg.timeout_connect_sec,
        read=cfg.timeout_read_sec,
        write=cfg.timeout_connect_sec,
        pool=cfg.timeout_connect_sec,
    )
    sem = asyncio.Semaphore(cfg.max_parallel)

    results = []

    async with httpx.AsyncClient(
        timeout=timeout,
        http2=True,
        follow_redirects=True,
        verify=True,
    ) as client:

        async def _bounded(url: str, target: dict[str, Any]) -> TestResult:
            async with sem:
                return await _test_url(url, target, client, repeats, cfg.body_cap_bytes)

        tasks = [_bounded(url, target) for target in targets for url in target.get("urls", [])]
        results = list(await asyncio.gather(*tasks))

    return results


def _verdict_from_response(
    *,
    status: int,
    tls_ok: bool,
    expected_status: int | None,
) -> tuple[Verdict, BlockingMethod | None]:
    """Decide the HTTP verdict from response signals alone.

    Order matters:
      1. 403/451 with valid TLS → server-side geoblock, not network censorship.
      2. expected_status from targets/*.yaml → OK on match, ANOMALY otherwise.
      3. No expected_status: status==200 is OK, anything else is ANOMALY.

    Static body-length-range comparison was deliberately not implemented:
    modern sites (news, social) drift in body size between edges and
    revisions, producing false ANOMALY verdicts.
    """
    if status in (403, 451) and tls_ok:
        return Verdict.GEOBLOCK_NOT_CENSORSHIP, None
    if expected_status is not None:
        return (Verdict.OK, None) if status == expected_status else (Verdict.ANOMALY, None)
    return (Verdict.OK, None) if status == 200 else (Verdict.ANOMALY, None)


async def _attempt_url(
    url: str,
    target: dict[str, Any],
    client: httpx.AsyncClient,
    body_cap_bytes: int,
    test_name: str,
    attempt: int,
) -> TestResult:
    """Stream the URL once; httpx exceptions become final BLOCKED/ERROR results.

    Streaming (rather than ``client.get``) keeps a TSPU block-page that streams an
    ISO from OOMing us — we stop reading after ``body_cap_bytes``.
    """
    async with client.stream("GET", url, headers=_BROWSER_HEADERS) as r:
        body_length = 0
        async for chunk in r.aiter_bytes():
            body_length += len(chunk)
            if body_length >= body_cap_bytes:
                break
        status = r.status_code
        final_url = str(r.url)
        content_type = r.headers.get("content-type", "")

    # If we got here over https://, ConnectError/SSLError did NOT
    # fire, so TLS *did* succeed against the system trust store
    # (httpx.AsyncClient was constructed with verify=True). Plain
    # HTTP requests don't carry a TLS guarantee — for those tls_ok
    # is False so the 403/451 "geoblock not censorship" rule never
    # downgrades a network-injected block page on a non-TLS URL.
    tls_ok = urlparse(url).scheme == "https"

    verdict, method = _verdict_from_response(
        status=status,
        tls_ok=tls_ok,
        expected_status=target.get("expected_status"),
    )

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
            "final_url": final_url,
            "content_type": content_type,
        },
        confidence=0.9,
    )


def _classify_connect_error(
    e: httpx.ConnectError,
    url: str,
    test_name: str,
    attempt: int,
) -> TestResult:
    """Map httpx.ConnectError to BLOCKED with the right BlockingMethod."""
    err_text = describe_exception(e)
    err_msg = err_text.lower()
    if (
        isinstance(getattr(e, "__cause__", None), ssl.SSLError)
        or "ssl" in err_msg
        or "certificate" in err_msg
    ):
        return TestResult(
            test=test_name,
            category="http",
            target=url,
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.TLS_HANDSHAKE_FAILURE,
            attempts=attempt,
            evidence={"ssl_error": err_text},
        )
    if "connection reset" in err_msg:
        return TestResult(
            test=test_name,
            category="http",
            target=url,
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.TCP_RST_INJECTION,
            attempts=attempt,
            evidence={"error": err_text},
        )
    return TestResult(
        test=test_name,
        category="http",
        target=url,
        verdict=Verdict.BLOCKED,
        method=BlockingMethod.IP_DROPPED,
        attempts=attempt,
        evidence={"connect_error": err_text},
    )


async def _test_url(
    url: str,
    target: dict[str, Any],
    client: httpx.AsyncClient,
    repeats: int,
    body_cap_bytes: int,
) -> TestResult:
    """Fetch a URL and analyze the response. Retries on transient failures."""
    domain = target.get("domain", url)
    test_name = _http_test_name(domain, url)
    last_error: TestResult | None = None

    for attempt in range(1, repeats + 1):
        try:
            return await _attempt_url(url, target, client, body_cap_bytes, test_name, attempt)
        except httpx.ConnectError as e:
            # httpx wraps SSL / TCP-RST / timeout under ConnectError; classify via
            # the cause and the message. SSL- and RST-classified errors are
            # final (return immediately); IP_DROPPED is retried.
            classified = _classify_connect_error(e, url, test_name, attempt)
            if classified.method != BlockingMethod.IP_DROPPED:
                return classified
            last_error = classified
        except httpx.ConnectTimeout:
            last_error = _timeout_result(test_name, url, attempts=attempt)
        except Exception as e:
            logger.debug("HTTP test error for %s: %s", url, e)
            last_error = TestResult(
                test=test_name,
                category="http",
                target=url,
                verdict=Verdict.ERROR,
                attempts=attempt,
                evidence={"error": str(e)},
            )

        if attempt < repeats:
            await asyncio.sleep(2)

    return last_error or _timeout_result(test_name, url, attempts=repeats)


def _http_test_name(domain: str, url: str) -> str:
    """Build a stable, unique test name for a given (domain, url) pair.

    A target in YAML can list multiple URLs for the same domain (e.g.
    twitter.com + x.com under domain="twitter.com", or ru/en wikipedia.org),
    and using slug(domain) alone collides them on the same Postgres key.

    The canonical form ``https://<domain>/`` keeps the bare ``http_<slug>``
    name so existing dashboards and saved baselines don't break. Any other
    URL gets a 6-char content hash suffix — stable across runs, unaffected
    by reordering URLs in YAML.
    """
    base = f"http_{_slug(domain)}"
    parsed = urlparse(url)
    is_canonical = (
        parsed.scheme == "https"
        and parsed.hostname == domain
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    )
    if is_canonical:
        return base
    # 6-char SHA-1 prefix is a stable label for grouping per-URL results in
    # Grafana, not a security primitive. usedforsecurity=False signals that
    # to ruff/bandit (S324) and to FIPS-restricted hosts where SHA-1 is
    # blocked for crypto use but still permitted for hashing.
    suffix = hashlib.sha1(url.encode("utf-8"), usedforsecurity=False).hexdigest()[:6]
    return f"{base}__{suffix}"


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


# Full Chrome-on-Windows fingerprint for top-level navigation GETs.
#
# The goal is to measure what a real user with a real browser sees, not
# what an "honest probe" sees. A bare Chrome UA without the matching
# client hints (sec-ch-ua*) and sec-fetch-* set fails Meta's anti-bot
# inconsistency check (Facebook/WhatsApp return 400), so the full set is
# load-bearing — drop any one header and we drift back toward false
# ANOMALY verdicts on those sites.
#
# Maintenance: refresh the Chrome major version (UA + sec-ch-ua) every
# ~6 months. Stale versions become a fingerprint of their own and start
# tripping the same heuristics we are trying to pass.
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "sec-ch-ua": '"Chromium";v="145", "Google Chrome";v="145", "Not?A_Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Upgrade-Insecure-Requests": "1",
}


def _slug(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").replace("/", "_").lower()
