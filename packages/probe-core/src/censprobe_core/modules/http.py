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
from urllib.parse import urlparse

import httpx

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
# Cap response read so a misbehaving server can't OOM the probe by streaming
# an ISO under a TSPU block-page response. Body bytes themselves are no longer
# inspected (block-page fingerprinting is gone) — we only record body_length
# as a forensic signal.
_MAX_BODY_READ = 512 * 1024
_MAX_PARALLEL = 8            # concurrency cap for HTTP probes


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


async def _test_url(
    url: str,
    target: dict,
    client: httpx.AsyncClient,
    repeats: int,
) -> TestResult:
    """Fetch a URL and analyze the response. Retries on transient failures."""
    domain = target.get("domain", url)
    test_name = _http_test_name(domain, url)
    last_error: TestResult | None = None

    for attempt in range(1, repeats + 1):
        try:
            # Stream and count bytes only (don't buffer) — httpx.get() would
            # buffer the whole body into RAM, and a TSPU block-page streaming
            # an ISO would OOM us. We stop reading after _MAX_BODY_READ.
            async with client.stream(
                "GET", url, headers={"User-Agent": _ua_probe()}
            ) as r:
                body_length = 0
                async for chunk in r.aiter_bytes():
                    body_length += len(chunk)
                    if body_length >= _MAX_BODY_READ:
                        break
                status = r.status_code
                final_url = str(r.url)
                content_type = r.headers.get("content-type", "")

            # If we got here over https://, ConnectError/SSLError did NOT
            # fire, so TLS *did* succeed. Reusing that boolean below for the
            # "geoblock vs censorship" attribution.
            tls_ok = url.startswith("https://")

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
    suffix = hashlib.sha1(url.encode("utf-8")).hexdigest()[:6]
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
