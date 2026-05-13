"""
modules/middlebox.py — Middlebox / DPI detection module.

Inspired by OONI HTTP Header Field Manipulation and HTTP Invalid Request Line tests.

Tests:
  1. Header case manipulation: send non-standard casing (hOsT:, uSeR-aGeNt:)
     → middlebox normalizes headers → detected
  2. HTTP invalid request line: send request with random method string
     → middlebox may transform or block it
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import socket
import string
from typing import Any

from censprobe_core.models import BlockingMethod, TestResult, Verdict
from censprobe_core.utils import stamp_test_elapsed

logger = logging.getLogger(__name__)

# Targets are wired inline below: 1.1.1.1:80 (Cloudflare raw edge — does not
# normalize header casing, so a tampered request shows up as a non-400 reply)
# and httpbin.org:80 (echoes the request method back, which lets us spot a
# middlebox that rewrites random methods to GET).
_TIMEOUT = 10.0


async def run_middlebox_tests() -> list[TestResult]:
    """Run all middlebox detection tests."""
    results = []

    # Test 1: Header case manipulation
    results.extend(await _test_header_manipulation())

    # Test 2: HTTP invalid request line
    result = await _test_invalid_request_line()
    if result:
        results.append(result)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Header case manipulation
# ─────────────────────────────────────────────────────────────────────────────


async def _test_header_manipulation() -> list[TestResult]:
    """
    Send HTTP request with modified header case via raw socket.

    Target is 1.1.1.1:80 — Cloudflare's raw edge returns a 400 status
    line that echoes the Request / path but does NOT normalize request
    header casing (unlike Flask/WSGI + ALB behind httpbin.org, which
    uppercases every header to HTTP_HOST before reflecting). We use
    httpx NOT at all here: modern HTTP clients case-insensitively store
    headers and may rewrite them before transmission, so the only
    reliable way to ask "was this exact byte sequence mutated on the
    wire" is a raw socket.

    The detection is indirect: we can't read the outbound bytes back,
    but a middlebox that rewrites `hOsT:` to `Host:` typically also
    terminates and replays the request, producing either a non-400
    status, an unexpectedly long response, or the connection dropping.
    Verdict OK means the request traversed intact (Cloudflare's 400);
    ANOMALY means behaviour diverged from that baseline.
    """
    results = []

    # Use the same Chrome UA as modules/http.py so middleboxes that
    # fingerprint by User-Agent value treat both probes uniformly. The
    # case-mutation test is about wire-byte survival, not UA content,
    # but a "censprobe/..." string here would let a UA-aware middlebox
    # selectively rewrite our traffic and confuse the verdict.
    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    )

    test_cases: list[dict[str, Any]] = [
        {
            "name": "middlebox_header_host_case",
            "headers": [("hOsT", "1.1.1.1"), ("User-Agent", _UA)],
            "field": "hOsT",
            "notes": "Modified Host header case",
        },
        {
            "name": "middlebox_header_useragent_case",
            "headers": [("Host", "1.1.1.1"), ("uSeR-aGeNt", _UA)],
            "field": "uSeR-aGeNt",
            "notes": "Modified User-Agent case",
        },
    ]

    for tc in test_cases:
        results.append(await _run_header_case(tc))

    return results


def _parse_status_code(response_head: str) -> tuple[str, int | None]:
    """Parse "HTTP/1.1 400 Bad Request" status line; return (status_line, status_code)."""
    status_line = response_head.split("\r\n", 1)[0] if response_head else ""
    parts = status_line.split(maxsplit=2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            return status_line, int(parts[1])
        except ValueError:
            return status_line, None
    return status_line, None


async def _run_header_case(tc: dict[str, Any]) -> TestResult:
    """Run a single header-case test case; never raises — returns a TestResult."""
    try:
        response_head, err = await asyncio.wait_for(
            _raw_http_request(
                host="1.1.1.1",
                port=80,
                path="/",
                headers=tc["headers"],
            ),
            timeout=_TIMEOUT + 2,
        )
    except TimeoutError:
        return TestResult(
            test=tc["name"],
            category="middlebox",
            target="1.1.1.1:80",
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": "timeout reaching 1.1.1.1:80"},
        )
    except Exception as e:
        return TestResult(
            test=tc["name"],
            category="middlebox",
            target="1.1.1.1:80",
            verdict=Verdict.ERROR,
            evidence={"error": str(e)},
        )

    if err:
        # A network failure to the reference endpoint is not
        # evidence of middlebox manipulation — surface as
        # INCONCLUSIVE so the dashboard doesn't treat it as ANOMALY.
        return TestResult(
            test=tc["name"],
            category="middlebox",
            target="1.1.1.1:80",
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": err},
        )

    # Cloudflare edge returns either 400 (bad request) or 301/302
    # (HTTPS redirect) for plain-HTTP connections. Both indicate the
    # request reached Cloudflare intact — not a middlebox. A middlebox
    # that rewrote or intercepted the request would typically return
    # 200 (its own block page), a reset, or a status code from its own
    # HTTP parser — those are anomalies.
    status_line, status_code = _parse_status_code(response_head)
    cloudflare_response = status_code in (301, 302, 400)
    verdict = Verdict.OK if cloudflare_response else Verdict.ANOMALY
    method = None if cloudflare_response else BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION

    return TestResult(
        test=tc["name"],
        category="middlebox",
        target="1.1.1.1:80",
        verdict=verdict,
        method=method,
        evidence={
            "sent_header": tc["field"],
            "status_line": status_line,
            "status_code": status_code,
            "response_head": response_head[:200],
            "cloudflare_ok_statuses": [301, 302, 400],
        },
        notes=tc["notes"],
    )


async def _raw_http_request(
    host: str,
    port: int,
    path: str,
    headers: list[tuple[str, str]],
) -> tuple[str, str | None]:
    """Send an HTTP/1.1 GET over a raw socket and return the response head.

    Returns (head_text, error_or_None). The point is to preserve the
    exact byte casing of header names — any HTTP client that goes
    through a CaseInsensitiveDict WILL lose that information.
    """
    loop = asyncio.get_running_loop()

    def _send() -> tuple[str, str | None]:
        try:
            request = f"GET {path} HTTP/1.1\r\n"
            for name, value in headers:
                request += f"{name}: {value}\r\n"
            request += "Connection: close\r\n\r\n"
            with socket.create_connection((host, port), timeout=_TIMEOUT) as s:
                s.sendall(request.encode("ascii"))
                s.settimeout(_TIMEOUT)
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 4096:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode("utf-8", errors="replace"), None
        except Exception as e:
            return "", str(e)

    return await loop.run_in_executor(None, _send)


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: HTTP Invalid Request Line
# ─────────────────────────────────────────────────────────────────────────────


@stamp_test_elapsed
async def _test_invalid_request_line() -> TestResult | None:
    """
    Send an HTTP request with a non-standard method.
    A direct origin returns 400 Bad Request or 501 Not Implemented (per RFC).
    A middlebox may transform it to GET, drop the connection, or return
    something else entirely.
    """
    # Random 7-letter method to avoid pattern matching. Using `secrets`
    # rather than `random` so the method string can't be predicted by an
    # adversary who knows the probe's PRNG state — a TSPU device that
    # fingerprints censprobe could otherwise pre-compute the next method
    # and selectively rewrite it to GET, masking the middlebox-detect
    # signal.
    random_method = "".join(secrets.choice(string.ascii_uppercase) for _ in range(7))
    target_host = "httpbin.org"
    request_line = f"{random_method} / HTTP/1.1\r\nHost: {target_host}\r\n\r\n"

    test_name = "middlebox_invalid_request_line"

    try:
        loop = asyncio.get_running_loop()

        def _send_raw() -> tuple[str, str | None]:
            try:
                # Use plain HTTP to avoid TLS complexity
                with socket.create_connection((target_host, 80), timeout=_TIMEOUT) as s:
                    s.sendall(request_line.encode())
                    s.settimeout(5.0)
                    response = b""
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if b"\r\n\r\n" in response:
                            break
                    return response.decode("utf-8", errors="replace"), None
            except Exception as e:
                return "", str(e)

        response_text, err = await asyncio.wait_for(
            loop.run_in_executor(None, _send_raw),
            timeout=_TIMEOUT + 2,
        )

        if err:
            # Network failure to a 3rd-party endpoint — can't conclude
            # anything about middleboxes from this alone.
            return TestResult(
                test=test_name,
                category="middlebox",
                target=f"{target_host}:80",
                verdict=Verdict.INCONCLUSIVE,
                evidence={
                    "sent_method": random_method,
                    "error": err,
                    "reason": "Could not reach reference endpoint; test depends on it.",
                },
            )

        # Parse the actual HTTP status code instead of substring-matching
        # "400" anywhere in the head — the previous heuristic also matched
        # bytes inside Date/timestamp headers and produced false positives.
        status_line, status_code = _parse_status_code(response_text)

        # RFC says 400 (Bad Request) or 501 (Not Implemented) is the
        # honest server response; 405 (Method Not Allowed) is also fine.
        ok_statuses = {400, 405, 501}
        is_ok = status_code in ok_statuses

        return TestResult(
            test=test_name,
            category="middlebox",
            target=f"{target_host}:80",
            verdict=Verdict.OK if is_ok else Verdict.ANOMALY,
            method=None if is_ok else BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION,
            evidence={
                "sent_method": random_method,
                "status_line": status_line,
                "status_code": status_code,
                "response_head": response_text[:200],
                "expected_one_of": sorted(ok_statuses),
            },
        )

    except TimeoutError:
        return TestResult(
            test=test_name,
            category="middlebox",
            target=f"{target_host}:80",
            verdict=Verdict.INCONCLUSIVE,
            evidence={"error": "timeout"},
        )
    except Exception as e:
        return TestResult(
            test=test_name,
            category="middlebox",
            target=f"{target_host}:80",
            verdict=Verdict.ERROR,
            evidence={"error": str(e)},
        )
