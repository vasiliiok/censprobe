"""
modules/middlebox.py — Middlebox / DPI detection module.

Inspired by OONI HTTP Header Field Manipulation and HTTP Invalid Request Line tests.

Tests:
  1. Header case manipulation: send non-standard casing (hOsT:, uSeR-aGeNt:)
     → middlebox normalizes headers → detected
  2. HTTP invalid request line: send request with random method string
     → middlebox may transform or block it
  3. TCP fragmentation: send TLS ClientHello split across 2 TCP segments
     → some DPI fails to reassemble and allows/blocks inconsistently
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import string
from typing import Optional

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

# Echo server on control-point that reflects back all headers as-is
# For initial M1 implementation, we use httpbin.org as fallback
_ECHO_URL = "https://httpbin.org/headers"
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

    # Test 3: TCP fragmentation of TLS ClientHello
    result = await _test_tcp_fragmentation()
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

    test_cases = [
        {
            "name": "middlebox_header_host_case",
            "headers": [("hOsT", "1.1.1.1"), ("User-Agent", "censprobe/0.1")],
            "field": "hOsT",
            "notes": "Modified Host header case",
        },
        {
            "name": "middlebox_header_useragent_case",
            "headers": [("Host", "1.1.1.1"), ("uSeR-aGeNt", "censprobe/0.1")],
            "field": "uSeR-aGeNt",
            "notes": "Modified User-Agent case",
        },
    ]

    for tc in test_cases:
        try:
            response_head, err = await _raw_http_request(
                host="1.1.1.1", port=80, path="/",
                headers=tc["headers"],
            )
            if err:
                results.append(TestResult(
                    test=tc["name"], category="middlebox", target="1.1.1.1:80",
                    verdict=Verdict.ERROR, evidence={"error": err},
                ))
                continue

            # Cloudflare edge returns "HTTP/1.1 400 Bad Request" for a Host
            # header that doesn't match a served domain. A middlebox that
            # rewrote the request commonly yields a 200, redirect, or TCP
            # reset — any of those are anomalies.
            status_line = response_head.split("\r\n", 1)[0] if response_head else ""
            got_400 = status_line.startswith("HTTP/1.1 400") or status_line.startswith("HTTP/1.0 400")
            verdict = Verdict.OK if got_400 else Verdict.ANOMALY
            method = None if got_400 else BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION

            results.append(TestResult(
                test=tc["name"],
                category="middlebox",
                target="1.1.1.1:80",
                verdict=verdict,
                method=method,
                evidence={
                    "sent_header": tc["field"],
                    "status_line": status_line,
                    "response_head": response_head[:200],
                    "baseline_expected": "HTTP/1.1 400",
                },
                notes=tc["notes"],
            ))
        except Exception as e:
            results.append(TestResult(
                test=tc["name"], category="middlebox", target="1.1.1.1:80",
                verdict=Verdict.ERROR, evidence={"error": str(e)},
            ))

    return results


async def _raw_http_request(
    host: str,
    port: int,
    path: str,
    headers: list[tuple[str, str]],
) -> tuple[str, Optional[str]]:
    """Send an HTTP/1.1 GET over a raw socket and return the response head.

    Returns (head_text, error_or_None). The point is to preserve the
    exact byte casing of header names — any HTTP client that goes
    through a CaseInsensitiveDict WILL lose that information.
    """
    loop = asyncio.get_running_loop()

    def _send() -> tuple[str, Optional[str]]:
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

async def _test_invalid_request_line() -> Optional[TestResult]:
    """
    Send an HTTP request with a non-standard method.
    A middlebox may transform or forward it; a direct server would 400.
    """
    # Random 7-letter method to avoid pattern matching
    random_method = "".join(random.choices(string.ascii_uppercase, k=7))
    request_line = f"{random_method} / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"

    test_name = "middlebox_invalid_request_line"

    try:
        loop = asyncio.get_running_loop()

        def _send_raw():
            try:
                # Use plain HTTP to avoid TLS complexity
                with socket.create_connection(("httpbin.org", 80), timeout=_TIMEOUT) as s:
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
                    return response.decode("utf-8", errors="replace")
            except Exception as e:
                return str(e)

        response_text = await asyncio.wait_for(
            loop.run_in_executor(None, _send_raw),
            timeout=_TIMEOUT + 2,
        )

        # A proper server returns 400 Bad Request or 405 Method Not Allowed
        # A middlebox might transform to GET or return something else
        is_400 = "400" in response_text[:100] or "405" in response_text[:100]

        return TestResult(
            test=test_name,
            category="middlebox",
            target="httpbin.org:80",
            verdict=Verdict.OK if is_400 else Verdict.ANOMALY,
            method=BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION if not is_400 else None,
            evidence={
                "sent_method": random_method,
                "response_head": response_text[:200],
                "expected_400_or_405": is_400,
            },
        )

    except Exception as e:
        return TestResult(
            test=test_name, category="middlebox", target="httpbin.org:80",
            verdict=Verdict.ERROR, evidence={"error": str(e)},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: TCP Fragmentation of TLS ClientHello
# ─────────────────────────────────────────────────────────────────────────────

async def _test_tcp_fragmentation() -> Optional[TestResult]:
    """
    TCP-fragmentation circumvention test.

    A real implementation would craft a TLS ClientHello split across two
    TCP segments (either via raw sockets / Scapy or via the kernel socket
    buffer with TCP_NODELAY + tiny send chunks) and compare reachability
    with and without the split, to detect middleboxes that fail to
    reassemble.

    That is NOT what this MVP does. Returning Verdict.OK from a plain
    `tls_sock.do_handshake()` would be actively misleading — it would
    suggest that fragmentation-based circumvention works when no
    fragmentation has been exercised at all. We therefore return
    INCONCLUSIVE with a clear "not_implemented_in_mvp" marker so the
    dashboard reflects reality.
    """
    test_name = "middlebox_tcp_fragmentation"
    target_host = "cloudflare.com"
    return TestResult(
        test=test_name,
        category="middlebox",
        target=f"{target_host}:443",
        verdict=Verdict.INCONCLUSIVE,
        confidence=0.0,
        evidence={
            "status": "not_implemented_in_mvp",
            "reason": (
                "Real TCP fragmentation requires raw-socket or low-level "
                "send-chunk control; the previous placeholder only ran a "
                "normal TLS handshake and was misleading."
            ),
        },
        notes="TCP fragmentation circumvention not implemented in MVP.",
    )
