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
    Send HTTP request with modified header case.
    A middlebox will normalize 'hOsT:' to 'Host:' — detectable in reflected response.
    """
    results = []

    test_cases = [
        {
            "name": "middlebox_header_host_case",
            "headers": {"hOsT": "httpbin.org", "User-Agent": "censprobe/0.1"},
            "field": "hOsT",
            "notes": "Modified Host header case",
        },
        {
            "name": "middlebox_header_useragent_case",
            "headers": {"Host": "httpbin.org", "uSeR-aGeNt": "censprobe/0.1"},
            "field": "uSeR-aGeNt",
            "notes": "Modified User-Agent case",
        },
    ]

    import httpx

    for tc in test_cases:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(_TIMEOUT)) as client:
                r = await client.get(_ECHO_URL, headers=tc["headers"])

                if r.status_code == 200:
                    reflected = r.json().get("headers", {})
                    # Check if the modified-case header was normalized by a middlebox
                    original_key = tc["field"]
                    normalized_key = original_key.lower().replace("-", " ").title().replace(" ", "-")

                    is_normalized = normalized_key in reflected and original_key not in reflected

                    middlebox_detected = is_normalized
                    verdict = Verdict.ANOMALY if middlebox_detected else Verdict.OK

                    results.append(TestResult(
                        test=tc["name"],
                        category="middlebox",
                        target=_ECHO_URL,
                        verdict=verdict,
                        method=BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION if middlebox_detected else None,
                        evidence={
                            "sent_header": original_key,
                            "reflected_headers": dict(list(reflected.items())[:10]),
                            "middlebox_normalized": middlebox_detected,
                        },
                        notes=tc["notes"],
                    ))
                else:
                    results.append(TestResult(
                        test=tc["name"], category="middlebox", target=_ECHO_URL,
                        verdict=Verdict.INCONCLUSIVE,
                        evidence={"status": r.status_code},
                    ))

        except Exception as e:
            results.append(TestResult(
                test=tc["name"], category="middlebox", target=_ECHO_URL,
                verdict=Verdict.ERROR, evidence={"error": str(e)},
            ))

    return results


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
