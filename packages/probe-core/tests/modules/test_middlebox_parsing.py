"""
Tests for ``modules.middlebox._test_header_manipulation`` response
classification.

Cloudflare's raw HTTP/80 edge returns 400 for bad Host or 301/302 for
HTTPS redirects — both indicate the request reached Cloudflare with
its case bytes intact. Anything else is a middlebox that rewrote our
request and is now serving its own page → ANOMALY +
MIDDLEBOX_HTTP_MANIPULATION.

We don't want to do real HTTP against 1.1.1.1 in unit tests; we mock
``_raw_http_request`` so the classification logic is the only thing
under test.
"""

from __future__ import annotations

from typing import Any

import pytest
from censprobe_core.models import BlockingMethod, Verdict
from censprobe_core.modules import middlebox as mb_mod


@pytest.mark.parametrize(
    ("status_line", "expected_verdict", "expected_method"),
    [
        # Cloudflare-OK statuses.
        ("HTTP/1.1 400 Bad Request", Verdict.OK, None),
        ("HTTP/1.1 301 Moved Permanently", Verdict.OK, None),
        ("HTTP/1.1 302 Found", Verdict.OK, None),
        # Anything else == middlebox rewriting our request.
        (
            "HTTP/1.1 200 OK",
            Verdict.ANOMALY,
            BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION,
        ),
        (
            "HTTP/1.1 503 Service Unavailable",
            Verdict.ANOMALY,
            BlockingMethod.MIDDLEBOX_HTTP_MANIPULATION,
        ),
    ],
)
async def test_status_classification(
    monkeypatch: pytest.MonkeyPatch,
    status_line: str,
    expected_verdict: Verdict,
    expected_method: BlockingMethod | None,
) -> None:
    response_head = status_line + "\r\nServer: cloudflare\r\n\r\n"

    async def _fake_raw_http_request(*_a: Any, **_kw: Any) -> tuple[str, str | None]:
        return response_head, None

    monkeypatch.setattr(mb_mod, "_raw_http_request", _fake_raw_http_request)

    results = await mb_mod._test_header_manipulation()
    # Two test_cases (host case + UA case) — both should classify the same way.
    assert len(results) == 2
    for r in results:
        assert r.verdict == expected_verdict
        assert r.method == expected_method
        # Always against 1.1.1.1:80 (the canary).
        assert r.target == "1.1.1.1:80"


async def test_network_error_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If 1.1.1.1 itself is unreachable, the verdict is INCONCLUSIVE —
    # we have no signal one way or the other about middleboxes.

    async def _fake_raw_http_request(*_a: Any, **_kw: Any) -> tuple[str, str | None]:
        return "", "ECONNREFUSED"

    monkeypatch.setattr(mb_mod, "_raw_http_request", _fake_raw_http_request)
    results = await mb_mod._test_header_manipulation()
    for r in results:
        assert r.verdict == Verdict.INCONCLUSIVE
        assert r.method is None


async def test_timeout_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Patch wait_for to raise TimeoutError synchronously — the test target
    # is the except-TimeoutError branch in _test_header_manipulation, not
    # the inner coroutine. We never have to await _raw_http_request.
    async def _fake_wait_for(coro: Any, **_kw: Any) -> Any:
        coro.close()  # close the unawaited inner coroutine cleanly
        raise TimeoutError

    monkeypatch.setattr(mb_mod.asyncio, "wait_for", _fake_wait_for)
    results = await mb_mod._test_header_manipulation()
    for r in results:
        assert r.verdict == Verdict.INCONCLUSIVE
