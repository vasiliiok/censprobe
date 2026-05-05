"""
Tests for ``modules.http._verdict_from_response``.

This pure helper decides the HTTP verdict from response signals and the
ordering of the three checks (geoblock-with-valid-TLS first, then
expected_status, then default 200). Any reorder would silently change
verdicts on dual-meaning status codes (403/451 from a geoblocking origin
vs. from a TSPU stub page over HTTP).
"""

from __future__ import annotations

import pytest
from censprobe_core.models import Verdict
from censprobe_core.modules.http import _verdict_from_response


class TestGeoblockPrecedence:
    """403/451 over a valid TLS handshake → GEOBLOCK_NOT_CENSORSHIP.

    Order matters: this branch must fire before expected_status and
    before the default 200 check, because RKN block pages are NOT
    served over a valid TLS handshake — they are RST-injected before
    the cert exchange completes.
    """

    @pytest.mark.parametrize("status", [403, 451])
    def test_with_valid_tls_geoblock(self, status: int) -> None:
        verdict, method = _verdict_from_response(
            status=status,
            tls_ok=True,
            expected_status=None,
        )
        assert verdict == Verdict.GEOBLOCK_NOT_CENSORSHIP
        assert method is None

    @pytest.mark.parametrize("status", [403, 451])
    def test_without_tls_does_not_geoblock(self, status: int) -> None:
        # Plain HTTP — no TLS guarantee, so a 403/451 could be a stub
        # block-page injected on the wire. Must NOT downgrade to
        # GEOBLOCK_NOT_CENSORSHIP.
        verdict, _ = _verdict_from_response(
            status=status,
            tls_ok=False,
            expected_status=None,
        )
        assert verdict == Verdict.ANOMALY

    def test_geoblock_overrides_expected_status(self) -> None:
        # If a target's expected_status was 200 but we got 403 over
        # valid TLS, the geoblock-precedence rule still wins.
        verdict, _ = _verdict_from_response(
            status=403,
            tls_ok=True,
            expected_status=200,
        )
        assert verdict == Verdict.GEOBLOCK_NOT_CENSORSHIP

    def test_geoblock_does_not_fire_on_other_codes(self) -> None:
        # 200 with valid TLS doesn't trigger geoblock just because TLS is OK.
        verdict, _ = _verdict_from_response(status=200, tls_ok=True, expected_status=None)
        assert verdict == Verdict.OK


class TestExpectedStatus:
    def test_match_returns_ok(self) -> None:
        verdict, _ = _verdict_from_response(status=204, tls_ok=True, expected_status=204)
        assert verdict == Verdict.OK

    def test_mismatch_returns_anomaly(self) -> None:
        verdict, _ = _verdict_from_response(status=500, tls_ok=True, expected_status=204)
        assert verdict == Verdict.ANOMALY

    def test_zero_expected_status_is_treated_as_set(self) -> None:
        # `is not None` discriminates — 0 is unusual but valid.
        verdict, _ = _verdict_from_response(status=0, tls_ok=False, expected_status=0)
        assert verdict == Verdict.OK


class TestDefault200:
    @pytest.mark.parametrize("status", [200])
    def test_200_is_ok(self, status: int) -> None:
        verdict, _ = _verdict_from_response(status=status, tls_ok=True, expected_status=None)
        assert verdict == Verdict.OK

    @pytest.mark.parametrize("status", [301, 302, 404, 500, 503])
    def test_non_200_is_anomaly(self, status: int) -> None:
        verdict, _ = _verdict_from_response(status=status, tls_ok=True, expected_status=None)
        assert verdict == Verdict.ANOMALY


class TestMethodAlwaysNone:
    """``_verdict_from_response`` doesn't attribute method — that's the
    caller's job in the exception branch (TLS_HANDSHAKE_FAILURE etc).
    Pin this so a future refactor doesn't accidentally start filling it
    here and double-counting techniques in the summary."""

    @pytest.mark.parametrize(
        ("status", "tls_ok", "expected"),
        [
            (200, True, None),
            (403, True, None),
            (451, True, None),
            (500, False, 200),
            (404, True, None),
        ],
    )
    def test_method_is_always_none(self, status: int, tls_ok: bool, expected: int | None) -> None:
        _, method = _verdict_from_response(
            status=status,
            tls_ok=tls_ok,
            expected_status=expected,
        )
        assert method is None
