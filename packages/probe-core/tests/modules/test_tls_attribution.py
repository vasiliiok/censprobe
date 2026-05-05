"""
Tests for ``modules.tls._attribute_tls_failure``.

This pure helper translates a (verdict, evidence) pair into a
:class:`BlockingMethod` for the dashboard. The mapping is small but
load-bearing — a wrong attribution puts the failure under the wrong
technique counter, and operators read those counters to pick which
protocol to deploy.
"""

from __future__ import annotations

import pytest
from censprobe_core.models import BlockingMethod, Verdict
from censprobe_core.modules.tls import _attribute_tls_failure


class TestAttributeTlsFailure:
    def test_ok_returns_none(self) -> None:
        # OK never produces a blocking-method attribution.
        assert _attribute_tls_failure(Verdict.OK, {"error": "anything"}) is None

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            ("connection_reset", BlockingMethod.TCP_RST_AFTER_TLS_CH),
            ("timeout", BlockingMethod.IP_DROPPED),
            ("ssl_error", BlockingMethod.TLS_HANDSHAKE_FAILURE),
            ("cert_verification_failed", BlockingMethod.TLS_HANDSHAKE_FAILURE),
        ],
    )
    def test_known_errors_map_to_methods(self, error: str, expected: BlockingMethod) -> None:
        method = _attribute_tls_failure(Verdict.BLOCKED, {"error": error})
        assert method is expected

    def test_unknown_error_returns_none(self) -> None:
        # Defensive default — a future error string we haven't catalogued
        # should leave the method blank rather than mis-attributing.
        assert _attribute_tls_failure(Verdict.BLOCKED, {"error": "wat"}) is None

    def test_missing_error_key_returns_none(self) -> None:
        # `evidence.get("error", "")` — empty error is unattributable.
        assert _attribute_tls_failure(Verdict.BLOCKED, {}) is None
