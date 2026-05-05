"""
Tests for ``modules.telegram._compute_health_score`` and ``_ok_ratio``.

The health score is a weighted average over three families (DC / web /
CDN). Two corners are easy to get wrong:

  * INCONCLUSIVE results must NOT drag a family's ratio down — they
    carry no signal. But if EVERY result in a family is INCONCLUSIVE,
    the family's ratio must be 0.0, NOT the neutral 0.5 — otherwise a
    fully-broken Telegram looks healthier than a partially-blocked one.
  * Weights from telegram.yaml may not sum to 1.0; the computed score
    must renormalise so the maximum is always 1.0.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from censprobe_core.models import TestResult, Verdict
from censprobe_core.modules.telegram import _compute_health_score, _ok_ratio


def _r(test: str, verdict: Verdict) -> TestResult:
    return TestResult(
        test=test,
        category="telegram",
        target="x",
        verdict=verdict,
        timestamp=datetime.now(UTC),
    )


# ─────────────────────────────────────────────────────────────────────────────
# _ok_ratio
# ─────────────────────────────────────────────────────────────────────────────


class TestOkRatio:
    def test_empty_returns_zero(self) -> None:
        # Empty == "no decisive evidence", not "neutral 50%".
        assert _ok_ratio([]) == pytest.approx(0.0)

    def test_all_inconclusive_returns_zero(self) -> None:
        # The crucial test: every result is INCONCLUSIVE → ratio is 0.0,
        # so a fully-broken Telegram (every probe inconclusive after
        # cert-pattern reconcile) doesn't artificially inflate the
        # health score.
        results = [
            _r("telegram_dc1_443", Verdict.INCONCLUSIVE),
            _r("telegram_dc2_443", Verdict.INCONCLUSIVE),
        ]
        assert _ok_ratio(results) == pytest.approx(0.0)

    def test_inconclusive_excluded_from_decisive_set(self) -> None:
        # 1 OK + 1 BLOCKED + 2 INCONCLUSIVE → decisive=2, ok=1 → 0.5.
        # The inconclusive ones must NOT push the denominator to 4.
        results = [
            _r("telegram_dc1_443", Verdict.OK),
            _r("telegram_dc2_443", Verdict.BLOCKED),
            _r("telegram_dc3_443", Verdict.INCONCLUSIVE),
            _r("telegram_dc4_443", Verdict.INCONCLUSIVE),
        ]
        assert _ok_ratio(results) == pytest.approx(0.5)

    def test_all_ok(self) -> None:
        results = [_r("telegram_dc1_443", Verdict.OK)] * 3
        assert _ok_ratio(results) == pytest.approx(1.0)


# ─────────────────────────────────────────────────────────────────────────────
# _compute_health_score
# ─────────────────────────────────────────────────────────────────────────────


_DEFAULT_WEIGHTS = {"dc_reachability": 0.55, "web_access": 0.25, "cdn_access": 0.20}


class TestComputeHealthScore:
    def test_all_ok_returns_one(self) -> None:
        results = [
            _r("telegram_dc1_443", Verdict.OK),
            _r("telegram_web_t_me", Verdict.OK),
            _r("telegram_cdn_t_me", Verdict.OK),
        ]
        assert _compute_health_score(results, _DEFAULT_WEIGHTS) == pytest.approx(1.0)

    def test_all_blocked_returns_zero(self) -> None:
        results = [
            _r("telegram_dc1_443", Verdict.BLOCKED),
            _r("telegram_web_t_me", Verdict.BLOCKED),
            _r("telegram_cdn_t_me", Verdict.BLOCKED),
        ]
        assert _compute_health_score(results, _DEFAULT_WEIGHTS) == pytest.approx(0.0)

    def test_only_dc_ok_yields_dc_weight(self) -> None:
        # Default weights: dc=0.55, web=0.25, cdn=0.20 → sum 1.0.
        # DC OK + others all BLOCKED → 1.0 × 0.55 = 0.55.
        results = [
            _r("telegram_dc1_443", Verdict.OK),
            _r("telegram_web_t_me", Verdict.BLOCKED),
            _r("telegram_cdn_t_me", Verdict.BLOCKED),
        ]
        score = _compute_health_score(results, _DEFAULT_WEIGHTS)
        assert score == pytest.approx(0.55)

    def test_weights_renormalised_when_sum_not_one(self) -> None:
        # Skewed weights summing to 2.0. Score must be in [0, 1].
        skewed = {"dc_reachability": 1.0, "web_access": 1.0, "cdn_access": 0.0}
        results = [
            _r("telegram_dc1_443", Verdict.OK),
            _r("telegram_web_t_me", Verdict.BLOCKED),
        ]
        score = _compute_health_score(results, skewed)
        # 1.0×1 + 0.0×1 + 0×0 = 1.0; total_w = 2.0 → 0.5.
        assert score == pytest.approx(0.5)

    def test_zero_weights_returns_one(self) -> None:
        # Defensive — a yaml that zeroed every weight must NOT divide
        # by zero. Code returns 1.0 in that case.
        results = [_r("telegram_dc1_443", Verdict.BLOCKED)]
        assert _compute_health_score(
            results, {"dc_reachability": 0, "web_access": 0, "cdn_access": 0}
        ) == pytest.approx(1.0)

    def test_missing_results_for_one_family(self) -> None:
        # No CDN results — family's ratio is 0.0 (empty == 0). With default
        # weights: dc(OK)*0.55 + web(OK)*0.25 + cdn(empty=0)*0.20 = 0.80.
        results = [
            _r("telegram_dc1_443", Verdict.OK),
            _r("telegram_web_t_me", Verdict.OK),
        ]
        assert _compute_health_score(results, _DEFAULT_WEIGHTS) == pytest.approx(0.80)

    def test_unrelated_test_names_ignored(self) -> None:
        # Only telegram_dc/telegram_web/telegram_cdn prefixes count.
        results = [
            _r("dns_meduza_io_system", Verdict.OK),  # ignored
            _r("telegram_dc1_443", Verdict.OK),
        ]
        # web=empty=0, cdn=empty=0 → only dc contributes → 0.55.
        assert _compute_health_score(results, _DEFAULT_WEIGHTS) == pytest.approx(0.55)
