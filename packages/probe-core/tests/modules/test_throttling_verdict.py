"""
Tests for ``modules.throttling._decide_method_b_verdict``.

Pure relative-bandwidth verdict. The function decides THROTTLED iff
the trigger SNI is below ``threshold_ratio`` of BOTH the correct and
typo SNIs measured in the same run on the same uplink. Three branches:

  1. Any zero / missing measurement  → INCONCLUSIVE.
  2. Trigger < ratio × correct AND
     trigger < ratio × typo          → THROTTLED.
  3. Otherwise                       → OK.
"""

from __future__ import annotations

import pytest
from censprobe_core.models import Verdict
from censprobe_core.modules.throttling import _decide_method_b_verdict

THRESHOLD = 0.25


class TestInconclusive:
    @pytest.mark.parametrize(
        ("correct", "trigger", "typo"),
        [
            (0.0, 50.0, 50.0),  # correct measurement failed
            (50.0, 0.0, 50.0),  # trigger run failed
            (50.0, 50.0, 0.0),  # typo measurement failed
            (-1.0, 50.0, 50.0),  # negative is treated as failure too
            (0.0, 0.0, 0.0),  # everything failed
        ],
    )
    def test_zero_or_negative_measurement_inconclusive(
        self, correct: float, trigger: float, typo: float
    ) -> None:
        assert _decide_method_b_verdict(correct, trigger, typo, THRESHOLD) == Verdict.INCONCLUSIVE


class TestThrottlingDetected:
    def test_trigger_below_both_thresholds(self) -> None:
        # correct=100, typo=80 → 25% × 100 = 25, 25% × 80 = 20. Trigger=10
        # is below both → throttled.
        assert _decide_method_b_verdict(100.0, 10.0, 80.0, THRESHOLD) == Verdict.THROTTLED

    def test_at_exact_boundary_not_throttled(self) -> None:
        # `<` not `<=` — equality at the threshold is OK, not throttled.
        # 25% × 100 = 25; trigger=25 must NOT trip.
        assert _decide_method_b_verdict(100.0, 25.0, 100.0, THRESHOLD) == Verdict.OK


class TestOk:
    def test_trigger_only_below_one_axis_is_ok(self) -> None:
        # Trigger=10 is below 25% of correct (25) but NOT below 25% of typo
        # (typo=20 → 25% = 5, trigger=10 > 5). Therefore OK, not throttled —
        # the uplink itself is just narrow on the typo run.
        assert _decide_method_b_verdict(100.0, 10.0, 20.0, THRESHOLD) == Verdict.OK

    def test_balanced_runs_are_ok(self) -> None:
        assert _decide_method_b_verdict(50.0, 49.0, 50.0, THRESHOLD) == Verdict.OK

    def test_trigger_higher_than_others_is_ok(self) -> None:
        # The relative-comparison philosophy: if trigger somehow runs FASTER
        # than the controls, we don't flag it.
        assert _decide_method_b_verdict(50.0, 200.0, 50.0, THRESHOLD) == Verdict.OK


class TestThresholdParameter:
    def test_lower_threshold_makes_detection_stricter(self) -> None:
        # Threshold 0.10 → trigger must be below 10% of both controls.
        # 12 < 25% × 100 = 25 (yes), 12 < 25% × 100 = 25 (yes) → THROTTLED at 0.25
        # 12 < 10% × 100 = 10 (no)              → OK at 0.10
        assert _decide_method_b_verdict(100.0, 12.0, 100.0, 0.25) == Verdict.THROTTLED
        assert _decide_method_b_verdict(100.0, 12.0, 100.0, 0.10) == Verdict.OK
