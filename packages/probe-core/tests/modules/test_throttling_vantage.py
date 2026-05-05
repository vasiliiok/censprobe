"""
Tests for ``modules.throttling.run_throttling_tests`` vantage gating.

The vantage-skip path emits a single INCONCLUSIVE TestResult so the
dashboard sees "not run" instead of "false negative". Pin both:
  * From an off-vantage host → no real probe is invoked, INCONCLUSIVE
    is emitted with a specific evidence-reason key.
  * If ``require_censoring_vantage=False`` is set, the gate is bypassed
    even off-vantage (we don't actually run the curl-based probe; we
    monkeypatch _run_method_b_sni_probe to confirm it IS called).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from censprobe_core.config import set_config
from censprobe_core.models import Verdict
from censprobe_core.modules import throttling as throttling_mod


@pytest.mark.asyncio
class TestThrottlingVantageGate:
    async def test_off_vantage_emits_inconclusive_marker(
        self,
        monkeypatch: pytest.MonkeyPatch,
        make_config: Any,
    ) -> None:
        cfg = make_config()
        set_config(cfg)
        # Force vantage to a non-censoring country.
        monkeypatch.setattr(throttling_mod, "is_censoring_vantage", lambda: False)

        # Sentinel: if the real probe ran, we'd hit subprocess code.
        called = AsyncMock()
        monkeypatch.setattr(throttling_mod, "_run_method_b_sni_probe", called)

        results = await throttling_mod.run_throttling_tests()
        assert len(results) == 1
        r = results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert r.test == "throttling_youtube_sni_probe_method_b"
        assert r.evidence.get("reason") == "non_censoring_vantage_method_b_skipped"
        # Confidence must be 0 on the skip path — dashboard treats it as
        # informational, not as evidence one way or another.
        assert r.confidence == pytest.approx(0.0)
        called.assert_not_called()

    async def test_on_vantage_invokes_probe(
        self,
        monkeypatch: pytest.MonkeyPatch,
        make_config: Any,
    ) -> None:
        cfg = make_config()
        set_config(cfg)
        monkeypatch.setattr(throttling_mod, "is_censoring_vantage", lambda: True)

        # Stub the probe so we don't invoke real curl.
        sentinel = AsyncMock(return_value=None)
        monkeypatch.setattr(throttling_mod, "_run_method_b_sni_probe", sentinel)

        results = await throttling_mod.run_throttling_tests()
        # Probe returned None → empty results list, but the sentinel was hit
        # exactly once with the live cfg's ThrottlingModuleConfig — confirms
        # the gating path didn't substitute a stale or default cfg object.
        assert results == []
        sentinel.assert_called_once()
        (passed_cfg,) = sentinel.call_args.args
        assert passed_cfg is cfg.modules.throttling, f"probe got wrong cfg object: {passed_cfg!r}"

    async def test_require_vantage_false_bypasses_gate(
        self,
        monkeypatch: pytest.MonkeyPatch,
        make_config: Any,
    ) -> None:
        # Build cfg with require_censoring_vantage=False explicitly.
        cfg = make_config(
            modules={
                "throttling": {
                    "enabled": True,
                    "require_censoring_vantage": False,
                    "target_url": "https://example.com/100MB",
                    "correct_sni": "example.com",
                    "typo_sni": "exaple.com",
                    "trigger_sni": "trigger.example",
                    "sequential_runs": 1,
                    "bandwidth_ratio_threshold": 0.25,
                    "curl_timeout_sec": 30.0,
                }
            }
        )
        set_config(cfg)
        monkeypatch.setattr(throttling_mod, "is_censoring_vantage", lambda: False)

        sentinel = AsyncMock(return_value=None)
        monkeypatch.setattr(throttling_mod, "_run_method_b_sni_probe", sentinel)

        await throttling_mod.run_throttling_tests()
        # Bypass — probe was invoked despite off-vantage, AND with the
        # override cfg's ThrottlingModuleConfig (require_censoring_vantage=False
        # specifically), confirming the bypass path didn't fall through to
        # an unconfigured default.
        sentinel.assert_called_once()
        (passed_cfg,) = sentinel.call_args.args
        assert passed_cfg.require_censoring_vantage is False
        assert passed_cfg.trigger_sni == "trigger.example"
