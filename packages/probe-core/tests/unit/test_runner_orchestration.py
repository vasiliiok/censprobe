"""
Tests for ``runner.ProbeRunner`` orchestration semantics.

Two load-bearing properties:

  1. One broken module must NOT sabotage the rest of the run.
     ``_run_one`` converts adapter exceptions to a tuple slot so the
     ``asyncio.gather`` in Phase A never propagates the failure;
     ``module_failures`` records the names so the operator can see
     which one died.

  2. ``module_failures`` must surface in the saved-report summary
     (``_summarize``) even when there are zero TestResults from the
     failed module — otherwise a silently-broken probe ships a
     glossy-looking summary.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from censprobe_core.config import set_config
from censprobe_core.models import TestResult, Verdict
from censprobe_core.module_registry import ModuleSpec, Phase
from censprobe_core.runner import ProbeRunner, _summarize
from censprobe_core.targets import TargetSet


def _ok(test: str = "x") -> TestResult:
    return TestResult(test=test, category="dns", target="example.com", verdict=Verdict.OK)


def _good_adapter(_cfg: Any, _ts: Any) -> Any:
    async def _impl() -> list[TestResult]:
        return [_ok("good_module_result")]

    return _impl()


def _bad_adapter(_cfg: Any, _ts: Any) -> Any:
    async def _impl() -> list[TestResult]:
        raise RuntimeError("boom")

    return _impl()


def _empty_adapter(_cfg: Any, _ts: Any) -> Any:
    async def _impl() -> list[TestResult]:
        return []

    return _impl()


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration — one bad module doesn't kill the run
# ─────────────────────────────────────────────────────────────────────────────


async def test_one_broken_module_does_not_kill_others(
    monkeypatch: pytest.MonkeyPatch,
    make_config: Callable[..., Any],
    tmp_path: Path,
) -> None:
    cfg = make_config()
    set_config(cfg)
    fake_modules = (
        ModuleSpec("good", Phase.PARALLEL, _good_adapter),
        ModuleSpec("bad", Phase.PARALLEL, _bad_adapter),
    )
    monkeypatch.setattr("censprobe_core.runner.MODULES", fake_modules)
    monkeypatch.setattr("censprobe_core.runner.enabled_modules", lambda _cfg: list(fake_modules))
    runner = ProbeRunner(workspace=tmp_path, test_id="t", config=cfg, targets=TargetSet())
    results = await runner.run_all()

    # Good module's results are present.
    assert any(r.test == "good_module_result" for r in results)
    # Bad module is recorded as failed.
    assert "bad" in runner.module_failures
    assert "good" not in runner.module_failures


async def test_phase_b_serial_failure_recorded(
    monkeypatch: pytest.MonkeyPatch,
    make_config: Callable[..., Any],
    tmp_path: Path,
) -> None:
    cfg = make_config()
    set_config(cfg)
    fake_modules = (
        ModuleSpec("good", Phase.PARALLEL, _good_adapter),
        ModuleSpec("bad_serial", Phase.SERIAL, _bad_adapter),
    )
    monkeypatch.setattr("censprobe_core.runner.MODULES", fake_modules)
    monkeypatch.setattr("censprobe_core.runner.enabled_modules", lambda _cfg: list(fake_modules))
    runner = ProbeRunner(workspace=tmp_path, test_id="t", config=cfg, targets=TargetSet())
    await runner.run_all()
    # Serial-phase failure must also land in module_failures.
    assert "bad_serial" in runner.module_failures


async def test_skipped_modules_are_logged_not_failed(
    monkeypatch: pytest.MonkeyPatch,
    make_config: Callable[..., Any],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Disabled modules go through ``enabled_modules`` filtering — they
    must NOT show up as failures, just as a "skipped" log line."""
    cfg = make_config()
    set_config(cfg)
    all_modules = (
        ModuleSpec("good", Phase.PARALLEL, _good_adapter),
        ModuleSpec("disabled", Phase.PARALLEL, _bad_adapter),
    )
    monkeypatch.setattr("censprobe_core.runner.MODULES", all_modules)
    # Only "good" is enabled.
    monkeypatch.setattr("censprobe_core.runner.enabled_modules", lambda _cfg: [all_modules[0]])
    runner = ProbeRunner(workspace=tmp_path, test_id="t", config=cfg, targets=TargetSet())
    import logging

    with caplog.at_level(logging.INFO):
        await runner.run_all()
    assert runner.module_failures == []
    assert any("skipped" in r.message.lower() for r in caplog.records)


# ─────────────────────────────────────────────────────────────────────────────
# _summarize — module_failures surface in the report summary
# ─────────────────────────────────────────────────────────────────────────────


class TestSummarize:
    def test_empty(self) -> None:
        s = _summarize([], module_failures=[])
        assert s["total"] == 0
        assert s["module_failures"] == []
        assert s["blocked_count"] == 0
        assert s["ok_count"] == 0
        assert s["detected_techniques"] == []

    def test_module_failures_pass_through(self) -> None:
        s = _summarize([], module_failures=["dns", "telegram"])
        assert s["module_failures"] == ["dns", "telegram"]

    def test_module_failures_default_none_yields_empty(self) -> None:
        # Defensive: caller may pass None — must not raise.
        s = _summarize([])
        assert s["module_failures"] == []

    def test_counts_by_verdict_and_category(self) -> None:
        results = [
            TestResult(test="dns_x", category="dns", target="x", verdict=Verdict.OK),
            TestResult(test="dns_y", category="dns", target="y", verdict=Verdict.BLOCKED),
            TestResult(test="tls_x", category="tls", target="x", verdict=Verdict.BLOCKED),
        ]
        s = _summarize(results)
        assert s["total"] == 3
        assert s["by_verdict"] == {"OK": 1, "BLOCKED": 2}
        assert s["by_category"]["dns"] == {"OK": 1, "BLOCKED": 1}
        assert s["by_category"]["tls"] == {"BLOCKED": 1}
        assert s["blocked_count"] == 2
        assert s["ok_count"] == 1

    def test_techniques_only_from_blocking_verdicts(self) -> None:
        from censprobe_core.models import BlockingMethod

        results = [
            TestResult(
                test="dns_x",
                category="dns",
                target="x",
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.DNS_POISONING,
            ),
            # SERVER_REFUSED carries a method but must NOT count.
            TestResult(
                test="http_x",
                category="http",
                target="x",
                verdict=Verdict.SERVER_REFUSED,
                method=BlockingMethod.TLS_HANDSHAKE_FAILURE,
            ),
        ]
        s = _summarize(results)
        assert s["detected_techniques"] == ["dns_poisoning"]


# ─────────────────────────────────────────────────────────────────────────────
# save_report — the saved JSON contains module_failures
# ─────────────────────────────────────────────────────────────────────────────


async def test_save_report_writes_module_failures(
    monkeypatch: pytest.MonkeyPatch,
    make_config: Callable[..., Any],
    tmp_path: Path,
) -> None:
    cfg = make_config()
    set_config(cfg)
    fake_modules = (
        ModuleSpec("good", Phase.PARALLEL, _good_adapter),
        ModuleSpec("bad", Phase.PARALLEL, _bad_adapter),
    )
    monkeypatch.setattr("censprobe_core.runner.MODULES", fake_modules)
    monkeypatch.setattr("censprobe_core.runner.enabled_modules", lambda _cfg: list(fake_modules))
    runner = ProbeRunner(workspace=tmp_path, test_id="ru-test", config=cfg, targets=TargetSet())
    results = await runner.run_all()
    out = runner.save_report(results)

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["test_id"] == "ru-test"
    assert payload["report_type"] == "solo"
    # The summary must reflect the bad module so operators see it failed.
    assert "bad" in payload["summary"]["module_failures"]
