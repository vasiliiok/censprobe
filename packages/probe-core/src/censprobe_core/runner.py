"""
runner.py — Async orchestrator driven by the module registry.

Loads :class:`~censprobe_core.config.CensprobeConfig` and the
auto-discovered :class:`~censprobe_core.targets.TargetSet` once, then
walks :data:`~censprobe_core.module_registry.MODULES` in two phases:

  * Phase A (parallel): each module's adapter coroutine is gathered at
    once. Every module is internally throttled, so concurrent execution
    does not flood the link.
  * Phase B (serial): bandwidth- or RTT-sensitive modules. Run one at a
    time on a quiet uplink to avoid biasing the numbers.

Modules are filtered by their ``modules.<name>.enabled`` config flag —
a disabled module produces zero results and zero failures.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from censprobe_core import __version__ as PROBE_CORE_VERSION
from censprobe_core.config import CensprobeConfig, get_config
from censprobe_core.models import ServerMeta, TestResult
from censprobe_core.module_registry import MODULES, ModuleSpec, Phase, enabled_modules
from censprobe_core.scoring import BLOCKING_VERDICT_STRINGS
from censprobe_core.targets import TargetSet, load_targets

logger = logging.getLogger(__name__)

WORKSPACE = Path("/workspace")


class ProbeRunner:
    """
    Orchestrates the registered measurement modules.

    Usage:
        runner = ProbeRunner(workspace=Path("/workspace"), test_id="selectel-spb-001")
        results = await runner.run_all()      # repeats come from config
        runner.save_report(results, server_meta=...)
    """

    def __init__(
        self,
        workspace: Path = WORKSPACE,
        test_id: str = "unknown",
        config: CensprobeConfig | None = None,
        targets: TargetSet | None = None,
    ) -> None:
        self.workspace = workspace
        self.test_id = test_id
        self.module_failures: list[str] = []
        # Config: callers can pass an explicit instance for tests; otherwise
        # we use whatever load_config has registered, falling back to defaults.
        self.config = config if config is not None else get_config()
        # Targets: lazily auto-discovered from the configured directory.
        if targets is not None:
            self.targets = targets
        else:
            self.targets = load_targets(
                directory=workspace / self.config.targets.directory,
                files=self.config.targets.files or None,
                module_owned=self.config.targets.module_owned,
            )

    def _absorb_module_outcome(
        self,
        outcome: tuple[ModuleSpec, list[TestResult] | None, BaseException | None],
        results: list[TestResult],
    ) -> None:
        """Merge one ``_run_one`` tuple into the running results / failures."""
        spec, mod_results, err = outcome
        if err is not None:
            logger.error(
                "[%s] %s module failed: %s",
                self.test_id,
                spec.name,
                err,
                exc_info=err,
            )
            self.module_failures.append(spec.name)
        elif mod_results is not None:
            results.extend(mod_results)
            logger.info(
                "[%s] %s: %d results",
                self.test_id,
                spec.name,
                len(mod_results),
            )

    def _apply_repeat_override(self, repeats: int) -> None:
        """Force every repeat-aware module section to use ``repeats``.

        DNS doesn't appear here because its retry surface is the
        multi-resolver cross-check rather than a single-record repeat;
        :func:`censprobe_core.modules.dns.run_dns_tests` takes no
        ``repeats`` parameter. The remaining three modules (tcp / tls /
        http) honour the override.
        """
        for name in ("tcp", "tls", "http"):
            section = getattr(self.config.modules, name, None)
            if section is not None and hasattr(section, "repeats"):
                section.repeats = repeats

    async def run_all(self, repeats: int | None = None) -> list[TestResult]:
        """Run every enabled module and return aggregated results.

        ``repeats`` is accepted for back-compat with older callers but
        not used directly — per-module repeat counts now live in
        :class:`~censprobe_core.config.ModulesConfig`. Setting an
        explicit ``repeats`` will override config for any module with a
        ``repeats`` attribute on its config section.
        """
        results: list[TestResult] = []
        self.module_failures = []

        if repeats is not None:
            self._apply_repeat_override(repeats)

        active = enabled_modules(self.config)
        skipped = [m.name for m in MODULES if m not in active]
        if skipped:
            logger.info("[%s] skipped (disabled): %s", self.test_id, ", ".join(skipped))

        logger.info(
            "[%s] Starting probe run with %d active modules",
            self.test_id,
            len(active),
        )

        # Phase A — parallel.
        phase_a = [m for m in active if m.phase == Phase.PARALLEL]
        if phase_a:
            logger.info(
                "[%s] Phase A: running %d modules in parallel...",
                self.test_id,
                len(phase_a),
            )
            coros = [self._run_one(m) for m in phase_a]
            for outcome in await asyncio.gather(*coros):
                self._absorb_module_outcome(outcome, results)

        # Phase B — serial. The module adapter calls inside _run_one
        # already swallow exceptions and report them via the tuple.
        phase_b = [m for m in active if m.phase == Phase.SERIAL]
        for spec in phase_b:
            logger.info("[%s] Phase B: running %s tests...", self.test_id, spec.name)
            self._absorb_module_outcome(await self._run_one(spec), results)

        if self.module_failures:
            logger.warning(
                "[%s] %d module(s) failed: %s",
                self.test_id,
                len(self.module_failures),
                ", ".join(self.module_failures),
            )
        logger.info(
            "[%s] Probe complete. Total results: %d",
            self.test_id,
            len(results),
        )
        return results

    async def _run_one(
        self,
        spec: ModuleSpec,
    ) -> tuple[ModuleSpec, list[TestResult] | None, BaseException | None]:
        """Run one module's adapter; convert exceptions to a tuple slot.

        Returning ``(spec, None, exc)`` rather than letting the
        exception propagate keeps the gather() in Phase A from
        cancelling sibling modules — one broken module shouldn't
        sabotage the whole run.
        """
        try:
            mod_results = await spec.adapter(self.config, self.targets)
            return spec, mod_results, None
        except Exception as e:  # noqa: BLE001 — we genuinely want anything
            return spec, None, e

    def save_report(
        self,
        results: list[TestResult],
        server_meta: ServerMeta | None = None,
        output_path: Path | None = None,
    ) -> Path:
        """
        Serialize results as pretty JSON and save.

        The report intentionally carries only raw measurement data — no
        ``scores`` field. Solo runs BEFORE listener, so any scores baked
        in here would freeze protocol-reachability at its neutral default
        and mislead every downstream reader. Sync-api recomputes scores
        on demand from raw results + listener data.
        """
        if output_path is None:
            ts = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
            reports_dir = self.workspace / "reports" / self.test_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = reports_dir / f"server-solo-{ts}.json"

        report_data = {
            "test_id": self.test_id,
            "report_type": "solo",
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "probe_core_version": PROBE_CORE_VERSION,
            "server_meta": server_meta.model_dump() if server_meta else None,
            "results": [r.model_dump(mode="json") for r in results],
            "summary": _summarize(
                results,
                module_failures=list(self.module_failures),
            ),
        }

        output_path.write_text(
            json.dumps(report_data, default=str, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        logger.info("Report saved: %s (%d bytes)", output_path, output_path.stat().st_size)
        return output_path


def _summarize(
    results: list[TestResult],
    module_failures: list[str] | None = None,
) -> dict[str, Any]:
    """Quick summary statistics for the report."""
    total = len(results)
    by_verdict: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    techniques: set[str] = set()
    blocked_count = 0
    ok_count = 0

    for r in results:
        v = str(r.verdict)
        by_verdict[v] = by_verdict.get(v, 0) + 1
        cat = r.category
        if cat not in by_category:
            by_category[cat] = {}
        by_category[cat][v] = by_category[cat].get(v, 0) + 1
        if r.method and v in BLOCKING_VERDICT_STRINGS:
            techniques.add(str(r.method))
        if v in BLOCKING_VERDICT_STRINGS:
            blocked_count += 1
        elif v == "OK":
            ok_count += 1

    return {
        "total": total,
        "by_verdict": by_verdict,
        "by_category": by_category,
        "detected_techniques": sorted(techniques),
        "blocked_count": blocked_count,
        "ok_count": ok_count,
        "module_failures": list(module_failures or []),
    }
