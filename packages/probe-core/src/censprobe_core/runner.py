"""
runner.py — Async orchestrator for all probe modules.

Runs all measurement modules, collects TestResult objects, handles N repeats.
Used by the solo container; the listener-side reachability tests live in
the listener package directly.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from censprobe_core import __version__ as PROBE_CORE_VERSION
from censprobe_core.models import ServerMeta, TestResult
from censprobe_core.modules import dns, tcp, tls, http, telegram, throttling, middlebox, cloudflare
from censprobe_core.scoring import BLOCKING_VERDICT_STRINGS

logger = logging.getLogger(__name__)

WORKSPACE = Path("/workspace")


class ProbeRunner:
    """
    Orchestrates all probe measurement modules.

    Usage:
        runner = ProbeRunner(workspace=Path("/workspace"), test_id="selectel-spb-001")
        results = await runner.run_all(repeats=3)
        runner.save_report(results, path)
    """

    def __init__(
        self,
        workspace: Path = WORKSPACE,
        test_id: str = "unknown",
    ) -> None:
        self.workspace = workspace
        self.test_id = test_id
        self._targets: dict[str, Any] = {}
        self.module_failures: list[str] = []

    def _load_targets(self, name: str) -> dict:
        """Load targets/<name>.yaml"""
        if name not in self._targets:
            path = self.workspace / "targets" / f"{name}.yaml"
            try:
                self._targets[name] = yaml.safe_load(path.read_text()) or {}
            except Exception as e:
                logger.warning("Could not load targets/%s.yaml: %s", name, e)
                self._targets[name] = {}
        return self._targets[name]

    async def run_all(self, repeats: int = 3) -> list[TestResult]:
        """Run all measurement modules and return aggregated results.

        Module phases:

          phase A (parallel, network I/O — each module has internal
            semaphore throttling, so concurrent execution does not flood
            the link): DNS, TCP, TLS, HTTP, Telegram, Cloudflare. VPN
            protocol handshake tests live in the listener container —
            solo runs from the server's side and has no peer to talk to.

          phase B (serial, timing-sensitive — bandwidth and RTT
            measurements must run on a quiet uplink to avoid biasing
            the numbers): Throttling, then Middlebox.

        Per-module failures are tracked in ``self.module_failures`` so the
        report summary can surface which phases produced no data —
        otherwise scoring on partial results silently degrades to neutral
        50% and the operator has no signal that half the measurements are
        missing.
        """
        results: list[TestResult] = []
        self.module_failures: list[str] = []

        logger.info("[%s] Starting probe run (repeats=%d)", self.test_id, repeats)

        async def _run_module(name: str, coro):
            try:
                return name, await coro, None
            except Exception as e:
                return name, None, e

        # ── Phase A: parallel network I/O ─────────────────────────────────────
        dns_domains = self._collect_dns_domains()
        tcp_targets = self._collect_tcp_targets()
        tls_targets = self._collect_tls_targets()
        http_targets = self._collect_http_targets()

        logger.info("[%s] Phase A: running 6 modules in parallel...", self.test_id)
        phase_a = await asyncio.gather(
            _run_module("dns", dns.run_dns_tests(dns_domains, repeats)),
            _run_module("tcp", tcp.run_tcp_tests(tcp_targets, repeats)),
            _run_module("tls", tls.run_tls_tests(tls_targets, repeats)),
            _run_module("http", http.run_http_tests(http_targets, repeats)),
            _run_module("telegram", telegram.run_telegram_tests(self._load_targets("telegram"))),
            _run_module("cloudflare", cloudflare.run_cloudflare_tests(self._load_targets("cloudflare"))),
        )
        for name, mod_results, err in phase_a:
            if err is not None:
                logger.error("[%s] %s module failed: %s", self.test_id, name, err, exc_info=err)
                self.module_failures.append(name)
            else:
                results.extend(mod_results)
                logger.info("[%s] %s: %d results", self.test_id, name, len(mod_results))

        # ── Phase B: timing-sensitive, serial ─────────────────────────────────
        logger.info("[%s] Phase B: running throttling tests...", self.test_id)
        try:
            thr_results = await throttling.run_throttling_tests()
            results.extend(thr_results)
            logger.info("[%s] throttling: %d results", self.test_id, len(thr_results))
        except Exception:
            logger.exception("[%s] throttling module failed", self.test_id)
            self.module_failures.append("throttling")

        logger.info("[%s] Phase B: running middlebox tests...", self.test_id)
        try:
            mb_results = await middlebox.run_middlebox_tests()
            results.extend(mb_results)
            logger.info("[%s] middlebox: %d results", self.test_id, len(mb_results))
        except Exception:
            logger.exception("[%s] middlebox module failed", self.test_id)
            self.module_failures.append("middlebox")

        if self.module_failures:
            logger.warning(
                "[%s] %d module(s) failed: %s",
                self.test_id, len(self.module_failures), ", ".join(self.module_failures),
            )
        logger.info("[%s] Probe complete. Total results: %d", self.test_id, len(results))
        return results

    def _collect_dns_domains(self) -> list[str]:
        """Collect all domains to test DNS for."""
        domains = set()
        for target_file in ["news", "social", "messengers", "vpn", "neutral"]:
            data = self._load_targets(target_file)
            for t in data.get("targets", []):
                if d := t.get("domain"):
                    domains.add(d)
        # Add Telegram domains
        tg = self._load_targets("telegram")
        for web in tg.get("web", []):
            domains.add(web)
        return sorted(domains)

    def _collect_tcp_targets(self) -> list[tuple[str, int]]:
        """Collect (ip, port) pairs for TCP reachability tests.

        Targets come from ``targets/neutral.yaml: tcp_targets`` — public DNS
        anycasts on TCP 443/853. Telegram DC TCP probes are NOT included here:
        they live in modules/telegram.py, and double-counting their
        reachability into ``relay_score`` (scoring.py) would tie raw uplink
        quality to Telegram-specific blocking instead of measuring it
        independently.
        """
        targets: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()

        neutral = self._load_targets("neutral")
        for entry in neutral.get("tcp_targets", []):
            ip = entry.get("ip")
            port = entry.get("port")
            if not ip or not port:
                continue
            key = (ip, int(port))
            if key in seen:
                continue
            seen.add(key)
            targets.append(key)

        return targets

    def _collect_tls_targets(self) -> list[dict]:
        """Collect TLS test targets from all target YAML files.

        ``ech_advertised`` is propagated into each target dict so the TLS
        module can skip the ECH probe for domains that don't publish an
        ECHConfig in their HTTPS DNS record. Without this flag every
        non-ECH domain emits an INCONCLUSIVE ``no_ech_in_https_record``
        result on every run, flooding the dashboard with noise.
        """
        targets = []
        seen_domains: set[str] = set()

        for tf in ["news", "social", "messengers", "vpn", "neutral"]:
            data = self._load_targets(tf)
            for t in data.get("targets", []):
                domain = t.get("domain")
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    targets.append({
                        "domain": domain,
                        "blocked_sni": domain,
                        "url": t.get("url", f"https://{domain}"),
                        "ech_advertised": bool(t.get("ech_advertised", False)),
                    })

        return targets

    def _collect_http_targets(self) -> list[dict]:
        """Collect HTTP test targets from all target files.

        Includes ``vpn.yaml`` even though VPN service websites are not the
        primary censorship signal: their HTTPS reachability is itself a
        cheap proxy for whether the operator's network blocks VPN-related
        domains at the edge (TLS-SNI / DNS RST), which is information the
        scoring layer can use independently of the dedicated VPN test
        modules.
        """
        targets = []
        for tf in ["news", "social", "messengers", "vpn", "neutral"]:
            data = self._load_targets(tf)
            for t in data.get("targets", []):
                targets.append(t)
        return targets

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
        and mislead every downstream reader. Sync-api recomputes
        scores on demand from raw results + listener data.

        Reports are plain .json: git's pack format already deflates textual
        blobs with zlib and computes delta chains across revisions, so
        gzipping upstream would defeat delta compression and make the
        .git directory grow quickly.
        """
        if output_path is None:
            ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
            reports_dir = self.workspace / "reports" / self.test_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = reports_dir / f"server-solo-{ts}.json"

        report_data = {
            "test_id": self.test_id,
            "report_type": "solo",
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "probe_core_version": PROBE_CORE_VERSION,
            "server_meta": server_meta.model_dump() if server_meta else None,
            "results": [r.model_dump(mode="json") for r in results],
            "summary": _summarize(results, module_failures=list(self.module_failures)),
        }

        output_path.write_text(
            json.dumps(report_data, default=str, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        logger.info("Report saved: %s (%d bytes)", output_path, output_path.stat().st_size)
        return output_path


def _summarize(results: list[TestResult], module_failures: list[str] | None = None) -> dict:
    """Quick summary statistics for the report.

    ``module_failures`` lists modules that raised before producing any
    results (DNS unreachable, import error, etc.). Surfaced so the
    dashboard can flag scoring done on partial data instead of treating
    a half-empty run as legitimate "neutral 50%".
    """
    # Verdicts that mean "this target was actually censored / unreachable"
    # — single source of truth in scoring.BLOCKING_VERDICT_STRINGS so the
    # CLI summary, saved JSON summary, and Grafana never disagree on what
    # counts as blocked.
    total = len(results)
    by_verdict: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    techniques = set()
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
