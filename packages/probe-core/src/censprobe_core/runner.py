"""
runner.py — Async orchestrator for all probe modules.

Runs all measurement modules, collects TestResult objects, handles N repeats.
Used by solo, client, and control containers.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from censprobe_core.baseline import BaselineComparator, load_baseline
from censprobe_core.models import (
    BaselineData,
    ServerMeta,
    ServerScores,
    TestResult,
)
from censprobe_core.modules import dns, tcp, tls, http, telegram, throttling, middlebox, protocols

logger = logging.getLogger(__name__)

_WORKSPACE = Path("/workspace")


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
        workspace: Path = _WORKSPACE,
        test_id: str = "unknown",
        mode: str = "solo",  # solo | control
    ) -> None:
        self.workspace = workspace
        self.test_id = test_id
        self.mode = mode
        self.baseline: BaselineData = load_baseline(workspace / "baseline" / "latest.json")
        self.comparator = BaselineComparator(self.baseline)
        self._targets: dict[str, Any] = {}

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
        """Run all measurement modules and return aggregated results."""
        results: list[TestResult] = []

        logger.info("[%s] Starting probe run (mode=%s, repeats=%d)", self.test_id, self.mode, repeats)

        # ── 1. DNS ────────────────────────────────────────────────────────────
        logger.info("[%s] Running DNS tests...", self.test_id)
        dns_domains = self._collect_dns_domains()
        try:
            dns_results = await dns.run_dns_tests(dns_domains, self.comparator, repeats)
            results.extend(dns_results)
            logger.info("[%s] DNS: %d results", self.test_id, len(dns_results))
        except Exception as e:
            logger.error("[%s] DNS module failed: %s", self.test_id, e)

        # ── 2. TCP ────────────────────────────────────────────────────────────
        logger.info("[%s] Running TCP reachability tests...", self.test_id)
        tcp_targets = self._collect_tcp_targets()
        try:
            tcp_results = await tcp.run_tcp_tests(tcp_targets, repeats)
            results.extend(tcp_results)
            logger.info("[%s] TCP: %d results", self.test_id, len(tcp_results))
        except Exception as e:
            logger.error("[%s] TCP module failed: %s", self.test_id, e)

        # ── 3. TLS/SNI ───────────────────────────────────────────────────────
        logger.info("[%s] Running TLS/SNI tests...", self.test_id)
        tls_targets = self._collect_tls_targets()
        try:
            tls_results = await tls.run_tls_tests(tls_targets, repeats)
            results.extend(tls_results)
            logger.info("[%s] TLS: %d results", self.test_id, len(tls_results))
        except Exception as e:
            logger.error("[%s] TLS module failed: %s", self.test_id, e)

        # ── 4. HTTP/HTTPS ─────────────────────────────────────────────────────
        logger.info("[%s] Running HTTP tests...", self.test_id)
        http_targets = self._collect_http_targets()
        try:
            http_results = await http.run_http_tests(http_targets, self.comparator, repeats)
            results.extend(http_results)
            logger.info("[%s] HTTP: %d results", self.test_id, len(http_results))
        except Exception as e:
            logger.error("[%s] HTTP module failed: %s", self.test_id, e)

        # ── 5. Telegram ───────────────────────────────────────────────────────
        logger.info("[%s] Running Telegram tests...", self.test_id)
        try:
            tg_results = await telegram.run_telegram_tests(self.comparator)
            results.extend(tg_results)
            logger.info("[%s] Telegram: %d results", self.test_id, len(tg_results))
        except Exception as e:
            logger.error("[%s] Telegram module failed: %s", self.test_id, e)

        # ── 6. Throttling (Method A + B) ──────────────────────────────────────
        logger.info("[%s] Running throttling tests...", self.test_id)
        try:
            thr_results = await throttling.run_throttling_tests(self.comparator)
            results.extend(thr_results)
            logger.info("[%s] Throttling: %d results", self.test_id, len(thr_results))
        except Exception as e:
            logger.error("[%s] Throttling module failed: %s", self.test_id, e)

        # ── 7. Middlebox ──────────────────────────────────────────────────────
        logger.info("[%s] Running middlebox tests...", self.test_id)
        try:
            mb_results = await middlebox.run_middlebox_tests()
            results.extend(mb_results)
            logger.info("[%s] Middlebox: %d results", self.test_id, len(mb_results))
        except Exception as e:
            logger.error("[%s] Middlebox module failed: %s", self.test_id, e)

        # ── 8. Protocol signatures (solo-only, no listener needed) ────────────
        logger.info("[%s] Protocol signature tests...", self.test_id)
        try:
            proto_results = await protocols.run_protocol_tests(control_endpoints=None)
            results.extend(proto_results)
        except Exception as e:
            logger.error("[%s] Protocol module failed: %s", self.test_id, e)

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
        """Collect (ip, port) pairs for TCP reachability tests."""
        targets = []
        # Telegram DCs
        tg = self._load_targets("telegram")
        for dc in tg.get("api_datacenters", []):
            for port in dc.get("ports", [443]):
                if ip := dc.get("ipv4"):
                    targets.append((ip, port))
        return targets[:20]  # cap to avoid excessive tests

    def _collect_tls_targets(self) -> list[dict]:
        """Collect TLS test targets."""
        targets = []
        # Sample of high-priority domains
        priority_domains = [
            {"domain": "meduza.io", "blocked_sni": "meduza.io"},
            {"domain": "instagram.com", "blocked_sni": "instagram.com"},
            {"domain": "youtube.com", "blocked_sni": "youtube.com"},
        ]
        return priority_domains

    def _collect_http_targets(self) -> list[dict]:
        """Collect HTTP test targets from all target files."""
        targets = []
        for tf in ["news", "social", "messengers", "neutral"]:
            data = self._load_targets(tf)
            for t in data.get("targets", []):
                targets.append(t)
        return targets

    def save_report(
        self,
        results: list[TestResult],
        server_meta: Optional[ServerMeta] = None,
        scores: Optional[ServerScores] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Serialize results to gzipped JSON and save.

        Returns the saved file path.
        """
        if output_path is None:
            ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
            reports_dir = self.workspace / "reports" / self.test_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = reports_dir / f"server-solo-{ts}.json.gz"

        report_data = {
            "test_id": self.test_id,
            "report_type": self.mode,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "probe_core_version": "0.1.0",
            "baseline_version": self.baseline.version,
            "server_meta": server_meta.model_dump() if server_meta else None,
            "scores": scores.model_dump() if scores else None,
            "results": [r.model_dump(mode="json") for r in results],
            "summary": _summarize(results),
        }

        json_bytes = json.dumps(report_data, default=str, ensure_ascii=False, indent=2).encode()
        with gzip.open(output_path, "wb") as f:
            f.write(json_bytes)

        logger.info("Report saved: %s (%d bytes compressed)", output_path, output_path.stat().st_size)
        return output_path


def _summarize(results: list[TestResult]) -> dict:
    """Quick summary statistics for the report."""
    total = len(results)
    by_verdict: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    techniques = set()

    for r in results:
        v = str(r.verdict)
        by_verdict[v] = by_verdict.get(v, 0) + 1
        cat = r.category
        if cat not in by_category:
            by_category[cat] = {}
        by_category[cat][v] = by_category[cat].get(v, 0) + 1
        if r.method:
            techniques.add(str(r.method))

    return {
        "total": total,
        "by_verdict": by_verdict,
        "by_category": by_category,
        "detected_techniques": sorted(techniques),
        "blocked_count": by_verdict.get("BLOCKED", 0),
        "ok_count": by_verdict.get("OK", 0),
    }
