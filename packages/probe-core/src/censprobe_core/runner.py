"""
runner.py — Async orchestrator for all probe modules.

Runs all measurement modules, collects TestResult objects, handles N repeats.
Used by solo, client, and control containers.
"""
from __future__ import annotations

import asyncio
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
        self.baseline: BaselineData = load_baseline(
            workspace / "baseline" / "latest.json",
            # Control *builds* the baseline — a stub on its first ever run is
            # expected; no need to log a warning every round.
            quiet_if_stub=(mode == "control"),
        )
        self.comparator = BaselineComparator(self.baseline)
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

        Tracks per-module failures in ``self.module_failures`` so the report
        summary can surface which phases produced no data — otherwise scoring
        on partial results silently degrades to neutral 50% and the operator
        has no signal that half the measurements are missing.
        """
        results: list[TestResult] = []
        self.module_failures: list[str] = []

        logger.info("[%s] Starting probe run (mode=%s, repeats=%d)", self.test_id, self.mode, repeats)

        # ── 1. DNS ────────────────────────────────────────────────────────────
        logger.info("[%s] Running DNS tests...", self.test_id)
        dns_domains = self._collect_dns_domains()
        try:
            dns_results = await dns.run_dns_tests(dns_domains, self.comparator, repeats)
            results.extend(dns_results)
            logger.info("[%s] DNS: %d results", self.test_id, len(dns_results))
        except Exception:
            logger.exception("[%s] DNS module failed", self.test_id)
            self.module_failures.append("dns")

        # ── 2. TCP ────────────────────────────────────────────────────────────
        logger.info("[%s] Running TCP reachability tests...", self.test_id)
        tcp_targets = self._collect_tcp_targets()
        try:
            tcp_results = await tcp.run_tcp_tests(tcp_targets, repeats)
            results.extend(tcp_results)
            logger.info("[%s] TCP: %d results", self.test_id, len(tcp_results))
        except Exception:
            logger.exception("[%s] TCP module failed", self.test_id)
            self.module_failures.append("tcp")

        # ── 3. TLS/SNI ───────────────────────────────────────────────────────
        logger.info("[%s] Running TLS/SNI tests...", self.test_id)
        tls_targets = self._collect_tls_targets()
        try:
            tls_results = await tls.run_tls_tests(tls_targets, repeats, self.comparator)
            results.extend(tls_results)
            logger.info("[%s] TLS: %d results", self.test_id, len(tls_results))
        except Exception:
            logger.exception("[%s] TLS module failed", self.test_id)
            self.module_failures.append("tls")

        # ── 4. HTTP/HTTPS ─────────────────────────────────────────────────────
        logger.info("[%s] Running HTTP tests...", self.test_id)
        http_targets = self._collect_http_targets()
        try:
            http_results = await http.run_http_tests(http_targets, self.comparator, repeats)
            results.extend(http_results)
            logger.info("[%s] HTTP: %d results", self.test_id, len(http_results))
        except Exception:
            logger.exception("[%s] HTTP module failed", self.test_id)
            self.module_failures.append("http")

        # ── 5. Telegram ───────────────────────────────────────────────────────
        logger.info("[%s] Running Telegram tests...", self.test_id)
        try:
            tg_results = await telegram.run_telegram_tests(self.comparator)
            results.extend(tg_results)
            logger.info("[%s] Telegram: %d results", self.test_id, len(tg_results))
        except Exception:
            logger.exception("[%s] Telegram module failed", self.test_id)
            self.module_failures.append("telegram")

        # ── 6. Throttling (Method A + B) ──────────────────────────────────────
        logger.info("[%s] Running throttling tests...", self.test_id)
        try:
            thr_results = await throttling.run_throttling_tests(self.comparator)
            results.extend(thr_results)
            logger.info("[%s] Throttling: %d results", self.test_id, len(thr_results))
        except Exception:
            logger.exception("[%s] Throttling module failed", self.test_id)
            self.module_failures.append("throttling")

        # ── 7. Middlebox ──────────────────────────────────────────────────────
        logger.info("[%s] Running middlebox tests...", self.test_id)
        try:
            mb_results = await middlebox.run_middlebox_tests()
            results.extend(mb_results)
            logger.info("[%s] Middlebox: %d results", self.test_id, len(mb_results))
        except Exception:
            logger.exception("[%s] Middlebox module failed", self.test_id)
            self.module_failures.append("middlebox")

        # ── 8. Protocol signatures (solo-only, no listener needed) ────────────
        logger.info("[%s] Protocol signature tests...", self.test_id)
        try:
            proto_results = await protocols.run_protocol_tests(control_endpoints=None)
            results.extend(proto_results)
        except Exception:
            logger.exception("[%s] Protocol module failed", self.test_id)
            self.module_failures.append("protocols")

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
        """Collect (ip, port) pairs for TCP reachability tests."""
        targets: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()

        # Telegram DCs
        tg = self._load_targets("telegram")
        for dc in tg.get("api_datacenters", []):
            for port in dc.get("ports", [443]):
                if ip := dc.get("ipv4"):
                    entry = (ip, port)
                    if entry not in seen:
                        seen.add(entry)
                        targets.append(entry)

        # Additional explicit TCP targets from other YAML files
        for tf in ["news", "social", "messengers"]:
            data = self._load_targets(tf)
            for t in data.get("targets", []):
                for ip_port in t.get("tcp_endpoints", []):
                    if ":" in str(ip_port):
                        ip, port_s = str(ip_port).rsplit(":", 1)
                        try:
                            entry = (ip, int(port_s))
                            if entry not in seen:
                                seen.add(entry)
                                targets.append(entry)
                        except ValueError:
                            pass

        return targets[:30]  # cap to avoid excessive tests

    def _collect_tls_targets(self) -> list[dict]:
        """Collect TLS test targets from all target YAML files."""
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
                    })

        # Always include a few known-blocked domains even if not in YAMLs
        priority = [
            {"domain": "meduza.io", "blocked_sni": "meduza.io", "url": "https://meduza.io"},
            {"domain": "instagram.com", "blocked_sni": "instagram.com", "url": "https://instagram.com"},
            {"domain": "youtube.com", "blocked_sni": "youtube.com", "url": "https://youtube.com"},
        ]
        for p in priority:
            if p["domain"] not in seen_domains:
                targets.insert(0, p)
                seen_domains.add(p["domain"])

        return targets

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
        Serialize results as pretty JSON and save.

        Reports are plain .json: git's pack format already deflates textual
        blobs with zlib and computes delta chains across revisions, so
        gzipping upstream would defeat delta compression and make the
        .git directory grow quickly.
        """
        if output_path is None:
            ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
            reports_dir = self.workspace / "reports" / self.test_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            # Filename embeds the runner mode so a future caller using the
            # same helper from control/listener-side doesn't end up with a
            # misleading "server-solo-*" report on disk.
            mode_label = self.mode if self.mode in ("solo", "control") else "report"
            output_path = reports_dir / f"server-{mode_label}-{ts}.json"

        report_data = {
            "test_id": self.test_id,
            "report_type": self.mode,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "probe_core_version": "0.1.0",
            "baseline_version": self.baseline.version,
            "server_meta": server_meta.model_dump() if server_meta else None,
            "scores": scores.model_dump() if scores else None,
            "results": [r.model_dump(mode="json") for r in results],
            "summary": _summarize(results, module_failures=list(self.module_failures)),
        }

        output_path.write_text(
            json.dumps(report_data, default=str, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        logger.info("Report saved: %s (%d bytes)", output_path, output_path.stat().st_size)
        return output_path


def _summarize(results: list[TestResult], module_failures: Optional[list[str]] = None) -> dict:
    """Quick summary statistics for the report.

    ``module_failures`` lists modules that raised before producing any
    results (DNS unreachable, import error, etc.). Surfaced so the
    dashboard can flag scoring done on partial data instead of treating
    a half-empty run as legitimate "neutral 50%".
    """
    # Verdicts that mean "this target was actually censored / unreachable",
    # not just "we didn't get a clean OK". Keep this in sync with the
    # dashboard's "blocked" filter (packages/dashboard/grafana/dashboards).
    BLOCKED_VERDICTS = {
        "BLOCKED",
        "DNS_BLOCKED",
        "DOH_BLOCKED",
        "DNS_POISONING",
        "IP_DROPPED",
        "RST_INJECTED",
        "REFUSED",
        "THROTTLED",
        "YOUTUBE_SNI_THROTTLED",
    }

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
        if r.method:
            techniques.add(str(r.method))
        if v in BLOCKED_VERDICTS:
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
