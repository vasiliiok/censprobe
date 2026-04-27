"""
reporter/main.py — CLI HTML/PDF report generator.

Usage:
  # HTML
  docker compose --profile reporter run --rm reporter --test-id selectel-spb-001

  # PDF
  docker compose --profile reporter run --rm reporter --test-id selectel-spb-001 --pdf

  # Output to specific file
  docker compose --profile reporter run --rm reporter --test-id selectel-spb-001 -o /workspace/reports/selectel-spb-001/report.html

Reads:
  - reports/<test_id>/meta.yaml
  - reports/<test_id>/server-solo-*.json  (latest)
  - reports/<test_id>/server-listener-*.json (all)

Writes:
  - reports/<test_id>/report.html   (default)
  - reports/<test_id>/report.pdf    (with --pdf)
"""
from __future__ import annotations

import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import click
import yaml
from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from censprobe_core.models import ListenerReport, TestResult
from censprobe_core.scoring import compute_scores

logger = logging.getLogger(__name__)
console = Console()

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))
# Templates are bundled with the package (src/reporter/templates/) so they
# resolve correctly both from a source checkout and after `pip install`.
# The previous `parent.parent.parent / "templates"` walked above
# site-packages and could not find anything once the wheel was installed.
TEMPLATES_DIR = Path(__file__).parent / "templates"


@click.command()
@click.option("--test-id", envvar="TEST_ID", required=True, help="Test identifier")
@click.option("--output", "-o", default=None, help="Output path (default: reports/<test_id>/report.html)")
@click.option("--pdf", "make_pdf", is_flag=True, default=False, help="Also generate PDF via WeasyPrint")
@click.option("--workspace", envvar="WORKSPACE", default=str(WORKSPACE), help="Repository workspace path")
def main(test_id: str, output: Optional[str], make_pdf: bool, workspace: str) -> None:
    """
    Generate HTML (and optionally PDF) report for a given test_id.

    Run: docker compose --profile reporter run --rm reporter --test-id selectel-spb-001
    """
    ws = Path(workspace)
    reports_dir = ws / "reports" / test_id

    if not reports_dir.exists():
        console.print(f"[red]Report directory not found: {reports_dir}[/red]")
        sys.exit(1)

    console.print(f"[dim]Building report for [bold]{test_id}[/bold]...[/dim]")

    # Load all data
    ctx = _build_context(test_id, reports_dir)

    # Render HTML
    html = _render_html(ctx)

    # Determine output path
    if output:
        out_path = Path(output)
    else:
        out_path = reports_dir / "report.html"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    console.print(f"[green]HTML report generated:[/green] {out_path}")

    # PDF
    if make_pdf:
        pdf_path = out_path.with_suffix(".pdf")
        try:
            from weasyprint import HTML
            HTML(string=html, base_url=str(out_path.parent)).write_pdf(str(pdf_path))
            console.print(f"[green]PDF report generated:[/green]  {pdf_path}")
        except ImportError:
            console.print("[yellow]WeasyPrint not installed — skipping PDF[/yellow]")
        except Exception as e:
            console.print(f"[red]PDF generation failed: {e}[/red]")


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def _build_context(test_id: str, reports_dir: Path) -> dict[str, Any]:
    """Load all report files and assemble template context."""
    # meta.yaml
    meta: dict = {}
    meta_path = reports_dir / "meta.yaml"
    if meta_path.exists():
        meta = yaml.safe_load(meta_path.read_text()) or {}

    server: dict = meta.get("server", {})

    # Find latest solo report.
    solo_files = sorted(
        reports_dir.glob("server-solo-*.json"),
        reverse=True,
    )
    results_all: list[dict] = []
    solo_data: Optional[dict] = None
    if solo_files:
        solo_data = _load_report(solo_files[0])
        results_all = solo_data.get("results", []) if solo_data else []
        if not server and solo_data:
            server = solo_data.get("server_meta", {}) or {}

    # Group results by category
    by_category: dict[str, list] = defaultdict(list)
    for r in results_all:
        by_category[r.get("category", "other")].append(r)

    # Sort: blocked first within each category
    verdict_order = {
        "BLOCKED": 0, "DNS_BLOCKED": 0, "IP_DROPPED": 1, "RST_INJECTED": 1,
        "REFUSED": 2, "DOH_BLOCKED": 2, "DNS_POISONING": 3,
        "THROTTLED": 4, "YOUTUBE_SNI_THROTTLED": 4,
        "ANOMALY": 5, "HANDSHAKE_ONLY": 6,
        "GEOBLOCK_NOT_CENSORSHIP": 7, "INCONCLUSIVE": 8, "OK": 9, "ERROR": 10,
    }
    for cat in by_category:
        by_category[cat].sort(key=lambda r: verdict_order.get(r.get("verdict", ""), 5))

    # Listener sessions.
    listener_files = sorted(reports_dir.glob("server-listener-*.json"))
    listener_sessions = []
    for lf in listener_files:
        ld = _load_report(lf)
        if not ld:
            continue
        session_id = ld.get("session_id", lf.stem)
        duration = ld.get("duration_sec")
        raw_results = ld.get("results", {})
        proto_results = [
            {
                "protocol": proto,
                "verdict": pr.get("verdict", "BLOCKED"),
                "handshake_count": pr.get("handshake_count", 0),
                "data_transfer_ok": pr.get("data_transfer_ok", False),
                "avg_rtt_ms": pr.get("avg_rtt_ms"),
            }
            for proto, pr in raw_results.items()
        ]
        listener_sessions.append({
            "session_id": session_id,
            "duration_sec": duration,
            "results": proto_results,
        })

    # Compute scores fresh from raw solo + listener reports. Solo's saved
    # JSON intentionally has no `scores` field anymore — the data on disk
    # might post-date solo's run, so any frozen score would lag.
    computed = _compute_scores_safely(results_all, listener_files)
    scores = {
        "Overall": computed.overall if computed else 0.0,
        "Entry":   computed.entry_score if computed else 0.0,
        "Exit":    computed.exit_score if computed else 0.0,
        "Relay":   computed.relay_score if computed else 0.0,
    }
    techniques = list(computed.detected_techniques) if computed and computed.detected_techniques else []
    protocols = list(computed.recommended_protocols) if computed and computed.recommended_protocols else []

    return {
        "meta": {
            "test_id": test_id,
            "description": meta.get("description"),
            "purpose": meta.get("purpose", "vpn-entry"),
        },
        "server": {
            "asn": server.get("asn"),
            "as_name": server.get("as_name"),
            "location": server.get("location"),
            "provider": server.get("provider"),
            "ipv4_masked": server.get("ipv4_masked"),
            "distro": server.get("distro"),
            "ipv6_available": server.get("ipv6_available", False),
        },
        "scores": scores,
        "techniques": techniques if isinstance(techniques, list) else [techniques],
        "protocols": protocols if isinstance(protocols, list) else [protocols],
        "results_by_category": dict(by_category),
        "listener_sessions": listener_sessions,
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _load_report(path: Path) -> Optional[dict]:
    """Load a .json report file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("Could not load %s: %s", path.name, e)
        return None


def _compute_scores_safely(
    raw_results: list[dict], listener_files: list[Path]
):
    """Recompute scores from raw solo results + listener reports.

    Returns a ServerScores or None if input is unusable. Wrapped in
    broad try/except because reporter is a presentation layer — a
    schema drift in one report file should never crash the HTML build.
    """
    if not raw_results:
        return None
    try:
        solo_models: list[TestResult] = []
        for r in raw_results:
            try:
                solo_models.append(TestResult.model_validate(r))
            except Exception:
                continue
        if not solo_models:
            return None
        listener_models: list[ListenerReport] = []
        for lf in listener_files:
            data = _load_report(lf)
            if not isinstance(data, dict):
                continue
            try:
                listener_models.append(ListenerReport.model_validate(data))
            except Exception:
                continue
        return compute_scores(
            solo_results=solo_models,
            listener_reports=listener_models or None,
        )
    except Exception as e:
        logger.warning("score computation failed: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HTML rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render_html(ctx: dict) -> str:
    """Render the HTML report from Jinja2 template."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")
    return template.render(**ctx)


if __name__ == "__main__":
    main()
