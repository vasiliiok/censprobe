"""
censprobe-solo — Main entrypoint.

Lifecycle:
  1. Read TEST_ID from env
  2. If reports/<TEST_ID>/meta.yaml missing → auto-detect server info, create it
  3. Load targets/*.yaml
  4. Run full probe suite (runner.run_all())
  5. Compute scores (scoring.compute_scores())
  6. Save report as reports/<TEST_ID>/server-solo-<timestamp>.json
  7. Exit. Publishing is manual: `git add reports/ && git push` from the host
     when you're ready to share results.

Important: Solo must run BEFORE listener.
  Listener opens VPN ports → ТСПУ may intensify filtering of outbound traffic.
  Solo run after listener = biased results.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import click
import yaml
from censprobe_core.config import load_config
from censprobe_core.models import ListenerReport, ReportMeta, ServerMeta, ServerScores, TestResult
from censprobe_core.runner import ProbeRunner
from censprobe_core.scoring import BLOCKING_VERDICT_STRINGS, compute_scores
from censprobe_core.server_meta import (
    detect_distro,
    detect_kernel,
    detect_server_meta,
    set_vantage_country,
)
from censprobe_core.utils import validate_id
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Bootstrap logging (after imports to avoid E402)
logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    format="%(message)s",
    datefmt="[%H:%M:%S]",
)
logger = logging.getLogger(__name__)

console = Console()
WORKSPACE = Path("/workspace")


@click.command()
@click.option(
    "--test-id", envvar="TEST_ID", required=True, help="Test identifier (e.g. selectel-spb-001)"
)
@click.option(
    "--repeats",
    envvar="RUNS_COUNT",
    required=True,
    type=int,
    help="Number of test repeats per measurement (set via RUNS_COUNT in .env)",
)
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(test_id: str, repeats: int, verbose: bool) -> None:
    """
    Censprobe Solo — run all probe tests from the server's perspective.

    Run: TEST_ID=selectel-spb-001 docker compose --profile solo up
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        validate_id("--test-id", test_id)
    except ValueError as e:
        raise click.BadParameter(str(e)) from e

    console.print(
        Panel.fit(
            f"[bold cyan]Censprobe Solo[/bold cyan]\n"
            f"Test ID: [yellow]{test_id}[/yellow]\n"
            f"Workspace: {WORKSPACE}\n"
            f"Repeats: {repeats}",
            title="Starting",
        )
    )

    asyncio.run(_async_main(test_id, repeats))


async def _detect_or_load_server_meta(test_id: str, meta_path: Path) -> ServerMeta:
    """Either auto-detect server meta into a fresh meta.yaml, or load+validate the existing one.

    Extracted so ``_async_main`` stays under Sonar's S3776 cognitive
    complexity threshold.
    """
    if not meta_path.exists():
        console.print("[dim]Detecting server metadata...[/dim]")
        try:
            server_meta = await detect_server_meta()
        except Exception as e:
            logger.warning("Server metadata detection failed: %s", e)
            console.print(
                "[yellow]Warning: could not auto-detect server metadata. "
                "Network may be unreachable. Continuing with empty metadata.[/yellow]"
            )
            server_meta = ServerMeta()
        meta = ReportMeta(test_id=test_id, server=server_meta)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(yaml.dump(meta.model_dump(mode="json"), allow_unicode=True))
        console.print(f"[green]Created meta.yaml for {test_id}[/green]")
        return server_meta

    console.print(f"[dim]Using existing meta.yaml for {test_id}[/dim]")
    # A corrupt meta.yaml is a real operator-visible error: the file
    # is the only place we record provider/ASN/country, and silently
    # re-detecting (or worse, falling through to empty metadata)
    # would attribute every result in this run to "unknown" without
    # the operator noticing. Fail loudly so they can either repair
    # or delete the file and re-run.
    raw = yaml.safe_load(meta_path.read_text()) or {}
    if not isinstance(raw, dict):
        raise RuntimeError(
            f"{meta_path} is corrupt: top level must be a YAML mapping, "
            f"got {type(raw).__name__}. Delete or fix the file and re-run."
        )
    server_meta = ServerMeta.model_validate(raw.get("server", {}))

    # Backfill kernel/distro for meta.yaml created before this code
    # populated those fields. Both detectors are local (uname /
    # /etc/os-release) so this is cheap and offline-safe.
    if not server_meta.kernel:
        server_meta.kernel = detect_kernel()
    if not server_meta.distro:
        server_meta.distro = detect_distro()
    return server_meta


async def _async_main(test_id: str, repeats: int) -> None:
    # ── Step 0: Load top-level config ────────────────────────────────────────
    # censprobe.yaml is required and must be fully populated. A missing or
    # malformed file is a fatal startup error — no fallback defaults exist.
    try:
        load_config(WORKSPACE)
    except ValueError as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise click.ClickException(str(e)) from e

    # ── Step 1: Initialize meta.yaml if needed ───────────────────────────────
    meta_path = WORKSPACE / "reports" / test_id / "meta.yaml"
    server_meta = await _detect_or_load_server_meta(test_id, meta_path)

    # Make vantage country available to measurement modules so RU-specific
    # attribution heuristics (TCP RST timing, QUIC drop, throttling target
    # geo) can gate themselves and not fire false positives on, e.g., a
    # Frankfurt VM probing the same domains.
    cc = (
        server_meta.endpoint.location.country_code
        if server_meta.endpoint and server_meta.endpoint.location
        else None
    )
    set_vantage_country(cc)
    if cc:
        console.print(f"[dim]Vantage: {cc}[/dim]")

    # ── Step 2: Run all tests ─────────────────────────────────────────────────
    runner = ProbeRunner(workspace=WORKSPACE, test_id=test_id)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running probe tests...", total=None)
        results = await runner.run_all(repeats=repeats)
        progress.update(task, description=f"[green]Completed — {len(results)} results")

    # ── Step 3: Load any existing listener reports ───────────────────────────
    listener_reports = _load_listener_reports(WORKSPACE / "reports" / test_id)
    if listener_reports:
        console.print(
            f"[dim]Found {len(listener_reports)} listener session(s) — "
            "incorporating into scores[/dim]"
        )

    # ── Step 4: Compute scores for the local CLI summary ─────────────────────
    # Scores are NOT written into the saved JSON — they would be stale the
    # moment a listener report lands later, and downstream readers
    # (sync-api) recomputes from raw results + listener data.
    # Here we use them only to print the operator-facing summary panel.
    scores = compute_scores(solo_results=results, listener_reports=listener_reports or None)

    # ── Step 5: Print summary ─────────────────────────────────────────────────
    _print_summary(results, scores)

    # ── Step 6: Save report ───────────────────────────────────────────────────
    report_path = runner.save_report(results, server_meta=server_meta)
    console.print(f"[green]Report saved:[/green] {report_path}")
    console.print(
        "[dim]Publishing is manual: review the file, then "
        "`git add reports/ && git commit && git push` from the host.[/dim]"
    )

    note_partial = " [dim](no listener data — partial)[/dim]"
    overall_note = "" if scores.listener_session_count > 0 else note_partial
    console.print(
        Panel.fit(
            f"[bold green]Solo complete.[/bold green]\n"
            f"Overall score: [yellow]{scores.overall}/100[/yellow]{overall_note}\n"
            f"Techniques detected: {', '.join(scores.detected_techniques) or 'none'}",
            title="Done",
        )
    )


def _print_summary(results: list[TestResult], scores: ServerScores) -> None:
    """Print a rich summary table of results."""
    table = Table(title="Results by Category", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan")
    table.add_column("OK", style="green", justify="right")
    table.add_column("Blocked", style="red", justify="right")
    table.add_column("Other", style="yellow", justify="right")
    table.add_column("Total", justify="right")

    by_cat: dict[str, dict[str, int]] = {}
    for r in results:
        cat = r.category
        if cat not in by_cat:
            by_cat[cat] = {"ok": 0, "blocked": 0, "other": 0}
        v = str(r.verdict)
        if v == "OK":
            by_cat[cat]["ok"] += 1
        elif v in BLOCKING_VERDICT_STRINGS:
            by_cat[cat]["blocked"] += 1
        else:
            by_cat[cat]["other"] += 1

    for cat, counts in sorted(by_cat.items()):
        total = sum(counts.values())
        table.add_row(
            cat, str(counts["ok"]), str(counts["blocked"]), str(counts["other"]), str(total)
        )

    console.print(table)
    has_listener = scores.listener_session_count > 0
    overall_note = "" if has_listener else " [dim](no listener data)[/dim]"
    # entry_score is built on a neutral 0.5 fallback for protocol_reachability
    # when no listener session reports exist, and overall already excludes
    # entry in that case (mean of exit+relay only). Render entry as N/A so
    # the printed numbers match overall instead of looking like broken math.
    entry_display = f"[yellow]{scores.entry_score}[/yellow]" if has_listener else "[dim]N/A[/dim]"
    console.print(
        f"\n[bold]Scores:[/bold] entry={entry_display} "
        f"exit=[yellow]{scores.exit_score}[/yellow] "
        f"relay=[yellow]{scores.relay_score}[/yellow] "
        f"overall=[bold yellow]{scores.overall}[/bold yellow]/100{overall_note}"
    )

    if scores.throttling_detected:
        console.print("[red]Throttling detected.[/red]")
    if scores.detected_techniques:
        console.print(f"[red]Censorship techniques:[/red] {', '.join(scores.detected_techniques)}")


def _load_listener_reports(reports_dir: Path) -> list[ListenerReport]:
    """Load all server-listener-*.json files from the test_id reports directory.

    Returns empty list if none exist or directory doesn't exist.
    """
    if not reports_dir.exists():
        return []

    reports: list[ListenerReport] = []
    for path in sorted(reports_dir.glob("server-listener-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            reports.append(ListenerReport.model_validate(data))
            logger.debug("Loaded listener report: %s", path.name)
        except Exception as e:
            logger.warning("Could not load %s: %s", path.name, e)

    return reports


if __name__ == "__main__":
    main()
