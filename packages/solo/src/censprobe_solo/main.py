"""
censprobe-solo — Main entrypoint.

Lifecycle:
  1. Read TEST_ID from env
  2. If reports/<TEST_ID>/meta.yaml missing → auto-detect server info, create it
  3. Load baseline/latest.json + targets/*.yaml
  4. Run full probe suite (runner.run_all())
  5. Compute scores (scoring.compute_scores())
  6. Save report as reports/<TEST_ID>/server-solo-<timestamp>.json
  7. git add && git commit && git push
  8. Exit

Important: Solo must run BEFORE listener.
  Listener opens VPN ports → ТСПУ may intensify filtering of outbound traffic.
  Solo run after listener = biased results.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from censprobe_core.git_io import git_add_commit_push, git_pull_async
from censprobe_core.models import ListenerReport, ReportMeta, ServerMeta
from censprobe_core.runner import ProbeRunner
from censprobe_core.scoring import BLOCKING_VERDICTS, compute_scores
from censprobe_core.server_meta import detect_distro, detect_kernel, detect_server_meta

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
@click.option("--test-id", envvar="TEST_ID", required=True, help="Test identifier (e.g. selectel-spb-001)")
@click.option("--repeats", envvar="RUNS_COUNT", default=3, show_default=True, help="Number of test repeats per measurement")
@click.option("--skip-push", is_flag=True, default=False, help="Skip git push (local dev mode)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(test_id: str, repeats: int, skip_push: bool, verbose: bool) -> None:
    """
    Censprobe Solo — run all probe tests from the server's perspective.

    Run: TEST_ID=selectel-spb-001 docker compose --profile solo up
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(Panel.fit(
        f"[bold cyan]Censprobe Solo[/bold cyan]\n"
        f"Test ID: [yellow]{test_id}[/yellow]\n"
        f"Workspace: {WORKSPACE}\n"
        f"Repeats: {repeats}",
        title="Starting",
    ))

    asyncio.run(_async_main(test_id, repeats, skip_push))


async def _async_main(test_id: str, repeats: int, skip_push: bool) -> None:
    # ── Step 1: git pull ──────────────────────────────────────────────────────
    # Use the async wrapper so the synchronous subprocess.run inside git_pull
    # (and the cross-container fcntl flock wait) doesn't freeze the asyncio
    # loop while httpx clients in detect_server_meta etc. are pending.
    console.print("[dim]Pulling latest from GitHub...[/dim]")
    try:
        await git_pull_async()
    except Exception as e:
        console.print(f"[yellow]Warning: git pull failed: {e}. Continuing with local state.[/yellow]")

    # ── Step 2: Initialize meta.yaml if needed ───────────────────────────────
    meta_path = WORKSPACE / "reports" / test_id / "meta.yaml"
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
        meta = ReportMeta(
            test_id=test_id,
            server=server_meta,
            purpose="vpn-entry",
            baseline_version=_get_baseline_version(),
        )
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(yaml.dump(meta.model_dump(mode="json"), allow_unicode=True))
        console.print(f"[green]Created meta.yaml for {test_id}[/green]")
    else:
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

    # ── Step 3: Run all tests ─────────────────────────────────────────────────
    runner = ProbeRunner(workspace=WORKSPACE, test_id=test_id, mode="solo")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running probe tests...", total=None)
        results = await runner.run_all(repeats=repeats)
        progress.update(task, description=f"[green]Completed — {len(results)} results")

    # ── Step 4: Load any existing listener reports ───────────────────────────
    listener_reports = _load_listener_reports(WORKSPACE / "reports" / test_id)
    if listener_reports:
        console.print(f"[dim]Found {len(listener_reports)} listener session(s) — incorporating into scores[/dim]")

    # ── Step 5: Compute scores for the local CLI summary ─────────────────────
    # Scores are NOT written into the saved JSON — they would be stale the
    # moment a listener report lands later, and downstream readers
    # (sync-api) recomputes from raw results + listener data.
    # Here we use them only to print the operator-facing summary panel.
    scores = compute_scores(solo_results=results, listener_reports=listener_reports or None)

    # ── Step 6: Print summary ─────────────────────────────────────────────────
    _print_summary(results, scores)

    # ── Step 7: Save report ───────────────────────────────────────────────────
    report_path = runner.save_report(results, server_meta=server_meta)
    console.print(f"[green]Report saved:[/green] {report_path.name}")

    # ── Step 8: git push ──────────────────────────────────────────────────────
    # Push runs in a thread pool so its retry-with-backoff loop doesn't park
    # the event loop. Runs sequentially in main flow so we still surface a
    # success/failure message before exiting.
    if not skip_push:
        console.print("[dim]Pushing to GitHub...[/dim]")
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: git_add_commit_push(
                    message=f"solo: {test_id} report at {datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
                    paths=[str(WORKSPACE / "reports" / test_id)],
                ),
            )
            console.print("[green bold]Pushed to GitHub successfully.[/green bold]")
        except Exception as e:
            console.print(f"[red]Push failed: {e}[/red]")
            console.print(
                "[yellow]The report has been committed locally. To publish results manually:[/yellow]\n"
                f"  [bold]cd {WORKSPACE} && git push[/bold]\n"
                "[yellow]Alternatively, copy the report file from:[/yellow]\n"
                f"  [bold]{WORKSPACE / 'reports' / test_id}/[/bold]"
            )
    else:
        console.print("[yellow]--skip-push: skipped git push[/yellow]")

    console.print(Panel.fit(
        f"[bold green]Solo complete.[/bold green]\n"
        f"Overall score: [yellow]{scores.overall}/100[/yellow]\n"
        f"Techniques detected: {', '.join(scores.detected_techniques) or 'none'}",
        title="Done",
    ))


def _get_baseline_version() -> str:
    """Read baseline version from baseline/latest.json.

    Distinguishes "no baseline yet" (expected on a fresh checkout
    before `control` has run) from "baseline is corrupt" (a real
    error the operator needs to see). The former is recorded as
    ``"stub"`` in meta.yaml; the latter raises.
    """
    path = WORKSPACE / "baseline" / "latest.json"
    if not path.exists():
        return "stub"
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(
            f"baseline/latest.json exists but cannot be parsed: {e}. "
            "Either delete it (to fall back to 'stub') or regenerate via "
            "'docker compose --profile control up'."
        ) from e
    if not isinstance(data, dict):
        raise RuntimeError(
            f"baseline/latest.json top level must be a JSON object, got {type(data).__name__}"
        )
    return data.get("version", "stub")


def _print_summary(results, scores) -> None:
    """Print a rich summary table of results."""
    table = Table(title="Results by Category", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan")
    table.add_column("OK", style="green", justify="right")
    table.add_column("Blocked", style="red", justify="right")
    table.add_column("Other", style="yellow", justify="right")
    table.add_column("Total", justify="right")

    blocked_strs = {str(v) for v in BLOCKING_VERDICTS}
    by_cat: dict[str, dict[str, int]] = {}
    for r in results:
        cat = r.category
        if cat not in by_cat:
            by_cat[cat] = {"ok": 0, "blocked": 0, "other": 0}
        v = str(r.verdict)
        if v == "OK":
            by_cat[cat]["ok"] += 1
        elif v in blocked_strs:
            by_cat[cat]["blocked"] += 1
        else:
            by_cat[cat]["other"] += 1

    for cat, counts in sorted(by_cat.items()):
        total = sum(counts.values())
        table.add_row(cat, str(counts["ok"]), str(counts["blocked"]), str(counts["other"]), str(total))

    console.print(table)
    console.print(f"\n[bold]Scores:[/bold] entry=[yellow]{scores.entry_score}[/yellow] "
                  f"exit=[yellow]{scores.exit_score}[/yellow] "
                  f"relay=[yellow]{scores.relay_score}[/yellow] "
                  f"overall=[bold yellow]{scores.overall}[/bold yellow]/100")

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
