"""
censprobe-control — Main entrypoint.

Lifecycle:
  1. Read RUNS_COUNT from env (default 5)
  2. git pull to get latest targets/*.yaml
  3. Run full probe suite N times (runner.run_all())
  4. Aggregate runs into baseline/latest.json via baseline_builder
  5. git add && git commit && git push
  6. Exit

Must run on a clean-jurisdiction VPS (DE/NL/FI) — not in Russia.
Results form the ground truth for all solo/client comparisons.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn

from censprobe_core.git_io import git_add_commit_push, git_pull
from censprobe_core.models import BaselineControlPoint
from censprobe_core.runner import ProbeRunner
from censprobe_core.server_meta import detect_server_meta

from censprobe_control.baseline_builder import build_baseline, save_baseline

# Bootstrap logging
logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    format="%(message)s",
    datefmt="[%H:%M:%S]",
)
logger = logging.getLogger("censprobe.control")
console = Console()

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))
CONTROL_ID = os.getenv("CONTROL_ID", "control-de-01")


@click.command()
@click.option(
    "--runs",
    envvar="RUNS_COUNT",
    default=5,
    show_default=True,
    help="Number of repeated probe runs to aggregate.",
)
@click.option("--skip-push", is_flag=True, default=False, help="Skip git push (local dev).")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(runs: int, skip_push: bool, verbose: bool) -> None:
    """
    Censprobe Control — generate ground-truth baseline from a clean-jurisdiction VPS.

    Run: docker compose --profile control up
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(Panel.fit(
        f"[bold cyan]Censprobe Control[/bold cyan]\n"
        f"Runs: [yellow]{runs}[/yellow]\n"
        f"Workspace: {WORKSPACE}\n"
        f"Control ID: {CONTROL_ID}",
        title="📡 Generating baseline",
    ))

    asyncio.run(_async_main(runs, skip_push))


async def _async_main(runs: int, skip_push: bool) -> None:
    # ── Step 1: git pull ──────────────────────────────────────────────────────
    console.print("[dim]Pulling latest targets...[/dim]")
    try:
        git_pull()
    except Exception as e:
        console.print(f"[yellow]Warning: git pull failed: {e}. Continuing.[/yellow]")

    # ── Step 2: Detect control-point metadata ─────────────────────────────────
    console.print("[dim]Detecting control-point metadata...[/dim]")
    server_meta = await detect_server_meta()
    control_point = BaselineControlPoint(
        control_id=CONTROL_ID,
        asn=server_meta.asn or "unknown",
        country=_detect_country(),
        city=server_meta.location or "unknown",
        ipv6_available=server_meta.ipv6_available,
    )
    console.print(
        f"[dim]Control point: ASN={control_point.asn} city={control_point.city} "
        f"IPv6={control_point.ipv6_available}[/dim]"
    )

    # ── Step 3: Run N probe rounds ────────────────────────────────────────────
    all_run_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running probe rounds...", total=runs)

        for i in range(1, runs + 1):
            progress.update(task, description=f"[cyan]Round {i}/{runs} ...")
            runner = ProbeRunner(workspace=WORKSPACE, test_id="control", mode="control")
            try:
                run_results = await runner.run_all(repeats=1)
                all_run_results.append(run_results)
                logger.info("Round %d/%d complete: %d results", i, runs, len(run_results))
            except Exception as e:
                logger.error("Round %d failed: %s — skipping", i, e)
            progress.advance(task)

    if not all_run_results:
        console.print("[red]All probe rounds failed — cannot build baseline.[/red]")
        raise SystemExit(1)

    console.print(
        f"[green]Completed {len(all_run_results)}/{runs} rounds "
        f"({sum(len(r) for r in all_run_results)} total results)[/green]"
    )

    # ── Step 4: Build and save baseline ───────────────────────────────────────
    console.print("[dim]Aggregating into baseline...[/dim]")
    targets_version = _detect_targets_version()
    baseline = build_baseline(
        runs=all_run_results,
        control_point=control_point,
        probe_core_version="0.3.0",
        targets_version=targets_version,
        validity_days=7,
    )
    saved_path = save_baseline(baseline, workspace=WORKSPACE)
    console.print(f"[green]Baseline saved:[/green] {saved_path.name}")
    _print_baseline_summary(baseline)

    # ── Step 5: git push ──────────────────────────────────────────────────────
    if not skip_push:
        console.print("[dim]Pushing baseline to GitHub...[/dim]")
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            git_add_commit_push(
                message=f"control: baseline {baseline.version} at {ts}",
                paths=[
                    str(WORKSPACE / "baseline"),
                ],
            )
            console.print("[green bold]✓ Baseline pushed to GitHub[/green bold]")
        except Exception as e:
            console.print(f"[red]Push failed: {e}[/red]")
            console.print("[yellow]Run 'git push' manually from /workspace[/yellow]")
    else:
        console.print("[yellow]--skip-push: skipped git push[/yellow]")

    console.print(Panel.fit(
        f"[bold green]Control baseline complete![/bold green]\n"
        f"Version: [yellow]{baseline.version}[/yellow]\n"
        f"Valid until: {baseline.validity_until.strftime('%Y-%m-%d') if baseline.validity_until else 'N/A'}\n"
        f"DNS entries: {len(baseline.dns)} | HTTP: {len(baseline.http)} | "
        f"Telegram: {len(baseline.telegram)} | Throttling: {len(baseline.throttling)}",
        title="✅ Done",
    ))


def _detect_country() -> str:
    """Try to detect country code from locale or environment."""
    return os.getenv("CONTROL_COUNTRY", "DE")


def _detect_targets_version() -> str:
    """Generate a version string for current targets/*.yaml."""
    try:
        result = subprocess.run(
            ["git", "log", "--format=%h", "-n", "1", "--", "targets/"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
        )
        hash_ = result.stdout.strip()
        date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        return f"{date}-{hash_}" if hash_ else date
    except Exception:
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _print_baseline_summary(baseline) -> None:
    """Print a short baseline summary."""
    from rich.table import Table

    table = Table(title="Baseline Summary", show_header=True)
    table.add_column("Category")
    table.add_column("Entries", justify="right")
    table.add_row("DNS domains", str(len(baseline.dns)))
    table.add_row("TLS domains", str(len(baseline.tls)))
    table.add_row("HTTP URLs", str(len(baseline.http)))
    table.add_row("Telegram endpoints", str(len(baseline.telegram)))
    table.add_row("Throttling domains", str(len(baseline.throttling)))
    table.add_row("SNI throttling", "yes" if baseline.sni_throttling else "no")
    console.print(table)


if __name__ == "__main__":
    main()
