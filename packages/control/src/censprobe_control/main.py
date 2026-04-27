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

from censprobe_core.git_io import git_add_commit_push, git_pull_async
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
        title="Generating baseline",
    ))

    asyncio.run(_async_main(runs, skip_push))


async def _async_main(runs: int, skip_push: bool) -> None:
    # ── Step 1: git pull ──────────────────────────────────────────────────────
    # Async wrapper so the synchronous subprocess.run inside git_pull (and
    # the cross-container fcntl flock wait) doesn't freeze the asyncio loop.
    console.print("[dim]Pulling latest targets...[/dim]")
    try:
        await git_pull_async()
    except Exception as e:
        console.print(f"[yellow]Warning: git pull failed: {e}. Continuing.[/yellow]")

    # ── Step 2: Detect control-point metadata ─────────────────────────────────
    console.print("[dim]Detecting control-point metadata...[/dim]")
    server_meta = await detect_server_meta()
    control_point = BaselineControlPoint(
        control_id=CONTROL_ID,
        asn=server_meta.asn or "unknown",
        country=_detect_country(server_meta),
        city=server_meta.location or "unknown",
        ipv6_available=server_meta.ipv6_available,
    )
    console.print(
        f"[dim]Control point: ASN={control_point.asn} city={control_point.city} "
        f"IPv6={control_point.ipv6_available}[/dim]"
    )

    # ── Step 3: Run N probe rounds ────────────────────────────────────────────
    # One ProbeRunner instance shared across rounds: instantiating per-iter
    # forced a re-read of baseline/latest.json + targets/*.yaml every round
    # for no benefit. The runner is stateless w.r.t. a single .run_all() call.
    runner = ProbeRunner(workspace=WORKSPACE, test_id="control", mode="control")
    all_run_results: list[list] = []
    failed_rounds = 0

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
            try:
                run_results = await runner.run_all(repeats=1)
                all_run_results.append(run_results)
                logger.info("Round %d/%d complete: %d results", i, runs, len(run_results))
            except Exception as e:
                failed_rounds += 1
                logger.error("Round %d failed: %s — skipping", i, e)
            progress.advance(task)

    if not all_run_results:
        console.print("[red]All probe rounds failed — cannot build baseline.[/red]")
        raise SystemExit(1)

    # Refuse to ship a baseline that was built from a too-small sample of
    # successful rounds: a baseline aggregated from only 1–2 surviving runs
    # would lock in noise as ground truth and trigger false-positive
    # "drift" verdicts for everyone comparing against it.
    failure_rate = failed_rounds / runs if runs else 0.0
    if failure_rate >= 0.7:
        console.print(
            f"[red]{failed_rounds}/{runs} rounds failed (≥70%). "
            "Refusing to publish a baseline built from this little data.[/red]"
        )
        raise SystemExit(2)
    if failed_rounds:
        console.print(
            f"[yellow]Warning: {failed_rounds}/{runs} rounds failed; "
            f"baseline aggregated from only {len(all_run_results)} runs.[/yellow]"
        )

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
    # Push runs in a worker thread so the retry-with-backoff loop doesn't
    # block the asyncio loop. We await it sequentially because the rest of
    # the function depends on knowing whether the push succeeded.
    if not skip_push:
        console.print("[dim]Pushing baseline to GitHub...[/dim]")
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: git_add_commit_push(
                    message=f"control: baseline {baseline.version} at {ts}",
                    paths=[str(WORKSPACE / "baseline")],
                ),
            )
            console.print("[green bold]Baseline pushed to GitHub successfully.[/green bold]")
        except Exception as e:
            console.print(f"[red]Push failed: {e}[/red]")
            console.print(
                "[yellow]The baseline has been committed locally. To publish manually:[/yellow]\n"
                f"  [bold]cd {WORKSPACE} && git push[/bold]\n"
                "[yellow]Alternatively, copy baseline/latest.json to the repository on another machine.[/yellow]"
            )
    else:
        console.print("[yellow]--skip-push: skipped git push[/yellow]")

    console.print(Panel.fit(
        f"[bold green]Control baseline complete.[/bold green]\n"
        f"Version: [yellow]{baseline.version}[/yellow]\n"
        f"Valid until: {baseline.validity_until.strftime('%Y-%m-%d') if baseline.validity_until else 'N/A'}\n"
        f"DNS entries: {len(baseline.dns)} | HTTP: {len(baseline.http)} | "
        f"Telegram: {len(baseline.telegram)} | Throttling: {len(baseline.throttling)}",
        title="Done",
    ))


def _detect_country(server_meta=None) -> str:
    """Pick a country code for the BaselineControlPoint.

    Preference order:
      1. ``CONTROL_COUNTRY`` env override (operator-specified deployment hint).
      2. ``server_meta.country`` (auto-detected from ipapi.is over HTTPS).
      3. Fallback ``"DE"`` — historical default; preserved so old setups
         that relied on the previous hardcoded value behave the same when
         metadata detection is unavailable.
    """
    env = os.getenv("CONTROL_COUNTRY")
    if env:
        return env
    if server_meta is not None and getattr(server_meta, "country", None):
        return server_meta.country
    return "DE"


def _detect_targets_version() -> str:
    """Generate a version string for current targets/*.yaml.

    Format: ``YYYY-MM-DD-<short-sha>[+dirty]``.

    A "+dirty" suffix is appended when targets/ has uncommitted modifications
    so two runs with locally-edited targets can never collide on the same
    version string — without it, baseline-drift detection silently breaks on
    dev boxes (the version stays identical even though the input changed).
    """
    date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    try:
        log = subprocess.run(
            ["git", "log", "--format=%h", "-n", "1", "--", "targets/"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError) as e:
        logger.debug("git not available for targets_version: %s", e)
        return date

    hash_ = (log.stdout or "").strip() if log.returncode == 0 else ""
    if not hash_:
        return date

    # Detect uncommitted modifications. `git diff --quiet` exits 0 if clean,
    # 1 if dirty, anything else on error — treat error as "not dirty" so we
    # don't accidentally permanently brand a healthy run as dirty.
    try:
        diff = subprocess.run(
            ["git", "diff", "--quiet", "--", "targets/"],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            check=False,
        )
        is_dirty = diff.returncode == 1
    except (FileNotFoundError, OSError):
        is_dirty = False

    suffix = "+dirty" if is_dirty else ""
    return f"{date}-{hash_}{suffix}"


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
