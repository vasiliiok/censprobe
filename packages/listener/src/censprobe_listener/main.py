"""
censprobe-listener — Main entrypoint.

Lifecycle:
  1. Read TEST_ID and SESSION_ID from env
  2. git pull to get latest protocols.yaml (or generate new one if first session)
  3. Start all 6 VPN protocol responders
  4. Wait for SIGINT (Ctrl+C) or SIGTERM
  5. Stop all responders
  6. Finalize results: compute verdicts per protocol
  7. Save report as reports/<TEST_ID>/server-listener-<SESSION_ID>-<ts>.json
  8. git add && git commit && git push
  9. Exit

Security note:
  All protocols run in test/dummy mode. No real traffic forwarding.
  Credentials are one-time per test session.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from censprobe_core.git_io import git_add_commit_push, git_pull
from censprobe_core.models import ListenerReport, ProtocolResult, Verdict
from censprobe_listener.credentials import (
    ProtocolCredentials,
    generate_credentials,
    load_protocols_yaml,
    save_protocols_yaml,
)
from censprobe_listener.echo_server import EchoServer
from censprobe_listener.openvpn_responder import OpenVPNResponder
from censprobe_listener.wg_responder import AmneziaWGResponder, WireGuardResponder
from censprobe_listener.ss_responder import ShadowsocksResponder
from censprobe_listener.vless_reality_wrapper import VlessRealityResponder
from censprobe_listener.hysteria_wrapper import HysteriaResponder

logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    format="%(message)s",
    datefmt="[%H:%M:%S]",
)
logger = logging.getLogger("censprobe.listener")
console = Console()

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))


@click.command()
@click.option("--test-id", envvar="TEST_ID", required=True, help="Test identifier")
@click.option("--session-id", envvar="SESSION_ID", required=True, help="Client network session identifier, e.g. client-home-rt-spb")
@click.option("--skip-push", is_flag=True, default=False, help="Skip git push (local dev)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(test_id: str, session_id: str, skip_push: bool, verbose: bool) -> None:
    """
    Censprobe Listener — expose VPN handshake endpoints, record what clients can reach.

    Run: TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb docker compose --profile listener up
    Stop: Ctrl+C → results saved and pushed automatically.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(Panel.fit(
        f"[bold cyan]Censprobe Listener[/bold cyan]\n"
        f"Test ID: [yellow]{test_id}[/yellow]\n"
        f"Session ID: [yellow]{session_id}[/yellow]\n"
        f"Workspace: {WORKSPACE}\n\n"
        "[dim]Press Ctrl+C to stop and save results.[/dim]",
        title="Starting listener",
    ))

    asyncio.run(_async_main(test_id, session_id, skip_push))


async def _async_main(test_id: str, session_id: str, skip_push: bool) -> None:
    # ── Step 1: git pull ──────────────────────────────────────────────────────
    try:
        git_pull()
    except Exception as e:
        console.print(f"[yellow]Warning: git pull failed: {e}[/yellow]")

    # ── Step 2: Load or generate credentials ─────────────────────────────────
    protocols_path = WORKSPACE / "reports" / test_id / "protocols.yaml"
    if not protocols_path.exists():
        console.print("[dim]Generating credentials for first session...[/dim]")
        creds = generate_credentials()
        save_protocols_yaml(creds, protocols_path)
        # Push credentials so client can read them
        if not skip_push:
            try:
                git_add_commit_push(
                    message=f"listener: credentials for {test_id}",
                    paths=[str(protocols_path)],
                )
                console.print("[green]Credentials pushed. Client can now run 'git pull' to obtain them.[/green]")
            except Exception as e:
                console.print(f"[red]Credentials push failed: {e}[/red]")
                console.print(
                    "[yellow]Client will not be able to obtain credentials via git pull.\n"
                    "To transfer credentials manually, copy the file:[/yellow]\n"
                    f"  [bold]{protocols_path}[/bold]\n"
                    "[yellow]to the client machine at the same relative path in the repository.[/yellow]"
                )
    else:
        console.print("[dim]Loading existing credentials...[/dim]")
        creds = load_protocols_yaml(protocols_path)

    # ── Step 3a: Start local echo server for SS/VLESS/Hy2 data phase ──────────
    echo_server = EchoServer()
    try:
        await echo_server.start()
    except Exception as e:
        console.print(f"[yellow]Warning: echo server failed to start: {e}[/yellow]")
        echo_server = None  # responders fall back to handshake-only signals

    # ── Step 3b: Start all responders ─────────────────────────────────────────
    responders, start_errors = await _start_responders(creds, echo_server)

    if not responders:
        console.print("[red]All responders failed to start. Exiting.[/red]")
        for name, err in start_errors.items():
            console.print(f"  [red]{name}:[/red] {err}")
        sys.exit(1)

    # Print status
    _print_responder_status(responders, start_errors, creds)
    console.print("\n[bold green]Listener is ready. Waiting for clients...[/bold green]")
    console.print("[dim]Press Ctrl+C to stop and save results.[/dim]\n")

    started_at = datetime.now(tz=timezone.utc)

    # ── Step 4: Wait for SIGINT ───────────────────────────────────────────────
    stop_event = asyncio.Event()

    def _handle_signal():
        console.print("\n[yellow]Stopping listener...[/yellow]")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    await stop_event.wait()

    stopped_at = datetime.now(tz=timezone.utc)
    duration = (stopped_at - started_at).total_seconds()

    # ── Step 5: Finalize BEFORE teardown (wg/awg lose their interface) ────────
    results: dict[str, ProtocolResult] = {}
    for name, responder in responders.items():
        pr = _finalize_protocol_result(name, responder)
        results[name] = pr

    # ── Step 6: Stop responders + echo server ─────────────────────────────────
    await _stop_responders(responders)
    if echo_server is not None:
        try:
            await echo_server.stop()
        except Exception as e:
            logger.warning("Echo server stop error: %s", e)

    # Print final table
    _print_final_results(results, duration)

    # ── Step 7: Save report ───────────────────────────────────────────────────
    report = ListenerReport(
        test_id=test_id,
        session_id=session_id,
        listener_started_at=started_at,
        listener_stopped_at=stopped_at,
        duration_sec=round(duration, 1),
        results=results,
    )
    report_path = _save_listener_report(report, test_id, session_id)
    console.print(f"[green]Report saved:[/green] {report_path.name}")

    # ── Step 8: git push ──────────────────────────────────────────────────────
    if not skip_push:
        try:
            ts = stopped_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            git_add_commit_push(
                message=f"listener: {test_id} session={session_id} at {ts}",
                paths=[str(WORKSPACE / "reports" / test_id)],
            )
            console.print("[green bold]Results pushed to GitHub successfully.[/green bold]")
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
        f"[bold green]Session complete.[/bold green]\n"
        f"Duration: {duration:.0f}s\n"
        f"Protocols tested: {len(results)}",
        title="Done",
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Responder lifecycle
# ─────────────────────────────────────────────────────────────────────────────

async def _start_responders(
    creds: ProtocolCredentials,
    echo_server: EchoServer | None,
) -> tuple[dict, dict]:
    """Start all protocol responders. Returns (started_dict, errors_dict)."""
    responders: dict = {}
    errors: dict = {}

    ss = ShadowsocksResponder(creds.ss_password_b64, creds.ss_port, creds.ss_method)
    vless = VlessRealityResponder(
        creds.vless_uuid, creds.vless_pvk, creds.vless_pbk,
        creds.vless_short_id, creds.vless_server_name, creds.vless_port,
    )
    hy2 = HysteriaResponder(creds.hy2_auth, creds.hy2_obfs_password, creds.hy2_port)

    # Inject echo_server into wrappers that need data-phase signal.
    for r in (ss, vless, hy2):
        r.echo_server = echo_server

    protocols_to_start = [
        ("openvpn", OpenVPNResponder(creds.openvpn_psk_b64, creds.openvpn_port)),
        ("wireguard", WireGuardResponder(
            creds.wg_server_private, creds.wg_client_public, creds.wg_preshared_key, creds.wg_port
        )),
        ("amneziawg", AmneziaWGResponder(
            creds.awg_server_private, creds.awg_client_public, creds.awg_preshared_key,
            creds.awg_port, creds.awg_jc, creds.awg_jmin, creds.awg_jmax,
            creds.awg_s1, creds.awg_s2,
            creds.awg_h1, creds.awg_h2, creds.awg_h3, creds.awg_h4,
        )),
        ("shadowsocks", ss),
        ("vless_reality", vless),
        ("hysteria2", hy2),
    ]

    for name, responder in protocols_to_start:
        try:
            await responder.start()
            responders[name] = responder
            logger.info("%s started", name)
        except Exception as e:
            logger.error("%s failed to start: %s", name, e)
            errors[name] = str(e)

    return responders, errors


async def _stop_responders(responders: dict) -> None:
    """Stop all protocol responders gracefully."""
    for name, responder in responders.items():
        try:
            await responder.stop()
        except Exception as e:
            logger.warning("Error stopping %s: %s", name, e)


def _finalize_protocol_result(name: str, responder) -> ProtocolResult:
    """Build ProtocolResult from responder state (snapshot BEFORE teardown)."""
    handshake_count = getattr(responder, "connection_count", 0) or \
                      getattr(responder, "handshake_count", 0)
    data_ok = bool(getattr(responder, "data_transfer_ok", False))

    pr = ProtocolResult(
        handshake_count=handshake_count,
        data_transfer_ok=data_ok,
    )
    pr.finalize()
    return pr


# ─────────────────────────────────────────────────────────────────────────────
# Report saving
# ─────────────────────────────────────────────────────────────────────────────

def _save_listener_report(report: ListenerReport, test_id: str, session_id: str) -> Path:
    """
    Save ListenerReport as pretty JSON.

    We intentionally do NOT gzip: git's pack format does its own zlib
    compression with delta chains across revisions, and gzipping upstream
    forces every commit to store a full new copy of the report.
    """
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    reports_dir = WORKSPACE / "reports" / test_id
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / f"server-listener-{session_id}-{ts}.json"

    out_path.write_text(
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# Rich display
# ─────────────────────────────────────────────────────────────────────────────

def _print_responder_status(responders: dict, errors: dict, creds: ProtocolCredentials) -> None:
    table = Table(title="Listener Status", show_header=True, header_style="bold cyan")
    table.add_column("Protocol", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Status")

    port_map = {
        "openvpn": f"UDP/{creds.openvpn_port}",
        "wireguard": f"UDP/{creds.wg_port}",
        "amneziawg": f"UDP/{creds.awg_port}",
        "shadowsocks": f"TCP/{creds.ss_port}",
        "vless_reality": f"TCP/{creds.vless_port}",
        "hysteria2": f"UDP/{creds.hy2_port}",
    }
    all_protocols = list(port_map.keys())

    for name in all_protocols:
        port = port_map.get(name, "?")
        if name in responders:
            table.add_row(name, port, "[green]Running[/green]")
        else:
            err = errors.get(name, "unknown error")
            table.add_row(name, port, f"[red]Failed: {err[:40]}[/red]")

    console.print(table)


def _print_final_results(results: dict[str, ProtocolResult], duration: float) -> None:
    table = Table(title=f"Session Results (duration: {duration:.0f}s)", header_style="bold magenta")
    table.add_column("Protocol", style="cyan")
    table.add_column("Verdict")
    table.add_column("Handshakes", justify="right")
    table.add_column("Data Transfer")

    for name, pr in results.items():
        verdict_str = {
            Verdict.OK: "[green]CONNECTED[/green]",
            Verdict.HANDSHAKE_ONLY: "[yellow]HANDSHAKE_ONLY[/yellow]",
            Verdict.BLOCKED: "[red]BLOCKED[/red]",
        }.get(pr.verdict, str(pr.verdict))
        table.add_row(
            name,
            verdict_str,
            str(pr.handshake_count),
            "yes" if pr.data_transfer_ok else "no",
        )

    console.print(table)


if __name__ == "__main__":
    main()
