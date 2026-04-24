"""
censprobe-client — Main entrypoint.

Lifecycle:
  1. Read TEST_ID and SESSION_ID from env
  2. git pull to get latest protocols.yaml (credentials from listener)
  3. Read SERVER_HOST from env (IP of the server running listener)
  4. Run handshake probes for all 6 protocols (with jitter between them)
  5. Print results to stdout — NO git commits, NO network writes
  6. Exit

Security note:
  The client never commits or writes anything to the repository.
  All results are only printed to stdout.
  SERVER_HOST is required — never resolved from DNS to prevent correlation.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from censprobe_core.git_io import git_pull
from censprobe_core.models import Verdict
from censprobe_core.protocol_probes import (
    ProbeResult,
    probe_hysteria2,
    probe_openvpn,
    probe_shadowsocks,
    probe_vless_reality,
    probe_wireguard,
    probe_amneziawg,
)

logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    format="%(message)s",
    datefmt="[%H:%M:%S]",
)
logger = logging.getLogger("censprobe.client")
console = Console()

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))
_DISCLAIMER = """
[yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/yellow]
 This tool tests VPN protocol reachability from
 YOUR network to YOUR OWN server.
 It does NOT bypass censorship or forward traffic.
 Results are printed to stdout only — nothing is
 committed or uploaded from this machine.
[yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/yellow]
"""


@click.command()
@click.option("--test-id", envvar="TEST_ID", required=True, help="Test identifier (must match listener)")
@click.option("--session-id", envvar="SESSION_ID", required=True, help="Your session label, e.g. client-home-rt-spb")
@click.option("--server-host", envvar="SERVER_HOST", required=True, help="IP address of the server running listener")
@click.option("--no-jitter", is_flag=True, default=False, help="Disable opsec jitter between probes (faster, less stealthy)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(test_id: str, session_id: str, server_host: str, no_jitter: bool, verbose: bool) -> None:
    """
    Censprobe Client — probe VPN protocol reachability from this machine to listener.

    Run: TEST_ID=selectel-spb-001 SESSION_ID=client-home-rt-spb SERVER_HOST=1.2.3.4 \\
         docker compose --profile client up

    The listener must be running on SERVER_HOST before this runs.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(_DISCLAIMER)
    console.print(Panel.fit(
        f"[bold cyan]Censprobe Client[/bold cyan]\n"
        f"Test ID: [yellow]{test_id}[/yellow]\n"
        f"Session ID: [yellow]{session_id}[/yellow]\n"
        f"Server: [yellow]{server_host}[/yellow]\n"
        f"Jitter: {'disabled' if no_jitter else 'enabled'}",
        title="Starting probes",
    ))

    results = asyncio.run(_async_main(test_id, session_id, server_host, no_jitter))
    _print_results(results, server_host)


async def _async_main(
    test_id: str, session_id: str, server_host: str, no_jitter: bool
) -> dict[str, ProbeResult]:
    # ── Step 1: git pull ──────────────────────────────────────────────────────
    console.print("[dim]Pulling latest credentials...[/dim]")
    try:
        git_pull()
    except Exception as e:
        console.print(f"[yellow]Warning: git pull failed: {e}[/yellow]")
        console.print(
            "[yellow]If GitHub is blocked from this network, copy the repository manually:\n"
            "  1. On a machine with access, run: git pull\n"
            "  2. Copy the updated repository to this machine via USB/SCP/rsync.\n"
            "  3. The critical file is: reports/<TEST_ID>/protocols.yaml[/yellow]"
        )

    # -- Step 2: Read credentials --------------------------------------------------
    protocols_path = WORKSPACE / "reports" / test_id / "protocols.yaml"
    if not protocols_path.exists():
        console.print(f"[red]protocols.yaml not found at {protocols_path}[/red]")
        console.print(
            "[yellow]Ensure that the listener has run at least once and pushed credentials.\n"
            "If git pull failed, copy protocols.yaml manually from the listener machine:[/yellow]\n"
            f"  [bold]scp <listener-host>:{protocols_path} {protocols_path}[/bold]"
        )
        sys.exit(1)

    from censprobe_core.credentials_reader import load_protocols_yaml
    try:
        creds = load_protocols_yaml(protocols_path)
    except Exception as e:
        console.print(f"[red]Failed to read protocols.yaml: {e}[/red]")
        sys.exit(1)

    console.print(f"[green]Credentials loaded from protocols.yaml[/green]")

    # ── Step 3: Run probes in random order with jitter ────────────────────────
    protocols = [
        ("openvpn", _run_openvpn, creds),
        ("wireguard", _run_wireguard, creds),
        ("amneziawg", _run_amneziawg, creds),
        ("shadowsocks", _run_shadowsocks, creds),
        ("vless_reality", _run_vless_reality, creds),
        ("hysteria2", _run_hysteria2, creds),
    ]

    # Randomize order for opsec
    random.shuffle(protocols)

    results: dict[str, ProbeResult] = {}
    for i, (name, probe_fn, _creds) in enumerate(protocols):
        if not no_jitter and i > 0:
            await asyncio.sleep(random.uniform(0.5, 3.0))

        console.print(f"[dim]Probing {name}...[/dim]")
        try:
            result = await probe_fn(server_host, _creds)
            results[name] = result
            _print_single_result(name, result)
        except Exception as e:
            logger.error("Probe %s failed with exception: %s", name, e)
            results[name] = ProbeResult(verdict=Verdict.ERROR, error=str(e))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Per-protocol wrappers
# ─────────────────────────────────────────────────────────────────────────────

async def _run_openvpn(host: str, creds) -> ProbeResult:
    return await probe_openvpn(host, creds.openvpn_port, creds.openvpn_psk_pem)


async def _run_wireguard(host: str, creds) -> ProbeResult:
    return await probe_wireguard(
        host, creds.wg_port,
        creds.wg_server_public,
        creds.wg_client_public,
        creds.wg_preshared_key,
        creds.wg_client_private,
    )


async def _run_amneziawg(host: str, creds) -> ProbeResult:
    return await probe_amneziawg(
        host, creds.awg_port,
        creds.awg_server_public,
        creds.awg_client_public,
        creds.awg_preshared_key,
        creds.awg_client_private,
        creds.awg_jc, creds.awg_jmin, creds.awg_jmax,
        creds.awg_s1, creds.awg_s2,
        creds.awg_h1, creds.awg_h2, creds.awg_h3, creds.awg_h4
    )


async def _run_shadowsocks(host: str, creds) -> ProbeResult:
    return await probe_shadowsocks(host, creds.ss_port, creds.ss_method, creds.ss_password_b64)


async def _run_vless_reality(host: str, creds) -> ProbeResult:
    return await probe_vless_reality(
        host, creds.vless_port,
        creds.vless_uuid,
        creds.vless_pbk,
        creds.vless_short_id,
        creds.vless_server_name,
    )


async def _run_hysteria2(host: str, creds) -> ProbeResult:
    return await probe_hysteria2(host, creds.hy2_port, creds.hy2_auth, creds.hy2_obfs_password)


# ─────────────────────────────────────────────────────────────────────────────
# Rich display
# ─────────────────────────────────────────────────────────────────────────────

def _print_single_result(name: str, result: ProbeResult) -> None:
    icons = {
        Verdict.OK: "[green]OK[/green]",
        Verdict.HANDSHAKE_ONLY: "[yellow]HANDSHAKE_ONLY[/yellow]",
        Verdict.BLOCKED: "[red]BLOCKED[/red]",
        Verdict.ERROR: "[dim]ERROR[/dim]",
    }
    v_str = icons.get(result.verdict, str(result.verdict))
    rtt_str = f" ({result.rtt_ms:.0f}ms)" if result.rtt_ms else ""
    console.print(f"  {name:<20} {v_str}{rtt_str}")


def _print_results(results: dict[str, ProbeResult], server_host: str) -> None:
    table = Table(
        title=f"Client probe results → {server_host}",
        header_style="bold magenta",
        show_header=True,
    )
    table.add_column("Protocol", style="cyan", width=20)
    table.add_column("Verdict", width=22)
    table.add_column("RTT", justify="right", width=10)
    table.add_column("Error", style="dim", width=40)

    verdict_colors = {
        Verdict.OK: "green",
        Verdict.HANDSHAKE_ONLY: "yellow",
        Verdict.BLOCKED: "red",
        Verdict.ERROR: "dim",
    }

    ok_count = 0
    for name, r in results.items():
        color = verdict_colors.get(r.verdict, "white")
        v_str = f"[{color}]{r.verdict}[/{color}]"
        rtt_str = f"{r.rtt_ms:.0f}ms" if r.rtt_ms else "—"
        table.add_row(name, v_str, rtt_str, r.error or "")
        if r.verdict in (Verdict.OK, Verdict.HANDSHAKE_ONLY):
            ok_count += 1

    console.print("\n")
    console.print(table)

    summary_color = "green" if ok_count == len(results) else "yellow" if ok_count > 0 else "red"
    console.print(Panel.fit(
        f"[{summary_color}]{ok_count}/{len(results)} protocols reached[/{summary_color}]\n"
        f"[dim]Note: HANDSHAKE_ONLY means handshake succeeded but data phase blocked.\n"
        f"This is expected in test mode — it still means the protocol is reachable.[/dim]",
        title="Summary",
    ))


if __name__ == "__main__":
    main()
