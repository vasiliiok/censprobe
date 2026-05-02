"""
censprobe-listener — Main entrypoint.

Lifecycle:
  1. Read TEST_ID and SESSION_ID from CLI args / env.
  2. Generate fresh in-memory credentials (one-time per session).
  3. Start a one-shot HTTPS endpoint (cred_server) that hands the YAML
     to the client when it presents the right bearer token. The
     endpoint also captures the IP of the first authenticated client
     for later enrichment. Print a ready-to-paste ``docker compose run
     --rm`` command for the operator to send to the client machine.
  4. Start all 6 VPN protocol responders.
  5. Wait for SIGINT (Ctrl+C) or SIGTERM.
  6. Stop all responders, snapshot client IP, then stop the cred endpoint.
  7. Enrich the captured client IP via ipapi.is into a structured
     EndpointMeta (no IP literal stored on disk). Three terminal states
     are recorded — see ListenerReport docstring.
  8. Save report as
     reports/<TEST_ID>/server-listener-<SESSION_ID>-<ts>.json.
  9. Exit. Publishing is manual: `git add reports/ && git push` from the
     host when you're ready to share results.

Security note:
  All protocols run in test/dummy mode. No real traffic forwarding.
  Credentials are one-time per session and live only in memory + on the
  TLS-pinned channel between this listener and the client.
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

from censprobe_core.models import EndpointMeta, ListenerReport, ProtocolResult, Verdict
from censprobe_core.server_meta import enrich_endpoint
from censprobe_core.utils import validate_id
from censprobe_listener.cred_server import CredServer, detect_external_ip
from censprobe_listener.credentials import (
    ProtocolCredentials,
    creds_to_yaml,
    generate_credentials,
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
logger = logging.getLogger(__name__)
console = Console()

WORKSPACE = Path("/workspace")


def _click_validate_id(field: str, value: str) -> str:
    """click.BadParameter wrapper around the shared probe-core validator.

    Operator-supplied identifiers flow into filesystem paths
    (reports/<test_id>/server-listener-<session_id>-*.json) and into
    Postgres row keys downstream — the underlying ``validate_id`` rejects
    anything outside ``[A-Za-z0-9_.-]`` so path-traversal and SQL/Grafana
    smuggling don't make it past the CLI.
    """
    try:
        return validate_id(field, value)
    except ValueError as e:
        raise click.BadParameter(str(e)) from e

# Hard ceiling on graceful-shutdown time. Any responder still inside its
# stop() coroutine after this many seconds gets cancelled so the listener
# can finish writing its report and exit. docker-compose gives us
# `stop_grace_period: 30s` before sending SIGKILL, so we leave ~10s of
# margin for the synchronous JSON write that follows responder shutdown.
_STOP_TIMEOUT_SEC = 20.0

@click.command()
@click.option("--test-id", envvar="TEST_ID", required=True, help="Test identifier")
@click.option("--session-id", envvar="SESSION_ID", required=True, help="Client network session identifier, e.g. client-home-rt-spb")
# CREDS_PORT lives in .env (default 8443 there). 8443 is the highest
# MASQUE-fallback port real Cloudflare WARP binds, so it's unlikely to be
# blocked outbound by an ISP; VLESS+Reality and Hysteria 2 already
# squat 443 so we can't reuse it.
@click.option("--creds-port", envvar="CREDS_PORT", required=True, type=int, help="Port for the credentials HTTPS endpoint")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(test_id: str, session_id: str, creds_port: int, verbose: bool) -> None:
    """
    Censprobe Listener — expose VPN handshake endpoints, record what clients can reach.

    Run: docker compose --profile listener run --rm listener --test-id selectel-spb-001 --session-id client-home-rt-spb
    Stop: Ctrl+C → results saved to reports/<TEST_ID>/.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    test_id = _click_validate_id("--test-id", test_id)
    session_id = _click_validate_id("--session-id", session_id)

    console.print(Panel.fit(
        f"[bold cyan]Censprobe Listener[/bold cyan]\n"
        f"Test ID: [yellow]{test_id}[/yellow]\n"
        f"Session ID: [yellow]{session_id}[/yellow]\n"
        f"Workspace: {WORKSPACE}\n\n"
        "[dim]Press Ctrl+C to stop and save results.[/dim]",
        title="Starting listener",
    ))

    asyncio.run(_async_main(test_id, session_id, creds_port))


async def _async_main(test_id: str, session_id: str, creds_port: int) -> None:
    # ── Step 1: Generate fresh credentials in memory ──────────────────────────
    # Each session gets its own one-time credential set; nothing is written
    # to disk. The cred_server below hands them to the client over a
    # TLS-pinned channel and is shut down on Ctrl+C.
    console.print("[dim]Generating one-time credentials...[/dim]")
    creds = generate_credentials()

    # ── Step 2: Start the credentials HTTPS endpoint ──────────────────────────
    cred_server = CredServer(
        creds_yaml=creds_to_yaml(creds),
        port=creds_port,
    )
    try:
        cred_server.start()
    except OSError as e:
        console.print(
            f"[red]Could not bind credentials port {creds_port}: {e}[/red]\n"
            f"[yellow]Another process is already listening on that port. "
            "Stop it (or set CREDS_PORT to a free one) and re-run.[/yellow]"
        )
        sys.exit(1)

    server_host = detect_external_ip() or "<your-server-ip>"
    _print_client_run_command(
        test_id=test_id,
        session_id=session_id,
        server_host=server_host,
        creds_port=creds_port,
        creds_token=cred_server.token,
        creds_cert_sha256=cred_server.cert_sha256,
    )

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
        cred_server.stop()
        sys.exit(1)

    # Print status
    _print_responder_status(responders, start_errors, creds)
    console.print("\n[bold green]Listener is ready. Waiting for clients...[/bold green]")
    console.print("[dim]Press Ctrl+C to stop and save results.[/dim]\n")

    started_at = datetime.now(tz=timezone.utc)

    # ── Step 4: Wait for SIGINT ───────────────────────────────────────────────
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_signal():
        if not stop_event.is_set():
            # First signal: ask responders to stop gracefully. Use logger
            # rather than `console.print` so the message is not interleaved
            # with the live Rich table renderer (which is itself doing
            # writes from a background thread).
            logger.info("signal received, stopping listener…")
            stop_event.set()
            return
        # Second signal while we're already shutting down — bypass the
        # graceful path and exit immediately. Without this, a stuck
        # responder.stop() leaves the user no way to abort short of
        # SIGKILL of the container.
        logger.warning("second signal received, exiting hard")
        os._exit(130)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    try:
        await stop_event.wait()
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError):
                pass

    stopped_at = datetime.now(tz=timezone.utc)
    duration = (stopped_at - started_at).total_seconds()

    # ── Step 5: Stop responders (snapshot stats inside stop) + echo server ───
    # Each responder's stop() captures its final connection_count /
    # data_transfer_ok state BEFORE tearing down its underlying
    # interface/process; the snapshot is then surfaced via the same
    # property names. Doing this before _finalize_protocol_result means
    # the report reflects the absolute last bytes that crossed the wire.
    await _stop_responders(responders, timeout=_STOP_TIMEOUT_SEC)
    if echo_server is not None:
        try:
            await asyncio.wait_for(echo_server.stop(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Echo server stop timed out after 5s; continuing")
        except Exception as e:
            logger.warning("Echo server stop error: %s", e)
    # Snapshot client IP from the cred-endpoint BEFORE tearing it down.
    # The IP is captured under the cred-server's lock when the client
    # successfully fetches credentials; reading it now gives a stable
    # answer even if a late retry races with shutdown.
    client_ip = cred_server.client_ip
    # Tear down the credentials endpoint last so a slow client retry can
    # still complete during the responder-shutdown window. cred_server.stop
    # is synchronous and doesn't wait for in-flight handlers, so this is
    # cheap and bounded.
    cred_server.stop()

    # ── Step 6: Finalize verdicts from snapshotted state ─────────────────────
    results: dict[str, ProtocolResult] = {}
    for name, responder in responders.items():
        pr = _finalize_protocol_result(name, responder)
        results[name] = pr

    # Print final table
    _print_final_results(results, duration)

    # ── Step 7: Enrich client identity (IP-free in serialized output) ────────
    # Three terminal states recorded in the report:
    #   * client_ip is None             → client_connected=False, client=None
    #     (the network never let the client reach 8443 — strongest blocking
    #     signal; per-protocol BLOCKED is network-level, not protocol-level)
    #   * client_ip set, enrichment OK  → client_connected=True, client=<meta>
    #   * client_ip set, enrichment None→ client_connected=True, client=None
    #     (transient ipapi failure; protocol verdicts stay meaningful)
    client_meta: EndpointMeta | None = None
    if client_ip is not None:
        try:
            client_meta = await enrich_endpoint(client_ip)
        except Exception as e:
            logger.warning("Client enrichment failed: %s", e)
            client_meta = None

    _print_client_summary(client_ip is not None, client_meta)

    # ── Step 8: Save report ───────────────────────────────────────────────────
    report = ListenerReport(
        test_id=test_id,
        session_id=session_id,
        listener_started_at=started_at,
        listener_stopped_at=stopped_at,
        duration_sec=round(duration, 1),
        client_connected=client_ip is not None,
        client=client_meta,
        results=results,
    )
    report_path = _save_listener_report(report, test_id, session_id)
    console.print(f"[green]Report saved:[/green] {report_path}")
    console.print(
        "[dim]Publishing is manual: review the file, then "
        "`git add reports/ && git commit && git push` from the host.[/dim]"
    )

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
        ("openvpn", OpenVPNResponder(creds.openvpn_psk_pem, creds.openvpn_port)),
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


async def _stop_responders(responders: dict, timeout: float) -> None:
    """Stop all protocol responders gracefully, in parallel, under a deadline.

    Stopping in parallel matters because each individual responder can
    spend up to ~1 s waiting for its child process to exit; running them
    sequentially turned a 6-protocol shutdown into a 6-second wall-clock
    delay that ate into our docker-compose `stop_grace_period` budget.

    A single overall `timeout` covers the entire fan-out so a misbehaving
    responder cannot block the report from being written.
    """
    async def _stop_one(name: str, responder) -> None:
        try:
            await responder.stop()
        except Exception as e:
            logger.warning("Error stopping %s: %s", name, e)

    tasks = {
        name: asyncio.create_task(_stop_one(name, r))
        for name, r in responders.items()
    }
    if not tasks:
        return
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks.values(), return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        stuck = [name for name, t in tasks.items() if not t.done()]
        logger.warning(
            "Responder shutdown exceeded %.1fs; cancelling: %s",
            timeout, ", ".join(stuck) or "<none>",
        )
        for t in tasks.values():
            if not t.done():
                t.cancel()
        # Drain the cancellations so we don't leak task objects.
        await asyncio.gather(*tasks.values(), return_exceptions=True)


def _finalize_protocol_result(name: str, responder) -> ProtocolResult:
    """Build ProtocolResult from a responder's post-stop snapshot."""
    # Different responders expose the field under different historical
    # names; prefer `connection_count` (the canonical one) and fall back
    # to `handshake_count` if a future responder uses that. `or` is a
    # truthy fallback rather than `None` chain because both are int
    # counters with `0` as a meaningful "nothing observed" value — they
    # therefore must compare to 0 with `is None` semantics.
    handshake_count = getattr(responder, "connection_count", None)
    if handshake_count is None:
        handshake_count = getattr(responder, "handshake_count", 0)
    handshake_count = int(handshake_count or 0)

    data_ok = bool(getattr(responder, "data_transfer_ok", False))

    # Throughput: only the SOCKS-routed responders expose
    # ``echo_server`` (injected in _start_responders). For OpenVPN /
    # WG / AWG the attribute is missing or None — leave the field
    # unset so the report carries an honest "not measured".
    avg_throughput: float | None = None
    echo_server = getattr(responder, "echo_server", None)
    if echo_server is not None:
        try:
            avg_throughput = echo_server.throughput_mbps.get(name)
        except (AttributeError, TypeError):
            avg_throughput = None

    pr = ProtocolResult(
        handshake_count=handshake_count,
        data_transfer_ok=data_ok,
        avg_throughput_mbps=avg_throughput,
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

def _print_client_run_command(
    test_id: str,
    session_id: str,
    server_host: str,
    creds_port: int,
    creds_token: str,
    creds_cert_sha256: str,
) -> None:
    """Print the one-liner the operator pastes into the client machine.

    The command is a single-line ``docker compose run`` invocation with
    every per-run value passed as a CLI flag rather than a shell-prefixed
    env var. This keeps the line identical across bash, zsh, PowerShell,
    and cmd.exe — the args are consumed by docker (and ultimately by
    click inside the container), never interpreted by the host shell.
    Click's CLI-over-envvar precedence means the empty per-run slots in
    `.env` (which compose still substitutes into the container's
    `environment:` block) don't shadow these values.

    `run --rm` is also a better semantic fit than `up` for the client:
    the probe is one-shot, exits when done, and `--rm` cleans up the
    container afterwards instead of leaving a stopped one behind.

    SERVER_HOST may be a placeholder if external-IP detection failed
    (the network panel above prints what the listener thinks the
    address is); the operator edits it on paste in that case.
    """
    cmd = (
        "docker compose --profile client run --rm client"
        f" --test-id {test_id}"
        f" --session-id {session_id}"
        f" --server-host {server_host}"
        f" --creds-port {creds_port}"
        f" --creds-token {creds_token}"
        f" --creds-cert-sha256 {creds_cert_sha256}"
    )
    console.print(Panel.fit(
        "[bold]Run this on the client machine[/bold] (in your local clone).\n"
        "Works as-is on Linux, macOS, and Windows (PowerShell or cmd):\n\n"
        f"[cyan]{cmd}[/cyan]\n\n"
        "[dim]The credentials are served once over a TLS-pinned channel "
        "(self-signed cert, fingerprint above). Token is single-use.[/dim]",
        title="Client setup command",
        border_style="green",
    ))


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


def _print_client_summary(connected: bool, meta: EndpointMeta | None) -> None:
    """Operator-facing summary of which client network this session saw.

    Three states match the report's tri-state (see ListenerReport docstring).
    No IPs are printed here either — only the structured network identity.
    """
    if not connected:
        console.print(Panel.fit(
            "[red]Client never reached the credentials endpoint.[/red]\n"
            "[dim]Per-protocol BLOCKED verdicts in this run reflect the "
            "client network's inability to reach 8443/tcp at all, not "
            "protocol-specific blocking.[/dim]",
            title="Client network",
            border_style="red",
        ))
        return

    if meta is None:
        console.print(Panel.fit(
            "[yellow]Client connected, but ipapi enrichment failed.[/yellow]\n"
            "[dim]Per-protocol verdicts are still meaningful; only the "
            "client-network identity is missing in the report.[/dim]",
            title="Client network",
            border_style="yellow",
        ))
        return

    asn = meta.asn
    loc = meta.location
    line_org = (asn.org if asn else None) or (meta.company.name if meta.company else None) or "—"
    line_asn = f"AS{asn.asn}" if asn else "—"
    line_route = (asn.route if asn else None) or "—"
    line_city = loc.city if loc else None
    line_country = loc.country_code if loc else None
    line_loc = ", ".join(p for p in (line_city, line_country) if p) or "—"

    flags = []
    if meta.is_mobile:
        flags.append("[bold]MOBILE[/bold]")
    if meta.is_datacenter:
        flags.append("[red]DATACENTER (likely behind self-hosted VPN)[/red]")
    flag_line = " · ".join(flags) if flags else "[dim]residential[/dim]"

    console.print(Panel.fit(
        f"Org: [cyan]{line_org}[/cyan]\n"
        f"ASN: [cyan]{line_asn}[/cyan]  Route: [dim]{line_route}[/dim]\n"
        f"Location: [cyan]{line_loc}[/cyan]\n"
        f"Type: {flag_line}",
        title="Client network",
        border_style="green",
    ))


def _print_final_results(results: dict[str, ProtocolResult], duration: float) -> None:
    table = Table(title=f"Session Results (duration: {duration:.0f}s)", header_style="bold magenta")
    table.add_column("Protocol", style="cyan")
    table.add_column("Verdict")
    table.add_column("Handshakes", justify="right")
    table.add_column("Data Transfer")
    # Listener-side throughput: only the SOCKS-routed protocols populate
    # this; OpenVPN / WG / AmneziaWG show "—" because their data-phase
    # verification is a single ping, not a bulk download. The number is
    # operator-facing only and intentionally NOT used by scoring.
    table.add_column("Throughput", justify="right")

    for name, pr in results.items():
        verdict_str = {
            Verdict.OK: "[green]CONNECTED[/green]",
            Verdict.HANDSHAKE_ONLY: "[yellow]HANDSHAKE_ONLY[/yellow]",
            Verdict.BLOCKED: "[red]BLOCKED[/red]",
        }.get(pr.verdict, str(pr.verdict))
        if pr.avg_throughput_mbps is not None:
            throughput_str = f"{pr.avg_throughput_mbps:,.1f} Mbps"
        else:
            throughput_str = "[dim]—[/dim]"
        table.add_row(
            name,
            verdict_str,
            str(pr.handshake_count),
            "yes" if pr.data_transfer_ok else "no",
            throughput_str,
        )

    console.print(table)


if __name__ == "__main__":
    main()
