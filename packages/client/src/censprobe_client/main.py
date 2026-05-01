"""
censprobe-client — Main entrypoint.

Lifecycle:
  1. Read TEST_ID, SESSION_ID, SERVER_HOST and CREDS_* from env (the
     listener prints a single ``docker compose ... up`` line containing
     all of these).
  2. Fetch credentials from the listener's one-shot HTTPS endpoint,
     pinning the cert via SHA-256 fingerprint.
  3. Run handshake probes for all 6 protocols (with jitter between them).
  4. Print results to stdout — NO git commits, NO network writes.
  5. Exit.

Security note:
  The client never commits or writes anything to the repository. All
  results are only printed to stdout. SERVER_HOST is taken from env, not
  resolved by the client, to prevent DNS-side correlation. Cert pinning
  protects the credential transfer against MitM even though the
  listener's cert is self-signed.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import random
import socket
import ssl
import sys

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from censprobe_core.credentials_reader import parse_protocols_yaml
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
logger = logging.getLogger(__name__)
console = Console()

_FETCH_TIMEOUT_SEC = 15.0
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
@click.option("--creds-port", envvar="CREDS_PORT", default=8443, show_default=True, type=int, help="Listener credentials HTTPS port")
@click.option("--creds-token", envvar="CREDS_TOKEN", required=True, help="One-shot bearer token (printed by listener)")
@click.option("--creds-cert-sha256", envvar="CREDS_CERT_SHA256", required=True, help="SHA-256 fingerprint of listener's self-signed cert (cert pinning)")
@click.option("--no-jitter", is_flag=True, default=False, help="Disable opsec jitter between probes (faster, less stealthy)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(
    test_id: str,
    session_id: str,
    server_host: str,
    creds_port: int,
    creds_token: str,
    creds_cert_sha256: str,
    no_jitter: bool,
    verbose: bool,
) -> None:
    """
    Censprobe Client — probe VPN protocol reachability from this machine to listener.

    Run the one-liner printed by the listener startup banner — it sets all
    the required env vars (TEST_ID / SESSION_ID / SERVER_HOST / CREDS_*).
    The listener must be running on SERVER_HOST before this starts.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(_DISCLAIMER)
    console.print(Panel.fit(
        f"[bold cyan]Censprobe Client[/bold cyan]\n"
        f"Test ID: [yellow]{test_id}[/yellow]\n"
        f"Session ID: [yellow]{session_id}[/yellow]\n"
        f"Server: [yellow]{server_host}:{creds_port}[/yellow]\n"
        f"Jitter: {'disabled' if no_jitter else 'enabled'}",
        title="Starting probes",
    ))

    results = asyncio.run(_async_main(
        test_id=test_id,
        session_id=session_id,
        server_host=server_host,
        creds_port=creds_port,
        creds_token=creds_token,
        creds_cert_sha256=creds_cert_sha256,
        no_jitter=no_jitter,
    ))
    _print_results(results, server_host)


async def _async_main(
    *,
    test_id: str,
    session_id: str,
    server_host: str,
    creds_port: int,
    creds_token: str,
    creds_cert_sha256: str,
    no_jitter: bool,
) -> dict[str, ProbeResult]:
    # ── Step 1: Fetch credentials from listener's one-shot HTTPS endpoint ────
    console.print(f"[dim]Fetching credentials from https://{server_host}:{creds_port}/creds...[/dim]")
    try:
        creds_yaml = await asyncio.to_thread(
            _fetch_credentials,
            server_host, creds_port, creds_token, creds_cert_sha256,
        )
    except Exception as e:
        console.print(f"[red]Could not fetch credentials: {e}[/red]")
        console.print(
            "[yellow]Make sure the listener is running and that the "
            "TOKEN / CERT_SHA256 values match the ones it printed.[/yellow]"
        )
        sys.exit(1)

    try:
        creds = parse_protocols_yaml(creds_yaml)
    except Exception as e:
        console.print(f"[red]Failed to parse credentials YAML: {e}[/red]")
        sys.exit(1)

    console.print("[green]Credentials received[/green]")

    # ── Step 2: Run probes in random order with jitter ────────────────────────
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
# Credentials transport
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_credentials(
    host: str, port: int, token: str, expected_sha256: str,
) -> str:
    """GET https://host:port/creds with bearer-token + cert pinning.

    Self-signed cert from the listener: `verify_mode=CERT_NONE` and
    `check_hostname=False`, then DER hash the peer cert and compare with
    the operator-supplied expected fingerprint. A MitM presenting a
    different self-signed cert is rejected here regardless of any
    network-layer interception.
    """
    expected = expected_sha256.lower().replace(":", "").strip()
    if len(expected) != 64 or not all(c in "0123456789abcdef" for c in expected):
        raise ValueError(
            "CREDS_CERT_SHA256 must be a 64-char hex SHA-256 fingerprint"
        )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Open the TLS connection ourselves (rather than letting urllib do it)
    # so we can hash the peer cert before sending the bearer token. Without
    # this order, the secret would land at a possibly-MitM'd peer.
    with socket.create_connection((host, port), timeout=_FETCH_TIMEOUT_SEC) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            peer_der = tls.getpeercert(binary_form=True)
            if not peer_der:
                raise RuntimeError("listener did not present a TLS certificate")
            actual = hashlib.sha256(peer_der).hexdigest()
            if not _hex_eq(actual, expected):
                raise RuntimeError(
                    f"cert fingerprint mismatch: listener presented "
                    f"{actual}, expected {expected}"
                )
            # Pinning passed — now safe to ship the bearer token.
            request = (
                f"GET /creds HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n"
                f"User-Agent: censprobe-client\r\n"
                f"\r\n"
            )
            tls.sendall(request.encode("ascii"))
            buf = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                buf += chunk

    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split(maxsplit=2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise RuntimeError(f"malformed response from listener: {status_line!r}")
    try:
        status_code = int(parts[1])
    except ValueError as e:
        raise RuntimeError(f"non-numeric HTTP status: {status_line!r}") from e
    if status_code != 200:
        msg = body.decode("utf-8", errors="replace").strip() or status_line
        raise RuntimeError(f"listener responded {status_code}: {msg}")

    return body.decode("utf-8", errors="replace")


def _hex_eq(a: str, b: str) -> bool:
    """Length-stable equality for two hex strings.

    Cert fingerprints are not really secrets in the constant-time sense
    (operator pastes them into a console), but using compare_digest costs
    nothing and keeps reviewers from second-guessing.
    """
    return hmac.compare_digest(a.lower(), b.lower())


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
