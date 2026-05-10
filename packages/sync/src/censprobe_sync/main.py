"""
censprobe-sync — incremental ``reports/`` transfer between operator machines.

Two CLI subcommands, both run via ``docker compose --profile sync``:

* ``serve`` — runs on the source machine (where solo / listener wrote
  reports). Generates an ephemeral self-signed cert + bearer token,
  prints a single ``docker compose run`` command for the operator to
  paste on the destination machine, then ``execvp``-s ``rclone serve
  http`` so the Python process is replaced (clean signal handling,
  no PID tree).

* ``pull`` — runs on the destination machine. Performs a pinned-TLS
  handshake against the serve side, verifies the SHA-256 fingerprint
  before sending the bearer token, materialises the verified peer
  cert as a temp file and ``execvp``-s ``rclone copy
  --ignore-existing --immutable`` so reports already on disk are
  never overwritten and only new files transfer.

Direction is one-way (source → destination): ``reports/`` always live
on the censprobe server (solo / listener wrote them) which has a
public IP by design (listener has to be reachable from clients on
``CREDS_PORT``). The pull side only needs outbound HTTPS — works
through any NAT/CGNAT.

Cert pinning is the same model as the existing listener / client pair
(``packages/listener/src/censprobe_listener/cred_server.py`` for the
generator, ``packages/client/src/censprobe_client/main.py::_pinned_get``
for the consumer): self-signed cert, ``CERT_NONE`` + manual SHA-256
compare, bearer token only sent after the fingerprint matches.

Refactor follow-up: ``generate_self_signed_cert`` and
``detect_external_ip`` (+ helpers) are duplicated here from
``cred_server.py`` rather than imported, because letting sync depend
on the full listener package would pull in mtg / openvpn / wg-tools /
amneziawg-go binary expectations. A second pass should hoist these
helpers into ``probe-core`` so listener and sync share one copy.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import socket
import ssl
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel

logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    format="%(message)s",
    datefmt="[%H:%M:%S]",
)
logger = logging.getLogger(__name__)
console = Console()

WORKSPACE_REPORTS = Path("/workspace/reports")
DEFAULT_PORT = 8444
RCLONE_BASIC_AUTH_USER = "op"

# Cert lifetime: 24 hours matches cred_server. A serve session that
# outlasts that is unusual (operator should ctrl+c long before),
# and rclone will emit a clean "certificate expired" rather than
# silently breaking.
_CERT_VALIDITY_HOURS = 24

_FETCH_TIMEOUT_SEC = 15.0

# Public-IP echo fallback chain — used when the local default-route
# source IP is private/CGNAT and would not be reachable by a remote
# pull-side. Mirror of cred_server's identical constant.
_PUBLIC_IP_ECHOES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
)
_PUBLIC_IP_TIMEOUT_SEC = 5.0
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


# ─────────────────────────────────────────────────────────────────────────────
# Cert generation (mirrors cred_server.generate_self_signed_cert).
# ─────────────────────────────────────────────────────────────────────────────


def _generate_self_signed_cert(extra_ip: str | None = None) -> tuple[bytes, bytes, str]:
    """Generate an RSA-2048 self-signed cert.

    Returns ``(cert_pem, key_pem, sha256_fingerprint_hex)``. SAN covers
    localhost + loopback (so an operator who curls the endpoint by
    hand with ``--cacert`` doesn't trip RFC 6125) plus, optionally,
    the externally-detected IPv4 the serve side will be reached on.

    Why ``extra_ip`` matters: rclone's HTTP backend uses Go's
    ``net/http`` which **always** verifies the cert SAN against the
    URL host even when ``--ca-cert`` already trusts the cert. There's
    no rclone flag to skip hostname verification while keeping CA
    trust. Pinning by fingerprint at the Python layer guarantees the
    cert is the right one; baking ``extra_ip`` into SAN then makes
    rclone's name check happy without weakening anything (the puller
    only ever talks to its parameter ``--server-host``, which equals
    the ``extra_ip`` that ``serve`` printed).

    ``None`` falls back to the listener-style SAN of just localhost +
    loopback — matches the unit-test surface and keeps the helper
    usable for non-network callers.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "censprobe-sync")])
    san_entries: list[x509.GeneralName] = [
        x509.DNSName("censprobe-sync"),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    if extra_ip:
        try:
            san_entries.append(x509.IPAddress(ipaddress.IPv4Address(extra_ip)))
        except (ipaddress.AddressValueError, ValueError):
            # Not a parseable IPv4 — treat as DNSName so an operator
            # who set up a custom hostname (e.g. ``censprobe.example``)
            # can still reach the cert. The puller's ``--server-host``
            # has to match this entry verbatim either way.
            san_entries.append(x509.DNSName(extra_ip))
    san = x509.SubjectAlternativeName(san_entries)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=_CERT_VALIDITY_HOURS))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_pem, key_pem, fingerprint


# ─────────────────────────────────────────────────────────────────────────────
# External IP detection (mirrors cred_server.detect_external_ip).
# ─────────────────────────────────────────────────────────────────────────────


def _detect_external_ip() -> str | None:
    """Best-effort IPv4 the puller should reach us on. ``None`` means
    no usable outbound — operator gets ``<your-server-ip>`` placeholder
    in the printed command and substitutes by hand.
    """
    local_ip = _udp_connect_local_ip()
    if local_ip is None:
        return None
    if not _is_unroutable(local_ip):
        return local_ip
    public_ip = _query_public_ip_echo()
    return public_ip or local_ip


def _udp_connect_local_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip: str = s.getsockname()[0]
            return ip
        finally:
            s.close()
    except OSError:
        return None


def _is_unroutable(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return True
    return addr.is_private or addr in _CGNAT_NETWORK


def _query_public_ip_echo() -> str | None:
    for url in _PUBLIC_IP_ECHOES:
        try:
            with urllib.request.urlopen(url, timeout=_PUBLIC_IP_TIMEOUT_SEC) as r:  # noqa: S310
                ip: str = r.read().decode("ascii", errors="replace").strip()
            ipaddress.IPv4Address(ip)
            return ip
        except (OSError, ValueError):
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Pinned cert fetch (mirrors client._pinned_get's first half).
# ─────────────────────────────────────────────────────────────────────────────


def _normalise_fingerprint(fingerprint: str) -> str:
    """Accept ``aa:bb:cc..`` or ``aabbcc..`` (case-insensitive) and
    return canonical lower-case 64-char hex. Raises ``ValueError`` on
    any malformed input — surfaces as ``--cert-fingerprint`` arg
    parsing failure before we touch the network.
    """
    canonical = fingerprint.lower().replace(":", "").strip()
    if len(canonical) != 64 or not all(c in "0123456789abcdef" for c in canonical):
        raise ValueError(
            "--cert-fingerprint must be a 64-char hex SHA-256 fingerprint "
            f"(got {len(canonical)} chars after normalisation)"
        )
    return canonical


def _fetch_and_verify_peer_cert(host: str, port: int, expected_fingerprint: str) -> bytes:
    """TLS-handshake the serve endpoint, capture the peer cert, verify
    its SHA-256 fingerprint matches, and return the cert as PEM.

    Returns the PEM bytes ready to write to a tempfile for
    ``rclone copy --ca-cert``. Raises ``ValueError`` on a fingerprint
    mismatch — operator should re-check the printed command for typos
    or the serve container for a restart (each restart issues a new
    cert + fingerprint, so an old paste won't work).

    No bearer token is sent during this fetch — only the TLS
    handshake. The token only flows once the cert is verified, inside
    the subsequent ``rclone copy`` call.
    """
    expected = _normalise_fingerprint(expected_fingerprint)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.create_connection((host, port), timeout=_FETCH_TIMEOUT_SEC) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            peer_der = tls.getpeercert(binary_form=True)

    if not peer_der:
        raise ValueError("sync server did not present a TLS certificate")

    actual = hashlib.sha256(peer_der).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError(
            f"cert fingerprint mismatch: server presented {actual}, "
            f"expected {expected} — re-check --cert-fingerprint"
        )

    # Convert DER → PEM for rclone --ca-cert (which expects PEM).
    cert_obj = x509.load_der_x509_certificate(peer_der)
    return cert_obj.public_bytes(serialization.Encoding.PEM)


def _write_secret_tempfile(content: bytes, suffix: str) -> Path:
    """Write ``content`` to a 0o600 tempfile and return its path. Used
    for cert/key materialisation before handing off to rclone (rclone
    consumes filesystem paths, not in-memory PEM blobs).
    """
    fd, name = tempfile.mkstemp(suffix=suffix, prefix="censprobe_sync_")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise
    return Path(name)


# ─────────────────────────────────────────────────────────────────────────────
# CLI: serve
# ─────────────────────────────────────────────────────────────────────────────


@click.group()
def cli() -> None:
    """censprobe-sync — incremental reports/ transfer."""


@cli.command()
@click.option(
    "--port",
    type=int,
    default=DEFAULT_PORT,
    envvar="SYNC_PORT",
    show_default=True,
    help="HTTPS port to bind for the read-only rclone endpoint",
)
def serve(port: int) -> None:
    """Serve ``reports/`` over rclone HTTP for one-shot pull from another machine.

    Generates an ephemeral cert + token, prints the one-liner the
    operator pastes on the destination machine, then exec-replaces
    this Python process with ``rclone serve http`` so SIGINT cleanly
    tears down the server.
    """
    if not WORKSPACE_REPORTS.exists():
        console.print(
            f"[red]No reports directory at {WORKSPACE_REPORTS} — nothing to serve.[/red]\n"
            "[yellow]Run solo or listener first; serve only makes sense when "
            "reports/ exists.[/yellow]"
        )
        sys.exit(1)

    # Detect external IP first so we can bake it into the cert SAN.
    # rclone's HTTP backend (Go net/http) verifies the URL host against
    # SAN even when --ca-cert already trusts the cert; without the IP
    # in SAN, pulls fail with "x509: certificate is valid for ... not
    # <server-host>" even though pinning at the Python layer was
    # already successful.
    detected_ip = _detect_external_ip()
    server_host = detected_ip or "<your-server-ip>"
    cert_pem, key_pem, fingerprint = _generate_self_signed_cert(extra_ip=detected_ip)
    token = secrets.token_urlsafe(32)

    cert_path = _write_secret_tempfile(cert_pem, ".pem")
    key_path = _write_secret_tempfile(key_pem, ".key")

    _print_serve_banner()
    _print_pull_command(server_host, port, token, fingerprint)

    rclone_argv = [
        "rclone",
        "serve",
        "http",
        "--addr",
        f"0.0.0.0:{port}",
        "--cert",
        str(cert_path),
        "--key",
        str(key_path),
        "--user",
        RCLONE_BASIC_AUTH_USER,
        "--pass",
        token,
        "--read-only",
        # rclone's VFS directory cache defaults to 5 minutes — files
        # added to /workspace/reports DURING a serve session would
        # otherwise be invisible to the puller for up to 5 min after
        # they appear. Operators almost always run a fresh listener
        # session (which writes new reports) and immediately want to
        # pull — 1s strikes a balance between "see new files quickly"
        # and "don't stat() the directory on every request".
        "--dir-cache-time",
        "1s",
        str(WORKSPACE_REPORTS),
    ]

    # execvp replaces the Python process with rclone — no zombie
    # reaping issues, SIGINT goes straight to rclone's signal handler,
    # /tmp cert+key files get unlinked by tmpfs on container exit.
    os.execvp("rclone", rclone_argv)  # noqa: S606 — argv is fully constructed


def _print_serve_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]Censprobe Sync — serve[/bold cyan]\n"
            f"Workspace: {WORKSPACE_REPORTS}\n"
            "Press Ctrl+C to stop.",
            title="Starting sync",
        )
    )


def _print_pull_command(server_host: str, port: int, token: str, fingerprint: str) -> None:
    """Print the one-liner the operator copies onto the destination
    machine. Mirror of listener's ``_print_client_run_command`` styling
    — bare ``console.print`` (no Panel) so Windows / cmd.exe don't
    munge box-drawing characters when copy-pasting from terminal.
    """
    console.print(
        "\n[bold]Pull command (run on the destination machine):[/bold]",
        style="cyan",
    )
    cmd = (
        "docker compose --profile sync run --rm sync pull"
        f" --server-host {server_host}"
        f" --port {port}"
        f" --token {token}"
        f" --cert-fingerprint {fingerprint}"
    )
    console.print(cmd, soft_wrap=True, highlight=False, markup=False)
    console.print(
        "\n[dim]Cert pinned by SHA-256 fingerprint above. "
        "Token is per-session — ctrl+c and re-run to issue fresh ones.[/dim]\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# CLI: pull
# ─────────────────────────────────────────────────────────────────────────────


@cli.command()
@click.option("--server-host", required=True, envvar="SYNC_SERVER_HOST")
@click.option("--port", type=int, required=True, envvar="SYNC_PORT")
@click.option("--token", required=True, envvar="SYNC_TOKEN")
@click.option(
    "--cert-fingerprint",
    required=True,
    envvar="SYNC_CERT_FINGERPRINT",
    help="64-char hex SHA-256 fingerprint printed by the serve side",
)
def pull(server_host: str, port: int, token: str, cert_fingerprint: str) -> None:
    """Pull missing reports from a serve endpoint into local ``reports/``.

    Verifies the server cert by SHA-256 before any token leaves this
    process, then exec-replaces with ``rclone copy --ignore-existing
    --immutable`` so already-present files stay untouched.
    """
    console.print(
        Panel.fit(
            "[bold cyan]Censprobe Sync — pull[/bold cyan]\n"
            f"Server: [yellow]{server_host}:{port}[/yellow]",
            title="Starting pull",
        )
    )

    try:
        cert_pem = _fetch_and_verify_peer_cert(server_host, port, cert_fingerprint)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except (OSError, ssl.SSLError) as e:
        console.print(
            f"[red]Could not reach sync server at {server_host}:{port}: "
            f"{type(e).__name__}: {e}[/red]\n"
            "[yellow]Check that the serve side is running and the port is reachable.[/yellow]"
        )
        sys.exit(1)

    cert_path = _write_secret_tempfile(cert_pem, ".pem")
    console.print(
        "[green]Cert fingerprint OK — downloading reports...[/green]",
    )

    WORKSPACE_REPORTS.mkdir(parents=True, exist_ok=True)

    # rclone HTTP-backend basic-auth goes via the URL userinfo:
    # ``https://USER:PASS@host:port/``. Token is from
    # ``secrets.token_urlsafe`` → [A-Za-z0-9_-] only, all URL-safe
    # in userinfo (no percent-encoding needed).
    #
    # The inline-remote syntax ``:http,url=URL:`` confuses rclone's
    # parser when URL contains both ``:`` and ``/`` (interpreted as
    # remote-name boundaries). Workaround: pass the URL via
    # ``--http-url`` and reference the backend as ``:http:`` (empty
    # config, all options on CLI). Same end result, no quoting puzzles.
    url = f"https://{RCLONE_BASIC_AUTH_USER}:{token}@{server_host}:{port}"
    rclone_argv = [
        "rclone",
        "copy",
        "--ca-cert",
        str(cert_path),
        "--http-url",
        url,
        "--ignore-existing",
        "--immutable",
        # ``-v`` surfaces "Copied (new)" / "Skipped" lines so the
        # operator can see what actually transferred. Without this
        # rclone is silent on success — looks identical to "did
        # nothing", which is misleading the first time you run it.
        "-v",
        # Progress visibility without flooding the log.
        "--stats",
        "5s",
        "--stats-one-line",
        ":http:",
        str(WORKSPACE_REPORTS),
    ]
    os.execvp("rclone", rclone_argv)  # noqa: S606


def main() -> None:
    """Module entry point — dispatch to click group."""
    cli()


if __name__ == "__main__":
    main()
