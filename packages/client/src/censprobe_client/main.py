"""
censprobe-client — Main entrypoint.

Lifecycle:
  1. Read TEST_ID, SESSION_ID, SERVER_HOST and CREDS_* from env (the
     listener prints a single ``docker compose ... up`` line containing
     all of these).
  2. Fetch credentials from the listener's one-shot HTTPS endpoint,
     pinning the cert via SHA-256 fingerprint.
  3. Run handshake probes for every enabled protocol (with jitter between them).
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
import json
import logging
import random
import socket
import ssl
import sys
import time
from pathlib import Path

import click
from censprobe_core.config import load_config
from censprobe_core.credentials_reader import parse_protocols_yaml
from censprobe_core.models import LiveSnapshot, ProtocolResult, Verdict
from censprobe_core.protocol_probes import ASYMMETRIC_DPI_ERROR_MARKERS, ProbeResult
from censprobe_core.protocol_registry import enabled_protocols, is_mtg_protocol, known_names
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from censprobe_client._probe_dispatch import CLIENT_PROBES, ProbeFactory

WORKSPACE = Path("/workspace")

logging.basicConfig(
    level=logging.INFO,
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    format="%(message)s",
    datefmt="[%H:%M:%S]",
)
logger = logging.getLogger(__name__)
console = Console()

_FETCH_TIMEOUT_SEC = 15.0
# 1 initial attempt + 2 retries for transient endpoint failures
# (connection refused, timeout, 5xx). Permanent errors (auth failure,
# /creds exhausted, cert pinning mismatch) skip retries entirely —
# they will never succeed by themselves and a retry would only waste
# time. Backoff is exponential with jitter base: 1s → 2s before the
# 2nd and 3rd attempt respectively.
_FETCH_MAX_ATTEMPTS = 3
_FETCH_RETRY_BACKOFF_BASE_SEC = 1.0
# Hard ceiling on response bytes. Cert pinning already rules out a
# random MitM, but a compromised listener (or a subtle server bug)
# could otherwise stream unbounded data into the client's memory.
# Real payloads are tiny: /creds is a few KB of YAML, /snapshot is
# tens of KB of JSON, /stop is ~30 bytes of JSON ack. 10 MiB leaves
# four orders of magnitude of headroom while still bounding RAM use.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class _TransientEndpointError(RuntimeError):
    """Endpoint failure that's worth retrying.

    Raised for connection refused, TLS handshake mid-stream errors,
    HTTP 5xx, OSError. The retry wrapper catches this; non-Transient
    exceptions propagate immediately.
    """


class _PermanentEndpointError(RuntimeError):
    """Endpoint failure that won't fix itself.

    Auth failures (401/403), exhausted single-use credentials (410),
    cert pinning mismatch, malformed response. Retries don't help.
    """


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
@click.option(
    "--test-id", envvar="TEST_ID", required=True, help="Test identifier (must match listener)"
)
@click.option(
    "--session-id",
    envvar="SESSION_ID",
    required=True,
    help=(
        "Session label printed by listener — paste it as-is from the "
        "listener's setup command. Auto-generated server-side; the operator "
        "doesn't invent it. Example: mob-A8F1."
    ),
)
@click.option(
    "--server-host",
    envvar="SERVER_HOST",
    required=True,
    help="IP address of the server running listener",
)
@click.option(
    "--creds-port",
    envvar="CREDS_PORT",
    required=True,
    type=int,
    help="Listener credentials HTTPS port (set via CREDS_PORT in .env)",
)
@click.option(
    "--creds-token",
    envvar="CREDS_TOKEN",
    required=True,
    help="One-shot bearer token (printed by listener)",
)
@click.option(
    "--creds-cert-sha256",
    envvar="CREDS_CERT_SHA256",
    required=True,
    help="SHA-256 fingerprint of listener's self-signed cert (cert pinning)",
)
@click.option(
    "--no-jitter",
    is_flag=True,
    default=False,
    help="Disable opsec jitter between probes (faster, less stealthy)",
)
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
    console.print(
        Panel.fit(
            f"[bold cyan]Censprobe Client[/bold cyan]\n"
            f"Test ID: [yellow]{test_id}[/yellow]\n"
            f"Session ID: [yellow]{session_id}[/yellow]\n"
            f"Server: [yellow]{server_host}:{creds_port}[/yellow]\n"
            f"Jitter: {'disabled' if no_jitter else 'enabled'}",
            title="Starting probes",
        )
    )

    # test_id / session_id are surfaced in the banner above but aren't
    # consumed by the async core — they were previously forwarded for
    # symmetry, which Sonar S1172 flagged as unused parameters.
    results, listener_snapshot = asyncio.run(
        _async_main(
            server_host=server_host,
            creds_port=creds_port,
            creds_token=creds_token,
            creds_cert_sha256=creds_cert_sha256,
            no_jitter=no_jitter,
        )
    )
    _print_results(results, server_host)
    _print_cross_verification(results, listener_snapshot)


async def _async_main(
    *,
    server_host: str,
    creds_port: int,
    creds_token: str,
    creds_cert_sha256: str,
    no_jitter: bool,
) -> tuple[dict[str, ProbeResult], dict[str, LiveSnapshot] | None]:
    # ── Step 0: Load top-level config ────────────────────────────────────────
    # proxy_throughput (called from the SS / VLESS+Reality / Hysteria-2
    # probes after a successful echo) reads target_bytes / timeout_sec
    # from cfg.throughput. Without this call get_config() raises and the
    # broad except in the per-probe loop turns OK verdicts into ERROR.
    try:
        load_config(WORKSPACE)
    except ValueError as e:
        console.print(f"[red]Config error:[/red] {e}")
        sys.exit(1)

    # ── Step 1: Fetch credentials from listener's one-shot HTTPS endpoint ────
    console.print(
        f"[dim]Fetching credentials from https://{server_host}:{creds_port}/creds...[/dim]"
    )
    try:
        creds_yaml = await asyncio.to_thread(
            _fetch_credentials,
            server_host,
            creds_port,
            creds_token,
            creds_cert_sha256,
        )
    except _PermanentEndpointError as e:
        # Permanent error means retrying won't help — surface a more
        # specific message so the operator immediately checks the
        # likely culprit (token/cert/credentials exhaustion).
        console.print(f"[red]Cannot fetch credentials: {e}[/red]")
        console.print(
            "[yellow]Permanent error — verify TOKEN and CERT_SHA256 "
            "match the listener's banner output, and that /creds "
            "hasn't already been consumed (it's single-use). The "
            "listener prints fresh values on every restart.[/yellow]"
        )
        sys.exit(1)
    except _TransientEndpointError as e:
        # Already retried _FETCH_MAX_ATTEMPTS times inside the helper.
        console.print(f"[red]Cannot fetch credentials after retries: {e}[/red]")
        console.print(
            "[yellow]Transient error — listener may not be running or "
            "is unreachable. Confirm the listener startup banner is "
            "still on screen and that the firewall on the test "
            "server allows inbound TCP from this client.[/yellow]"
        )
        sys.exit(1)
    except ValueError as e:
        # Operator-side input error (cert sha256 isn't 64 hex chars).
        console.print(f"[red]Invalid credential argument: {e}[/red]")
        sys.exit(1)

    try:
        creds = parse_protocols_yaml(creds_yaml)
    except Exception as e:
        console.print(f"[red]Failed to parse credentials YAML: {e}[/red]")
        sys.exit(1)

    console.print("[green]Credentials received[/green]")

    # ── Step 2: Run probes in random order with jitter ────────────────────────
    # Pull the list of enabled protocols from the credentials YAML.
    # The listener writes `_protocols_enabled` into the body; the
    # client mirrors that exact set so we never probe a protocol the
    # listener didn't bring up. The field is required by
    # parse_protocols_yaml — listener and client deploy in lockstep
    # (same compose image), so a missing field is a schema-drift bug,
    # not a back-compat scenario worth a silent fallback.
    enabled_names = creds._protocols_enabled
    valid_names = set(known_names())
    unknown = [n for n in enabled_names if n not in valid_names]
    if unknown:
        logger.warning(
            "Listener advertised unknown protocol(s) %s; ignored. Known: %s",
            ", ".join(unknown),
            ", ".join(sorted(valid_names)),
        )

    probe_jobs: list[tuple[str, ProbeFactory]] = []
    for spec in enabled_protocols(enabled_names):
        factory = CLIENT_PROBES.get(spec.name)
        if factory is None:
            logger.error(
                "No client probe factory for %s — fix _probe_dispatch.py",
                spec.name,
            )
            continue
        probe_jobs.append((spec.name, factory))

    # Randomize order for opsec.
    random.shuffle(probe_jobs)

    results: dict[str, ProbeResult] = {}
    for i, (name, factory) in enumerate(probe_jobs):
        if not no_jitter and i > 0:
            # Jitter is opsec — randomising probe spacing so a network observer
            # can't fingerprint the suite by its inter-probe timing. Cryptographic
            # randomness is overkill (and slower); random.uniform is fine.
            await asyncio.sleep(random.uniform(0.5, 3.0))  # noqa: S311

        console.print(f"[dim]Probing {name}...[/dim]")
        probe_t0 = time.monotonic()
        try:
            result = await factory(server_host, creds)
            results[name] = result
            _print_single_result(name, result)
            # Structured INFO breakdown so a diagnostician reading the
            # pasted log can verify each probe's verdict against the
            # underlying timings. Decoupled from the operator-facing
            # ``_print_single_result`` (Rich-formatted) so plain-text
            # log dumps carry the same signal.
            logger.info(
                "probe[%s] verdict=%s elapsed=%.0fms rtt=%s throughput=%s error=%s",
                name,
                result.verdict,
                result.elapsed_ms if result.elapsed_ms is not None else 0.0,
                f"{result.rtt_ms:.0f}ms" if result.rtt_ms is not None else "n/a",
                (
                    f"{result.throughput_mbps:.2f}Mbps"
                    if result.throughput_mbps is not None
                    else "n/a"
                ),
                result.error or "none",
            )
        except Exception as e:
            # ``logger.exception`` auto-attaches the traceback so we
            # don't have to thread the exception object into the
            # format string (Sonar S8572). ``str(e)`` is still
            # needed for the ProbeResult.error payload below.
            # ``elapsed_ms`` is stamped here (not via the per-probe
            # decorator) because exceptions bypass the decorator's
            # post-return stamping.
            logger.exception("Probe %s failed", name)
            results[name] = ProbeResult(
                verdict=Verdict.ERROR,
                error=str(e),
                elapsed_ms=(time.monotonic() - probe_t0) * 1000,
            )

    # ── Step 3: Ask listener to stop, then fetch the final snapshot ──────────
    # The listener IS the ground truth: kernel-level counters, post-
    # handshake auth-validated bytes, iptables packet counts. Whatever
    # the client sees can be spoofed by the OS/networking layer.
    #
    # Two-step protocol (2026-05): first POST /stop so the listener
    # tears down responders and freezes per-protocol counters into a
    # final snapshot. Then poll GET /snapshot — it 503s until the
    # listener has committed, then returns the same dict the JSON
    # report contains. No more live-vs-final drift (which was the
    # AWG cross-verify discrepancy that surfaced in RU runs).
    listener_snapshot: dict[str, LiveSnapshot] | None = None
    # Collect per-protocol client-measured throughput numbers and ship
    # them in the /stop body so the listener can persist them into the
    # report (its own loopback measurement collapses on fast links).
    # We only include OK rows with a finite positive number — error /
    # blocked / unmeasured probes have no signal to forward.
    client_throughput = {
        name: float(r.throughput_mbps)
        for name, r in results.items()
        if r.throughput_mbps is not None and r.throughput_mbps > 0
    }
    try:
        await asyncio.to_thread(
            _post_stop,
            server_host,
            creds_port,
            creds_token,
            creds_cert_sha256,
            client_throughput=client_throughput,
        )
    except _PermanentEndpointError as e:
        # /stop refused at auth/pinning level. The operator can still
        # Ctrl+C on the server manually; we don't abort the client,
        # we just skip cross-verification.
        logger.warning("Listener /stop rejected: %s", e)
    except _TransientEndpointError as e:
        logger.warning(
            "Listener /stop unreachable after %d retries: %s — "
            "falling back to operator Ctrl+C on the server",
            _FETCH_MAX_ATTEMPTS,
            e,
        )
    except Exception as e:  # noqa: BLE001 — defence in depth
        logger.warning("Could not POST /stop: %s", e)

    # /snapshot now polls — it returns 503 until main.py finishes
    # _stop_responders and calls commit_final_snapshots. responder
    # teardown can take 30+s (openvpn graceful-terminate, mtg SIGTERM
    # grace), so we give it ample retry headroom — five attempts at
    # the existing exponential backoff (1s → 2s → 4s → 8s → 16s,
    # capped by _FETCH_TIMEOUT_SEC per attempt) cleanly covers the
    # _STOP_TIMEOUT_SEC window without hard-waiting.
    try:
        listener_snapshot = await asyncio.to_thread(
            _fetch_snapshot,
            server_host,
            creds_port,
            creds_token,
            creds_cert_sha256,
        )
    except _PermanentEndpointError as e:
        # Auth or pinning mismatch on the snapshot endpoint — same
        # token/cert that worked for /creds shouldn't fail on /snapshot,
        # so this is genuinely surprising. Don't abort: client-side
        # results are still useful, just print the diagnostic.
        logger.warning("Listener snapshot rejected (no retry): %s", e)
    except _TransientEndpointError as e:
        # Already attempted _FETCH_MAX_ATTEMPTS times inside the helper.
        # Fall through and skip cross-verification — the client-side
        # table still prints and the operator gets a yellow note in
        # _print_cross_verification.
        logger.warning(
            "Listener snapshot unavailable after %d retries: %s",
            _FETCH_MAX_ATTEMPTS,
            e,
        )
    except Exception as e:  # noqa: BLE001 — defence-in-depth
        # Anything not covered by the typed branches (e.g. JSON
        # parsing surprises) — treat as soft-fail too.
        logger.warning("Could not fetch listener snapshot: %s", e)

    return results, listener_snapshot


# ─────────────────────────────────────────────────────────────────────────────
# Credentials transport
# ─────────────────────────────────────────────────────────────────────────────


def _fetch_credentials(
    host: str,
    port: int,
    token: str,
    expected_sha256: str,
) -> str:
    """GET https://host:port/creds with bearer-token + cert pinning.

    Retries up to :data:`_FETCH_MAX_ATTEMPTS` times on transient
    network failures (connection refused, TLS hiccup, 5xx) — the
    listener's HTTP server is a daemon thread and may briefly be
    unresponsive during start-up or reload. Permanent failures
    (401/403/410, cert pinning mismatch) skip retries entirely.
    """
    return _pinned_get_with_retry(host, port, token, expected_sha256, path="/creds")


def _fetch_snapshot(
    host: str,
    port: int,
    token: str,
    expected_sha256: str,
) -> dict[str, LiveSnapshot]:
    """GET https://host:port/snapshot — listener-side final counters.

    Polls (with retry) until the listener has committed its post-stop
    snapshot. Returns 503 while responders are still tearing down;
    the retry wrapper treats those as transient. Once the server
    finishes ``_stop_responders`` + ``commit_final_snapshots``, the
    endpoint flips to 200 and serves the same per-protocol dict that
    landed in the JSON report.

    Returns a per-protocol ``LiveSnapshot`` map. Protocols whose
    snapshot reader threw an exception on the listener are
    represented as a ``LiveSnapshot`` with default zeros — the
    server already logged the failure, the client just shows a
    "no listener data" cell.
    """
    # max_attempts is bumped here vs the default 3: openvpn graceful
    # terminate alone can take 30s, plus wg-quick down + iptables
    # teardown + ipapi.is enrichment can push the listener's
    # commit_final_snapshots past a minute. With 5 attempts the
    # wrapper sleeps between #1→#2..#4→#5 (4 gaps), so total backoff
    # is 1+2+4+8 = 15s plus up to 5×_FETCH_TIMEOUT_SEC=75s of network
    # time — comfortably covering the 30-60s teardown window without
    # hard-waiting.
    body = _pinned_get_with_retry(
        host,
        port,
        token,
        expected_sha256,
        path="/snapshot",
        max_attempts=5,
    )
    raw = json.loads(body)
    out: dict[str, LiveSnapshot] = {}
    for name, payload in raw.items():
        if isinstance(payload, dict) and "error" not in payload:
            try:
                out[name] = LiveSnapshot.model_validate(payload)
            except Exception as e:
                logger.debug("invalid snapshot for %s: %s", name, e)
                out[name] = LiveSnapshot()
        else:
            out[name] = LiveSnapshot()
    return out


def _post_stop(
    host: str,
    port: int,
    token: str,
    expected_sha256: str,
    *,
    client_throughput: dict[str, float] | None = None,
) -> None:
    """POST https://host:port/stop — ask listener to stop.

    Same TLS-pinned bearer-auth as /creds and /snapshot. The listener
    returns 202 Accepted with a tiny JSON ack and asynchronously
    tears down responders. We treat both 200 and 202 as success
    (POST-helpers in the retry wrapper accept 2xx broadly). Retries
    on transient errors.

    When ``client_throughput`` is supplied, the per-protocol Mbps map
    is attached as a JSON body — the listener merges it into the
    final report's ``ProtocolResult.client_avg_throughput_mbps`` so
    the dashboard sees real numbers on fast links (the listener's
    own loopback measurement collapses to ``None`` above ~Gbps).

    Retrying POST is normally risky (double-submit hazard), but the
    cred-server's /stop is explicitly idempotent: it sets a single
    asyncio.Event guarded by ``Event.set()``, which is a no-op after
    the first call. A retry that lands while the listener has
    already started teardown will simply re-flip an already-set
    event and return 202 — no double-teardown, no leaked state.
    The throughput map is merged on the listener side so a retry
    with the same numbers is idempotent there too.
    """
    body = b""
    if client_throughput:
        body = json.dumps(
            {"client_throughput": client_throughput},
            separators=(",", ":"),
        ).encode("utf-8")
    _pinned_get_with_retry(
        host,
        port,
        token,
        expected_sha256,
        path="/stop",
        method="POST",
        body=body,
    )


def _pinned_get(
    host: str,
    port: int,
    token: str,
    expected_sha256: str,
    *,
    path: str,
    method: str = "GET",
    body: bytes = b"",
) -> str:
    """Pinned-TLS bearer-auth request. Shared by /creds, /snapshot, /stop.

    Self-signed cert from the listener: ``verify_mode=CERT_NONE`` and
    ``check_hostname=False``, then DER hash the peer cert and compare
    with the operator-supplied expected fingerprint. A MitM presenting
    a different self-signed cert is rejected here regardless of any
    network-layer interception.

    Failure modes are split between two exception types so the caller's
    retry wrapper knows what's worth retrying:

      * :class:`_TransientEndpointError` — connection refused, TLS
        mid-stream broken pipe, HTTP 5xx, OSError. Worth retrying.
      * :class:`_PermanentEndpointError` — auth failure (401/403),
        single-use creds exhausted (410), cert pinning mismatch,
        malformed HTTP response. Retries won't help.
      * ``ValueError`` — caller's expected_sha256 is malformed.
        Permanent at the type level (we don't even reach the network);
        propagated as-is so the operator immediately fixes the input.
    """
    expected = expected_sha256.lower().replace(":", "").strip()
    if len(expected) != 64 or not all(c in "0123456789abcdef" for c in expected):
        raise ValueError("CREDS_CERT_SHA256 must be a 64-char hex SHA-256 fingerprint")

    # Reject embedded CRLF in host BEFORE formatting the HTTP request below.
    # ``host`` flows in from --server-host / SERVER_HOST and is otherwise
    # template-interpolated into a literal HTTP/1.1 request; without this
    # guard, a host like ``1.2.3.4\r\nEvil: header`` would smuggle a
    # second header. CLI/env are the only current sources, but defending
    # at the formatter is cheap insurance against a future caller.
    if "\r" in host or "\n" in host or "\r" in path or "\n" in path:
        raise ValueError(f"host/path must not contain CR or LF: host={host!r}, path={path!r}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Open the TLS connection ourselves (rather than letting urllib do it)
    # so we can hash the peer cert before sending the bearer token. Without
    # this order, the secret would land at a possibly-MitM'd peer.
    try:
        with socket.create_connection((host, port), timeout=_FETCH_TIMEOUT_SEC) as raw:
            # ``create_connection`` set the timeout on the raw socket
            # only for the connect() syscall. ``wrap_socket`` does NOT
            # carry that over to subsequent recv() loops, so an
            # unresponsive peer after the TLS handshake would block on
            # ``tls.recv`` until OS keepalive (~2 hours on Linux). Set
            # the deadline explicitly on the wrapped socket below so
            # the recv loop has a bounded budget.
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.settimeout(_FETCH_TIMEOUT_SEC)
                peer_der = tls.getpeercert(binary_form=True)
                if not peer_der:
                    # No cert == server didn't actually negotiate TLS;
                    # treat as transient (server may be mid-startup).
                    raise _TransientEndpointError("listener did not present a TLS certificate")
                actual = hashlib.sha256(peer_der).hexdigest()
                if not _hex_eq(actual, expected):
                    raise _PermanentEndpointError(
                        f"cert fingerprint mismatch: listener presented {actual}, "
                        f"expected {expected}"
                    )
                # Pinning passed — now safe to ship the bearer token.
                # POST carries an optional JSON body (currently only
                # /stop ships one, with the per-protocol client_throughput
                # map). GET never has a body. The Content-Length header
                # is emitted for any POST regardless of body size so a
                # zero-length body still parses cleanly on the server.
                if method == "POST":
                    headers_extra = f"Content-Length: {len(body)}\r\n"
                    if body:
                        headers_extra += "Content-Type: application/json; charset=utf-8\r\n"
                else:
                    headers_extra = ""
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Authorization: Bearer {token}\r\n"
                    f"{headers_extra}"
                    f"Connection: close\r\n"
                    f"User-Agent: censprobe-client\r\n"
                    f"\r\n"
                )
                tls.sendall(request.encode("ascii"))
                if body:
                    tls.sendall(body)
                buf = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > _MAX_RESPONSE_BYTES:
                        # Defence-in-depth against an unbounded
                        # response (compromised listener, server-side
                        # bug). Real payloads are tiny — see
                        # _MAX_RESPONSE_BYTES docstring.
                        raise _PermanentEndpointError(
                            f"response exceeded {_MAX_RESPONSE_BYTES} byte ceiling"
                        )
    except (TimeoutError, ConnectionError, OSError, ssl.SSLError) as e:
        # ConnectionError covers refused / reset / aborted; OSError is
        # the supertype that also covers DNS / unreachable. SSLError
        # surfaces handshake-time interruptions (server mid-restart).
        raise _TransientEndpointError(f"endpoint I/O error: {type(e).__name__}: {e}") from e

    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split(maxsplit=2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise _PermanentEndpointError(f"malformed response from listener: {status_line!r}")
    try:
        status_code = int(parts[1])
    except ValueError as e:
        raise _PermanentEndpointError(f"non-numeric HTTP status: {status_line!r}") from e
    # Accept 200 (GET / POST OK) and 202 Accepted (POST /stop ack).
    if status_code in (200, 202):
        return body.decode("utf-8", errors="replace")

    msg = body.decode("utf-8", errors="replace").strip() or status_line
    # 503 is the lifecycle "responders not yet ready" reply — worth
    # retrying. 5xx generally indicates a server-side hiccup; 408 is
    # request-timeout in HTTP semantics. The remaining 4xx codes
    # (401/403/410 and friends) are operator/input errors — no retry.
    if status_code >= 500 or status_code == 408:
        raise _TransientEndpointError(f"listener responded {status_code}: {msg}")
    raise _PermanentEndpointError(f"listener responded {status_code}: {msg}")


def _pinned_get_with_retry(
    host: str,
    port: int,
    token: str,
    expected_sha256: str,
    *,
    path: str,
    method: str = "GET",
    body: bytes = b"",
    max_attempts: int = _FETCH_MAX_ATTEMPTS,
) -> str:
    """Wrap :func:`_pinned_get` with bounded retry on transient errors.

    Retries ``max_attempts - 1`` times after the first failure.
    Permanent errors (auth, pinning mismatch, malformed responses)
    propagate after the FIRST attempt — re-trying them only delays
    the inevitable failure that the operator has to fix manually.

    Backoff is exponential, base ``_FETCH_RETRY_BACKOFF_BASE_SEC``:
    1 s before retry #1, 2 s before retry #2. With the per-attempt
    timeout of 15 s the total worst-case is ~3·15 + 1 + 2 = 48 s,
    which is well under any reasonable session-wait limit.
    """
    last_exc: _TransientEndpointError | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return _pinned_get(
                host, port, token, expected_sha256, path=path, method=method, body=body
            )
        except _TransientEndpointError as e:
            last_exc = e
            if attempt < max_attempts:
                delay = _FETCH_RETRY_BACKOFF_BASE_SEC * (2 ** (attempt - 1))
                logger.warning(
                    "Transient %s on attempt %d/%d (%s) — retrying in %.1fs",
                    path,
                    attempt,
                    max_attempts,
                    e,
                    delay,
                )
                time.sleep(delay)
            # else: fall through to raise after the loop
    # Exhausted retries — re-raise the last transient error so the
    # caller decides whether to abort (creds) or skip-and-warn (snapshot).
    # Defensive: max_attempts >= 1 by the function's signature contract,
    # so last_exc must be set if we got here. Production ``raise`` rather
    # than ``assert`` so a future caller passing max_attempts=0 surfaces
    # the bug instead of being silently stripped by python -O.
    if last_exc is None:
        raise RuntimeError(
            "_pinned_get_with_retry: retry loop exited without recording "
            "a transient error — caller likely passed max_attempts < 1"
        )
    raise last_exc


def _hex_eq(a: str, b: str) -> bool:
    """Length-stable equality for two hex strings.

    Cert fingerprints are not really secrets in the constant-time sense
    (operator pastes them into a console), but using compare_digest costs
    nothing and keeps reviewers from second-guessing.
    """
    return hmac.compare_digest(a.lower(), b.lower())


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
    # Prefer elapsed_ms (total probe wall-clock — uniform across protocols
    # and across OK/error paths) over rtt_ms (protocol-specific latency
    # signal that, for timeout-failing TCP probes, reflects only the
    # initial TCP connect and is misleadingly small). rtt_ms remains the
    # fallback for any probe path that didn't get elapsed_ms stamped.
    duration_ms = result.elapsed_ms if result.elapsed_ms is not None else result.rtt_ms
    duration_str = f" ({duration_ms:.0f}ms)" if duration_ms is not None else ""
    console.print(f"  {name:<20} {v_str}{duration_str}")


def _format_throughput(r: ProbeResult) -> str:
    if r.throughput_throttled:
        return "[red]throttled[/red]"
    if r.throughput_mbps is not None:
        return f"{r.throughput_mbps:,.1f} Mbps"
    return "[dim]—[/dim]"


def _summary_color(ok_count: int, total: int) -> str:
    if ok_count == total:
        return "green"
    if ok_count > 0:
        return "yellow"
    return "red"


def _print_results(results: dict[str, ProbeResult], server_host: str) -> None:
    table = Table(
        title=f"Client probe results → {server_host}",
        header_style="bold magenta",
        show_header=True,
    )
    table.add_column("Protocol", style="cyan", width=20)
    table.add_column("Verdict", width=22)
    # "Elapsed" is total probe wall-clock (uniform semantics across all
    # protocols, OK + error paths). It is the right number to look at
    # when asking "how long did this probe take to finish".
    # "RTT" is the protocol-specific latency signal preserved alongside:
    # TCP-connect for TCP-based probes, tunnel ICMP-ping RTT for VPN
    # protocols. It is NOT a probe duration — for timeout-failing
    # probes RTT will be milliseconds while Elapsed is up to 15 s.
    table.add_column("Elapsed", justify="right", width=10)
    table.add_column("RTT", justify="right", width=10)
    # Client-side throughput as observed by curl through the tunnel.
    # SOCKS-routed protocols (SS / VLESS / Hy2) measure through their
    # SOCKS proxy to a 127.0.0.1 echo; VPN protocols (OpenVPN / WG /
    # AWG) measure directly through the tun to a listener-side echo
    # bound on the tun IP. MTProto protocols still show "—" — their
    # data phase isn't HTTP so we don't run a bulk download.
    # The "throttled" suffix appears when the download did not finish
    # inside the timeout — strong signal that the data plane is
    # heavily rate-limited. NEVER used by scoring.
    table.add_column("Throughput", justify="right", width=14)
    table.add_column("Error", style="dim", width=32)

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
        elapsed_str = f"{r.elapsed_ms:.0f}ms" if r.elapsed_ms is not None else "—"
        rtt_str = f"{r.rtt_ms:.0f}ms" if r.rtt_ms is not None else "—"
        tp_str = _format_throughput(r)
        table.add_row(name, v_str, elapsed_str, rtt_str, tp_str, r.error or "")
        if r.verdict in (Verdict.OK, Verdict.HANDSHAKE_ONLY):
            ok_count += 1

    console.print("\n")
    console.print(table)

    color = _summary_color(ok_count, len(results))
    body = f"[{color}]{ok_count}/{len(results)} protocols reached[/{color}]"
    has_handshake_only = any(r.verdict == Verdict.HANDSHAKE_ONLY for r in results.values())
    if has_handshake_only:
        body += (
            "\n[dim]HANDSHAKE_ONLY: client completed the handshake but the "
            "data-plane round-trip did not finish before the deadline. "
            "See the per-protocol Note column on the cross-verified table "
            "for the attribution.[/dim]"
        )
    console.print(Panel.fit(body, title="Summary"))


def _listener_verdict(snap: LiveSnapshot) -> Verdict:
    """Apply :meth:`ProtocolResult.finalize` semantics to a live snapshot.

    Same predicates the listener will use when committing the JSON
    report at session end — delegated to ``ProtocolResult.finalize()``
    so client + listener agree on the verdict shape on both sides of
    the cross-verification.

    Since 2026-05-14 ``finalize()`` no longer downgrades BLOCKED→ERROR
    on a failed self-test — a wedged listener responder produces the
    same end-to-end failure the client sees, so both sides report
    BLOCKED and the operator gets a single coherent verdict. The
    per-protocol failure-note on the listener side carries the L7-vs-
    local attribution for the operator.
    """
    pr = ProtocolResult(
        handshake_count=snap.handshake_count,
        data_transfer_ok=snap.data_transfer_ok,
        responder_self_test_ok=snap.responder_self_test_ok,
    )
    pr.finalize()
    return pr.verdict


def _is_asymmetric_dpi_error(error: str | None) -> bool:
    """Whether ``error`` is the read-timeout-after-handshake shape that,
    combined with a listener-side OK / HANDSHAKE_ONLY counter, attributes
    the failure to asymmetric DPI rather than a generic
    client-overconfident disagreement.

    Imports the canonical marker tuple from probe-core
    (:data:`ASYMMETRIC_DPI_ERROR_MARKERS`) — single source of truth
    with the producer side (``_mtg_error_result`` in
    ``protocol_probes``). The 2026-05-14 audit moved the markers
    there so a future rename of an error string in
    ``protocol_probes`` can't silently break the cross-verify
    attribution (commit 280cf77 / memory ``mts_round_2026-05-13``).
    """
    if not error:
        return False
    return any(marker in error for marker in ASYMMETRIC_DPI_ERROR_MARKERS)


def _agreed_verdict(
    client: Verdict,
    listener: Verdict,
    client_error: str | None = None,
    *,
    protocol: str | None = None,
    dc_reach_ok: bool | None = None,
) -> tuple[str, str]:
    """Combine client + listener verdicts into a final + comment.

    The listener is authoritative — it's the one running the kernel
    counters and HMAC validation. The client's role is to ATTEMPT
    each protocol; whether anything actually arrived at the server
    is the listener's call.

    Outcomes:
      * ``agree``: both sides report the same verdict. Final =
        either side, comment empty.
      * ``client_overconfident``: client says OK, listener says
        BLOCKED/HANDSHAKE_ONLY. Final = listener's (the strict
        view). Common on Docker Desktop where the host netstack
        spoofs ICMP/UDP responses locally even though nothing
        reached the server; also surfaces under host-firewall
        artefacts and amneziawg-go local-loop quirks.
      * ``asymmetric_dpi`` (since 2026-05-13, broadened 2026-05-14,
        wording corrected 2026-05-13 after pcap audit):
        client says BLOCKED with a read-timeout-after-handshake error
        marker (see ``_ASYMMETRIC_DPI_ERROR_MARKERS``), and the
        listener saw at least the L4 handshake leave the wire — either
        OK (the daemon completed the full server-side flow) or
        HANDSHAKE_ONLY (counter only saw the accept(), no application
        bytes flowed). Both shapes mean "the data plane is filtered
        in at least one direction" but the listener cannot reliably
        distinguish ``c→s ClientHello dropped`` from ``s→c return
        leg dropped`` from its counters alone — observed both shapes
        in production:
          * MTS RU 2026-05-13: server PSH-ACK iptables counter ticked,
            client got ``welcome_read_timeout_record0`` → ``s→c``
            return leg dropped.
          * Selectel→Vultr 2026-05-13 (pcap-confirmed): L4 handshake
            both directions, six 517-byte ``ClientHello`` retransmits
            from client, zero application bytes arrived at mtg →
            ``c→s`` payload dropped, server never responded.
        Final = HANDSHAKE_ONLY with a direction-agnostic note.
      * ``listener_overconfident`` (other shapes): listener=OK,
        client=BLOCKED but with a NON-timeout error (e.g.
        ``connection_refused`` from a Docker-loopback artefact).
        Listener's OK reading is still trusted as authoritative.
    """
    if client == listener:
        return str(listener), ""
    # Both sides disagree — listener wins by default, but flag it.
    if client == Verdict.OK:
        return str(listener), "client overread (listener saw less)"
    # Asymmetric DPI: client got a read-timeout-after-handshake while
    # the listener saw the L4 handshake. Two distinct shapes verified
    # in pcap audits (see docstring); the listener counters cannot
    # tell them apart, so the attribution stays direction-agnostic.
    # Either way the protocol is NOT usable from this client vantage —
    # final collapses to HANDSHAKE_ONLY with the explicit note.
    if (
        client == Verdict.BLOCKED
        and listener in (Verdict.OK, Verdict.HANDSHAKE_ONLY)
        and _is_asymmetric_dpi_error(client_error)
    ):
        # Dual-vantage caveat (added 2026-05-14 after ya-b log review):
        # the asymmetric-DPI shape is INDISTINGUISHABLE on the wire from
        # "listener can't reach Telegram DCs to relay" (mtg accepts the
        # client's FakeTLS WelcomePacket locally, then the inner resPQ
        # never returns because there's no DC backend to forward to).
        # If the listener's preflight already showed dc_reach_ok=False
        # for an mtg-based protocol, prefer that explanation — it's the
        # one with positive evidence (preflight TCP SYN to 149.154.0.0/16
        # got dropped), not the speculative DPI attribution.
        if protocol is not None and is_mtg_protocol(protocol) and dc_reach_ok is False:
            return (
                str(Verdict.HANDSHAKE_ONLY),
                "listener egress to Telegram DCs blocked — no DC relay possible",
            )
        return (
            str(Verdict.HANDSHAKE_ONLY),
            "asymmetric DPI: handshake passed, data plane filtered",
        )
    if listener == Verdict.OK:
        return str(listener), "listener saw data the client missed"
    # Both non-OK but different (e.g. HANDSHAKE_ONLY vs BLOCKED).
    return str(listener), f"client={client}"


def _print_cross_verification(
    results: dict[str, ProbeResult],
    snapshot: dict[str, LiveSnapshot] | None,
) -> None:
    """Side-by-side client / listener / final verdict table.

    Skipped silently when the snapshot fetch failed (older listener,
    transient HTTPS error). The client-only table from ``_print_results``
    is still printed by main(), so the operator never loses output.
    """
    if snapshot is None:
        console.print(
            "\n[yellow]Listener snapshot unavailable — falling back to "
            "client-side verdicts only. The listener's JSON report "
            "remains the authoritative record.[/yellow]"
        )
        return

    table = Table(
        title="Cross-verified verdicts (listener is authoritative)",
        header_style="bold magenta",
        show_header=True,
    )
    table.add_column("Protocol", style="cyan", width=20)
    table.add_column("Client", width=18)
    table.add_column("Listener", width=18)
    table.add_column("Final", width=18)
    table.add_column("Note", style="dim", width=42)

    verdict_color = {
        Verdict.OK: "green",
        Verdict.HANDSHAKE_ONLY: "yellow",
        Verdict.BLOCKED: "red",
        Verdict.ERROR: "dim",
    }

    disagreements = 0
    client_overread = 0
    for name, client_r in results.items():
        snap = snapshot.get(name)
        if snap is None:
            # Listener didn't surface this protocol — defaults to BLOCKED
            # so the table cell is still meaningful instead of blank.
            snap = LiveSnapshot()

        listener_v = _listener_verdict(snap)
        final, note = _agreed_verdict(
            client_r.verdict,
            listener_v,
            client_r.error,
            protocol=name,
            dc_reach_ok=snap.dc_reach_ok,
        )
        # Structured INFO so the cross-verify decision is auditable from
        # plain-text logs — the table goes through Rich and loses its
        # column alignment in raw stdout dumps; the INFO line preserves
        # the exact (client, listener, dc_reach_ok) → (final, note)
        # mapping for after-the-fact review.
        logger.info(
            "cross-verify[%s] client=%s listener=%s dc_reach_ok=%s "
            "client_error=%s → final=%s note=%s",
            name,
            client_r.verdict,
            listener_v,
            snap.dc_reach_ok,
            client_r.error or "none",
            final,
            note or "agree",
        )
        if note:
            disagreements += 1
            # ``client_overread`` is the only disagreement shape where the
            # Docker-Desktop/loopback-spoofing hint adds real value — for
            # ``asymmetric DPI …`` the per-row note already explains it
            # and a generic "Docker Desktop" trailer is misleading
            # (verified 2026-05-13 on ubuntu-server → ubuntu-server pcap).
            if client_r.verdict == Verdict.OK and listener_v != Verdict.OK:
                client_overread += 1

        client_v = client_r.verdict
        c_color = verdict_color.get(client_v, "white")
        l_color = verdict_color.get(listener_v, "white")
        f_color = verdict_color.get(Verdict(final), "white")
        table.add_row(
            name,
            f"[{c_color}]{client_v}[/{c_color}]",
            f"[{l_color}]{listener_v}[/{l_color}]",
            f"[{f_color}]{final}[/{f_color}]",
            note,
        )

    console.print("\n")
    console.print(table)
    if disagreements:
        msg = f"[yellow]{disagreements} protocol(s) disagreed — listener-side verdict wins."
        if client_overread:
            msg += (
                " Client-overread rows above typically come from a host "
                "netstack that spoofs ICMP/UDP locally (Docker Desktop, "
                "amneziawg-go loopback) — listener counters are the "
                "ground truth."
            )
        msg += "[/yellow]"
        console.print(msg)


if __name__ == "__main__":
    main()
