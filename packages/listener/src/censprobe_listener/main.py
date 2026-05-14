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
  4. Start every protocol responder enabled in censprobe.yaml.
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
import contextlib
import json
import logging
import os
import secrets
import signal
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click
from censprobe_core.config import get_config, load_config
from censprobe_core.models import EndpointMeta, ListenerReport, ProtocolResult, Verdict
from censprobe_core.protocol_registry import enabled_protocols, known_names
from censprobe_core.server_meta import enrich_endpoint
from censprobe_core.utils import validate_id
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from censprobe_listener._responder_dispatch import LISTENER_RESPONDERS, Responder
from censprobe_listener.cred_server import CredServer, detect_external_ip
from censprobe_listener.credentials import (
    ProtocolCredentials,
    creds_to_yaml,
    generate_credentials,
)
from censprobe_listener.echo_server import EchoServer
from censprobe_listener.preflight import (
    CheckResult,
    run_mtproxy_orig_self_test,
    run_preflight,
)

# Title reused for the three Rich panels that summarize client-network
# state. Hoisted to a constant — Sonar S1192 otherwise flags the literal
# duplicated three times across panels.
_CLIENT_NETWORK_PANEL_TITLE = "Client network"

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
# Upper bound for keeping the cred-server up after responder teardown
# so the client's polling /snapshot can complete its read. Common case
# resolves in < 1s (client polls aggressively, hits the 200 right after
# commit_final_snapshots). The 30s ceiling covers a flaky network
# round-trip without dragging the operator's shell forever when nobody
# is polling.
_SNAPSHOT_DRAIN_TIMEOUT_SEC = 30.0


def _generate_session_id(*, is_mobile: bool, is_whitelist: bool) -> str:
    """Auto-generate a per-run SESSION_ID with a human-eyeballable prefix.

    Operators previously had to invent ``client-<type>-<provider>-<city>``
    strings by hand and pass them via ``--session-id``. The convention
    drifted (typos, abbreviations) and the resulting strings weren't
    machine-parseable for dashboards anyway — the real signal is "what
    kind of network was the client on", which is now captured by the
    two boolean flags ``--mobile`` and ``--white``.

    Prefix encodes the flags so ``ls reports/<test_id>/`` is readable
    at a glance: ``mob-A8F1``, ``white-K9p2``, ``mob-white-X3R5``,
    ``plain-L4M8``. The 4-hex-char suffix (~16 bits of entropy) keeps
    multiple sessions within a single test_id distinguishable; collision
    probability inside a 96-test campaign is negligible.
    """
    if is_mobile and is_whitelist:
        prefix = "mob-white"
    elif is_mobile:
        prefix = "mob"
    elif is_whitelist:
        prefix = "white"
    else:
        prefix = "plain"
    return f"{prefix}-{secrets.token_hex(2).upper()}"


@click.command()
@click.option("--test-id", envvar="TEST_ID", required=True, help="Test identifier")
# CREDS_PORT lives in .env (default 8443 there). 8443 is the highest
# MASQUE-fallback port real Cloudflare WARP binds, so it's unlikely to be
# blocked outbound by an ISP; VLESS+Reality and Hysteria 2 already
# squat 443 so we can't reuse it.
@click.option(
    "--creds-port",
    envvar="CREDS_PORT",
    required=True,
    type=int,
    help="Port for the credentials HTTPS endpoint",
)
@click.option(
    "--mobile",
    "is_mobile",
    is_flag=True,
    default=False,
    help="Mark this session as conducted from a mobile-carrier network (used as a "
    "first-class filter dimension in Grafana). Combinable with --white.",
)
@click.option(
    "--white",
    "is_whitelist",
    is_flag=True,
    default=False,
    help="Mark this session as conducted from a network with carrier-side allow-"
    "lists / whitelisting in effect. Combinable with --mobile.",
)
@click.option("--verbose", "-v", is_flag=True, default=False)
def main(
    test_id: str,
    creds_port: int,
    is_mobile: bool,
    is_whitelist: bool,
    verbose: bool,
) -> None:
    """
    Censprobe Listener — expose VPN handshake endpoints, record what clients can reach.

    Run:
        docker compose --profile listener run --rm listener \\
            --test-id selectel-spb-001
        docker compose --profile listener run --rm listener \\
            --test-id selectel-spb-001 --mobile        # this run is from mobile
        docker compose --profile listener run --rm listener \\
            --test-id selectel-spb-001 --mobile --white # mobile + carrier whitelist

    Stop: Ctrl+C → results saved to reports/<TEST_ID>/.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    test_id = _click_validate_id("--test-id", test_id)
    # session_id is auto-generated so the operator never has to invent
    # one — the network-type prefix makes it eyeballable in `ls` output
    # and the two booleans become first-class Grafana filter dimensions.
    session_id = _generate_session_id(is_mobile=is_mobile, is_whitelist=is_whitelist)

    network_label = (
        ", ".join(label for label, on in (("mobile", is_mobile), ("whitelist", is_whitelist)) if on)
        or "regular"
    )
    console.print(
        Panel.fit(
            f"[bold cyan]Censprobe Listener[/bold cyan]\n"
            f"Test ID: [yellow]{test_id}[/yellow]\n"
            f"Session ID: [yellow]{session_id}[/yellow] (auto-generated)\n"
            f"Network: [yellow]{network_label}[/yellow]\n"
            f"Workspace: {WORKSPACE}\n\n"
            "[dim]Press Ctrl+C to stop and save results.[/dim]",
            title="Starting listener",
        )
    )

    asyncio.run(_async_main(test_id, session_id, creds_port, is_mobile, is_whitelist))


def _load_config_or_exit() -> None:
    """Load censprobe.yaml; exit cleanly with a red message on failure."""
    try:
        load_config(WORKSPACE)
    except ValueError as e:
        console.print(f"[red]Config error:[/red] {e}")
        sys.exit(1)


def _listener_udp_ports(enabled: list[str], ports_map: dict[str, int]) -> list[int]:
    """Resolve enabled UDP-transport protocols to their actual bind ports.

    Used by the pre-flight NOTRACK auto-setup. Walks ``enabled`` (the
    canonical list of protocols the listener will bring up this session)
    and picks the matching port from ``ports_map``. Disabled protocols
    are skipped — listener never binds them, no NOTRACK rule needed.
    The config validator (:meth:`ProtocolsConfig._check_ports_cover_enabled`)
    guarantees every enabled name appears in ``ports_map``, so the
    lookup is total.
    """
    from censprobe_core.protocol_registry import get_protocol

    out: set[int] = set()
    for name in enabled:
        spec = get_protocol(name)
        if spec is None or spec.transport != "udp":
            continue
        out.add(ports_map[name])
    return sorted(out)


def _extract_dc_reach_ok(results: list[CheckResult]) -> bool | None:
    """Pull the telegram-dc-reach pass/fail out of the preflight result list.

    ``ok`` → True (at least one DC pingable from listener egress).
    ``warn`` → False (0/N reachable — typical RU/BY vantages behind ТСПУ).
    Anything else (``skip``, missing) → None (treat as "no signal" so we
    don't override mtg verdicts on hosts where the check simply didn't run).
    """
    for r in results:
        if r.name != "telegram-dc-reach":
            continue
        if r.status == "ok":
            return True
        if r.status == "warn":
            return False
        return None
    return None


def _print_preflight(results: list[CheckResult]) -> None:
    """Render pre-flight check results to the rich console.

    Warnings are loud (yellow panel) so the operator sees them before
    they puzzle over a half-broken probe run; ``ok``/``skip`` are
    folded into a single dim line so the startup path stays quiet
    when the host is healthy.
    """
    warnings = [r for r in results if r.status == "warn"]
    if warnings:
        body = "\n".join(f"[yellow]⚠ {r.name}:[/yellow] {r.message}" for r in warnings)
        console.print(Panel(body, title="Pre-flight warnings", border_style="yellow"))
    quiet = [r for r in results if r.status != "warn"]
    if quiet:
        line = " · ".join(f"{r.name}={r.status}" for r in quiet)
        console.print(f"[dim]Pre-flight: {line}[/dim]")


def _start_cred_server_or_exit(creds_yaml: str, creds_port: int) -> CredServer:
    """Bind the one-shot credentials HTTPS endpoint or exit cleanly."""
    cred_server = CredServer(creds_yaml=creds_yaml, port=creds_port)
    try:
        cred_server.start()
    except OSError as e:
        console.print(
            f"[red]Could not bind credentials port {creds_port}: {e}[/red]\n"
            f"[yellow]Another process is already listening on that port. "
            "Stop it (or set CREDS_PORT to a free one) and re-run.[/yellow]"
        )
        sys.exit(1)
    return cred_server


async def _start_echo_server_or_none() -> EchoServer | None:
    """Bring up the loopback echo server; on failure the responders
    fall back to handshake-only signals.
    """
    echo_server = EchoServer()
    try:
        await echo_server.start()
    except Exception as e:
        console.print(f"[yellow]Warning: echo server failed to start: {e}[/yellow]")
        return None
    return echo_server


async def _enrich_client_or_none(client_ip: str | None) -> EndpointMeta | None:
    """Best-effort ipapi enrichment; transient failures yield ``None``."""
    if client_ip is None:
        return None
    try:
        return await enrich_endpoint(client_ip)
    except Exception as e:
        logger.warning("Client enrichment failed: %s", e)
        return None


async def _wait_for_shutdown_signal(remote_stop: asyncio.Event | None = None) -> None:
    """Block until SIGINT/SIGTERM arrives, OR ``remote_stop`` is set
    (client-driven stop via ``cred_server`` ``/stop`` endpoint).
    Second signal exits immediately.

    Extracted out of ``_async_main`` so the parent's cognitive complexity
    stays under Sonar's S3776 threshold — the nested handler plus the
    setup/teardown loops add five branches by themselves.

    The remote-stop path is the normal case in 2026-05+: the client
    POSTs ``/stop`` after probes finish, the cred-server sets
    ``remote_stop``, this function returns, ``_async_main`` proceeds
    to ``_stop_responders`` BEFORE the client polls ``/snapshot``.
    That sequencing eliminates the race where AWG userspace counters
    could drift between live-snapshot and stop() reads. ``Ctrl+C`` is
    kept as the fallback when the cred-server endpoint is unreachable
    (e.g. operator wants to abort early).
    """
    signal_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_signal() -> None:
        if not signal_event.is_set():
            # First signal: ask responders to stop gracefully. Use logger
            # rather than `console.print` so the message is not interleaved
            # with the live Rich table renderer (which is itself doing
            # writes from a background thread).
            logger.info("signal received, stopping listener…")
            signal_event.set()
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
        # Race between operator Ctrl+C and client-side /stop endpoint.
        # Whichever fires first wins; the other Event remains set but
        # ignored (the listener can only stop once).
        signal_task = asyncio.create_task(signal_event.wait())
        if remote_stop is not None:
            remote_task = asyncio.create_task(remote_stop.wait())
            done, pending = await asyncio.wait(
                {signal_task, remote_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if remote_task in done and signal_task not in done:
                logger.info("/stop endpoint signalled by client; tearing down")
            for t in pending:
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await t
        else:
            await signal_task
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            # NotImplementedError derives from RuntimeError, so catching
            # RuntimeError alone covers both — Sonar S5713 flagged the
            # tuple form as redundant.
            with contextlib.suppress(RuntimeError):
                loop.remove_signal_handler(sig)


async def _async_main(
    test_id: str,
    session_id: str,
    creds_port: int,
    is_mobile: bool,
    is_whitelist: bool,
) -> None:
    # ── Step 0: Load top-level config (protocols.enabled, vantage list, …) ───
    _load_config_or_exit()

    # ── Step 0b: Pre-flight environment checks ───────────────────────────────
    # Surfaces conditions that would silently degrade verdicts mid-run
    # (canonical: nf_conntrack table full → kernel drops handshakes
    # before responders see them). Never aborts startup — operators may
    # not have permission to fix sysctls — but every WARN is loud.
    cfg = get_config()
    preflight_results = await run_preflight(
        udp_ports=_listener_udp_ports(cfg.protocols.enabled, cfg.protocols.ports)
    )
    _print_preflight(preflight_results)
    # Structured INFO summary mirroring the panel — operator-pasting
    # logs to a diagnostician means the panel ANSI is stripped and the
    # status-per-check signal would be lost. Emit one line per check
    # with name + status + message so the same information survives a
    # plain-text copy/paste.
    for r in preflight_results:
        logger.info("preflight[%s] %s: %s", r.status, r.name, r.message)
    # Surface the telegram-dc-reach result as a kwarg threaded through
    # to ``_finalize_protocol_result`` and the cross-verify snapshot.
    # Listener can't relay client→DC if egress is blocked → mtg-based
    # protocols cap at HANDSHAKE_ONLY instead of falsely promoting to OK
    # when only the WelcomePacket leaked back to the client. ``None``
    # when the check didn't run (e.g. unit-test stubs).
    dc_reach_ok: bool | None = _extract_dc_reach_ok(preflight_results)

    # ── Step 1: Generate fresh credentials in memory ──────────────────────────
    # Each session gets its own one-time credential set; nothing is written
    # to disk. The cred_server below hands them to the client over a
    # TLS-pinned channel and is shut down on Ctrl+C.
    console.print("[dim]Generating one-time credentials...[/dim]")
    creds = generate_credentials(cfg.protocols.ports, cfg.protocols.sni)

    # ── Step 2: Start the credentials HTTPS endpoint ──────────────────────────
    cred_server = _start_cred_server_or_exit(
        creds_yaml=creds_to_yaml(creds, enabled_protocols=cfg.protocols.enabled),
        creds_port=creds_port,
    )

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
    echo_server = await _start_echo_server_or_none()

    # ── Step 3b: Start all responders ─────────────────────────────────────────
    responders, start_errors = await _start_responders(creds, echo_server)

    if not responders:
        console.print("[red]All responders failed to start. Exiting.[/red]")
        for name, err in start_errors.items():
            console.print(f"  [red]{name}:[/red] {err}")
        cred_server.stop()
        sys.exit(1)

    # ── Step 3c: Post-responder preflight self-tests ─────────────────────────
    # mtproto_orig is the only protocol with a self-test today — see
    # ``run_mtproxy_orig_self_test`` for the rationale. Result is
    # surfaced as a WARN in the preflight panel AND threaded into
    # ``_finalize_protocol_result`` so a wedged-responder session
    # downgrades BLOCKED → ERROR instead of falsely attributing a
    # local responder bug to network censorship.
    self_test_results: dict[str, bool] = {}
    post_preflight: list[CheckResult] = []
    if "mtproto_orig" in responders:
        mt_orig = responders["mtproto_orig"]
        if getattr(mt_orig, "unavailable", False):
            # Responder deliberately skipped its subprocess launch
            # because the C MTProxy binary's upstream Telegram fleet is
            # unreachable from this vantage (typical RU host). Running
            # the loopback self-test would just time out for 12 s and
            # land in the same "False" branch — skip the wait and
            # surface the diagnostic now.
            alive = getattr(mt_orig, "upstream_alive_count", 0)
            total = getattr(mt_orig, "upstream_total_count", 0)
            post_preflight.append(
                CheckResult(
                    "mtproxy-orig-self-test",
                    "warn",
                    (
                        f"skipped: mtproto-proxy not launched ({alive}/{total} "
                        f"proxy-multi.conf upstreams reachable on TCP/8888). "
                        f"mtproto_orig sessions WILL report BLOCKED — the "
                        f"prune itself is positive evidence that Telegram's "
                        f"DC fleet is unreachable from this vantage (typical "
                        f"for RU hosts behind ТСПУ on TCP/8888 to "
                        f"91.108.4.0/24 and 149.154.0.0/16)."
                    ),
                )
            )
            self_test_results["mtproto_orig"] = False
        else:
            st = await run_mtproxy_orig_self_test(
                port=creds.mtproxy_orig_port,
                secret_hex=creds.mtproxy_orig_secret,
            )
            post_preflight.append(st)
            self_test_results["mtproto_orig"] = st.status == "ok"
    if post_preflight:
        _print_preflight(post_preflight)

    # Bind the asyncio Event we'll await in _wait_for_shutdown_signal,
    # so an authenticated POST /stop on the cred-server can wake the
    # main loop and trigger graceful teardown. The shutdown wait then
    # races SIGINT vs /stop and acts on whichever fires first.
    remote_stop_event = asyncio.Event()
    cred_server.bind_stop_event(remote_stop_event, asyncio.get_running_loop())

    # Print status
    _print_responder_status(responders, start_errors, creds)
    console.print("\n[bold green]Listener is ready. Waiting for clients...[/bold green]")
    console.print(
        "[dim]Stops automatically when the client finishes "
        "(POSTs /stop). Ctrl+C is the manual fallback.[/dim]\n"
    )

    started_at = datetime.now(tz=UTC)

    # ── Step 4: Wait for client /stop OR SIGINT ──────────────────────────────
    await _wait_for_shutdown_signal(remote_stop_event)

    stopped_at = datetime.now(tz=UTC)
    duration = (stopped_at - started_at).total_seconds()

    # ── Step 5: Stop responders (snapshot stats inside stop) + echo server ───
    # /snapshot stays 503 until commit_final_snapshots is called below,
    # so no detach handshake is needed — the post-stop path is the
    # only path that ever surfaces counter values.
    # Each responder's stop() captures its final connection_count /
    # data_transfer_ok state BEFORE tearing down its underlying
    # interface/process; the snapshot is then surfaced via the same
    # property names. Doing this before _finalize_protocol_result means
    # the report reflects the absolute last bytes that crossed the wire.
    await _stop_responders(responders, timeout=_STOP_TIMEOUT_SEC)

    # Capture POST-stop snapshots and hand them to the cred-server.
    # /snapshot then flips from 503 → 200 for the client's polling pull.
    # Doing this AFTER stop() makes the snapshot identical to what's
    # going into the JSON report — no more live-vs-final drift.
    final_snapshots: dict[str, dict[str, Any]] = {}
    for name, responder in responders.items():
        try:
            snap_dict = responder.live_snapshot().model_dump(mode="json")
        except Exception as e:
            snap_dict = {"error": f"{type(e).__name__}: {e}"}
        # Inject the post-responder self-test result (computed in
        # step 3c) into the committed snapshot so the client's
        # cross-verification panel can apply the same BLOCKED→ERROR
        # downgrade the listener will write into the JSON report.
        # Keyed by protocol name; absence keeps the field None.
        if name in self_test_results:
            snap_dict["responder_self_test_ok"] = self_test_results[name]
        # Telegram DC reachability from listener egress at preflight
        # time. Only relevant to mtg-based protocols — the client
        # cross-verifier reads it to distinguish "client DPI dropped
        # the data plane" from "listener can't relay to DC". Other
        # protocols leave the field None.
        if name in ("mtproto_proxy", "mtproto_proxy_alt", "mtproto_orig"):
            snap_dict["dc_reach_ok"] = dc_reach_ok
        final_snapshots[name] = snap_dict
    cred_server.commit_final_snapshots(final_snapshots)
    if echo_server is not None:
        try:
            await asyncio.wait_for(echo_server.stop(), timeout=5.0)
        except TimeoutError:
            logger.warning("Echo server stop timed out after 5s; continuing")
        except Exception as e:
            logger.warning("Echo server stop error: %s", e)
    # Snapshot client IP from the cred-endpoint BEFORE tearing it down.
    # The IP is captured under the cred-server's lock when the client
    # successfully fetches credentials; reading it now gives a stable
    # answer even if a late retry races with shutdown.
    client_ip = cred_server.client_ip
    # Keep the cred-server up just long enough for the client's
    # polling /snapshot to land at least once. wait_snapshot_drained
    # returns immediately if the client already GET'd /snapshot after
    # the commit (the common case — client just POSTed /stop and was
    # polling /snapshot), times out after ``_SNAPSHOT_DRAIN_TIMEOUT_SEC``
    # if the operator Ctrl+C'd manually with no client polling.
    drained = await asyncio.to_thread(
        cred_server.wait_snapshot_drained, _SNAPSHOT_DRAIN_TIMEOUT_SEC
    )
    if not drained:
        logger.info(
            "snapshot drain timed out after %.0fs — no client polled /snapshot; "
            "report still saved to disk",
            _SNAPSHOT_DRAIN_TIMEOUT_SEC,
        )
    # Tear down the credentials endpoint last so a slow client retry can
    # still complete during the responder-shutdown window. cred_server.stop
    # is synchronous and doesn't wait for in-flight handlers, so this is
    # cheap and bounded.
    cred_server.stop()

    # ── Step 6: Finalize verdicts from snapshotted state ─────────────────────
    # Per-protocol throughput the client measured via curl-through-tunnel
    # and POSTed in the body of /stop. Authoritative on fast links where
    # the listener's loopback echo collapses below the 30 ms kernel-buffer
    # absorption floor. Empty when an older client (no body) connects;
    # we keep ``avg_throughput_mbps`` as the fallback in that case.
    client_throughput = cred_server.client_throughput()
    results: dict[str, ProtocolResult] = {}
    for name, responder in responders.items():
        pr = _finalize_protocol_result(
            name,
            responder,
            self_test_ok=self_test_results.get(name),
            dc_reach_ok=dc_reach_ok if name in _MTG_PROTOCOLS else None,
        )
        pr.client_avg_throughput_mbps = client_throughput.get(name)
        if name == "mtproto_orig":
            override = _mtproto_orig_failure_note(responder, self_test_results.get(name))
            if override is not None:
                pr.note = override
        elif name in _MTG_PROTOCOLS and dc_reach_ok is False and pr.note is None:
            # mtg accepted the FakeTLS WelcomePacket — that flips the
            # iptables PSH+ACK counter to ≥1 → data_transfer_ok=True →
            # verdict OK by default. But with DC egress blocked the inner
            # Telegram protocol can never complete, so the OK is an
            # artefact of WelcomePacket emission, not a working session.
            # ``_finalize_protocol_result`` already capped the verdict at
            # HANDSHAKE_ONLY for this case — surface the same context as
            # a per-protocol note so it lands in the JSON report.
            pr.note = (
                "listener egress to Telegram DCs blocked at preflight "
                "(telegram-dc-reach 0/N) — mtg accepted the FakeTLS "
                "handshake locally but cannot relay to a real DC, so "
                "client-side resPQ never arrives. The end-to-end protocol "
                "is unusable from this listener vantage, independent of "
                "any client-side DPI."
            )
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
    client_meta = await _enrich_client_or_none(client_ip)

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
        is_mobile=is_mobile,
        is_whitelist=is_whitelist,
        results=results,
    )
    report_path = _save_listener_report(report, test_id, session_id)
    console.print(f"[green]Report saved:[/green] {report_path}")
    console.print(
        "[dim]Publishing is manual: review the file, then "
        "`git add reports/ && git commit && git push` from the host.[/dim]"
    )

    console.print(
        Panel.fit(
            f"[bold green]Session complete.[/bold green]\n"
            f"Duration: {duration:.0f}s\n"
            f"Protocols tested: {len(results)}",
            title="Done",
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# Responder lifecycle
# ─────────────────────────────────────────────────────────────────────────────


async def _start_responders(
    creds: ProtocolCredentials,
    echo_server: EchoServer | None,
) -> tuple[dict[str, Responder], dict[str, str]]:
    """Start all protocol responders.

    Iterates :data:`censprobe_core.protocol_registry.PROTOCOLS` filtered
    by ``censprobe.yaml::protocols.enabled``. Per-protocol factories
    live in :mod:`censprobe_listener._responder_dispatch`.

    Returns ``(started, errors)`` keyed by canonical protocol name.
    """
    responders: dict[str, Responder] = {}
    errors: dict[str, str] = {}

    cfg = get_config()
    requested = cfg.protocols.enabled
    valid_names = set(known_names())
    unknown = [n for n in requested if n not in valid_names]
    if unknown:
        logger.warning(
            "Ignoring unknown protocol names in protocols.enabled: %s (known: %s)",
            ", ".join(unknown),
            ", ".join(sorted(valid_names)),
        )

    for spec in enabled_protocols(requested):
        factory = LISTENER_RESPONDERS.get(spec.name)
        if factory is None:
            logger.error(
                "Protocol %s is in the registry but has no listener factory; "
                "fix _responder_dispatch.py",
                spec.name,
            )
            errors[spec.name] = "no listener factory"
            continue
        try:
            responder = factory(creds, echo_server)
            await responder.start()
            responders[spec.name] = responder
            logger.info("%s started", spec.name)
        except Exception as e:
            # ``logger.exception`` includes the traceback automatically
            # (S8572). ``str(e)`` is still needed for the errors[] map
            # which gets surfaced in the operator-facing status table.
            logger.exception("%s failed to start", spec.name)
            errors[spec.name] = str(e)

    return responders, errors


async def _stop_responders(responders: dict[str, Responder], timeout: float) -> None:
    """Stop all protocol responders gracefully, in parallel, under a deadline.

    Stopping in parallel matters because each individual responder can
    spend up to ~1 s waiting for its child process to exit; running them
    sequentially scales the wall-clock shutdown linearly with the number
    of enabled protocols and ate into our docker-compose
    `stop_grace_period` budget.

    A single overall `timeout` covers the entire fan-out so a misbehaving
    responder cannot block the report from being written.
    """

    async def _stop_one(name: str, responder: Responder) -> None:
        try:
            await responder.stop()
        except Exception as e:
            logger.warning("Error stopping %s: %s", name, e)

    tasks = {name: asyncio.create_task(_stop_one(name, r)) for name, r in responders.items()}
    if not tasks:
        return
    try:
        # async with asyncio.timeout(...) is the Python 3.11+ idiom Sonar
        # S7483 prefers over the older asyncio.wait_for(..., timeout=)
        # pattern. Same semantics, cleaner cancellation.
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks.values(), return_exceptions=True)
    except TimeoutError:
        stuck = [name for name, t in tasks.items() if not t.done()]
        logger.warning(
            "Responder shutdown exceeded %.1fs; cancelling: %s",
            timeout,
            ", ".join(stuck) or "<none>",
        )
        for t in tasks.values():
            if not t.done():
                t.cancel()
        # Drain the cancellations so we don't leak task objects.
        await asyncio.gather(*tasks.values(), return_exceptions=True)


_MTG_PROTOCOLS: tuple[str, ...] = ("mtproto_proxy", "mtproto_proxy_alt")


def _finalize_protocol_result(
    name: str,
    responder: Responder,
    self_test_ok: bool | None = None,
    dc_reach_ok: bool | None = None,
) -> ProtocolResult:
    """Build ProtocolResult from a responder's post-stop snapshot.

    ``self_test_ok`` is the listener-side startup loopback-probe outcome
    for this protocol — ``True`` when the responder successfully
    handshook against itself, ``False`` when it didn't, ``None`` when
    no self-test was configured. As of 2026-05-14 the field is
    diagnostic-only: it's stored on the result for the per-protocol
    failure-note formatter (``_mtproto_orig_failure_note``) and the
    client's cross-verification snapshot, but does NOT change the
    verdict. A wedged responder still produces BLOCKED — operator
    experience matches client experience.

    ``dc_reach_ok`` is the preflight Telegram-DC-reach outcome. Only
    consumed for ``_MTG_PROTOCOLS`` (mtproto_proxy / mtproto_proxy_alt):
    when ``False`` (0/N reachable), the verdict is capped at
    HANDSHAKE_ONLY even if data_transfer_ok=True — because the PSH+ACK
    counter for these protocols can tick on just the WelcomePacket
    emission and the inner Telegram protocol cannot complete without
    DC relay. ``None`` is the no-signal value (check didn't run, or
    not applicable to this protocol) — verdict logic is unchanged.
    """
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

    # Throughput: every protocol-with-an-echo-bind exposes
    # ``echo_server`` (injected in _start_responders). For SOCKS-routed
    # protocols (SS / VLESS / Hy2) the bind is on 127.0.0.1 from
    # EchoServer.start(); for VPN protocols (OpenVPN / WG / AWG) the
    # bind is on the listener-side tun IP, added by the responder via
    # add_tun_bind() once the tun is up. MTProto responders don't carry
    # a /throughput endpoint and leave the field unset.
    avg_throughput: float | None = None
    echo_server = getattr(responder, "echo_server", None)
    if echo_server is not None:
        try:
            avg_throughput = echo_server.throughput_mbps.get(name)
        except (AttributeError, TypeError):
            avg_throughput = None

    # mtg-protocol DC-reach gate: with listener egress to Telegram DCs
    # blocked, the iptables PSH+ACK counter can tick on just the
    # WelcomePacket emission (mtg locally completes FakeTLS before
    # attempting DC relay). data_transfer_ok=True alone is therefore
    # over-optimistic — cap at HANDSHAKE_ONLY so the JSON report and the
    # cross-verify table both reflect that the inner Telegram protocol
    # never had a chance to complete. Other protocols (and the
    # dc_reach_ok=True / dc_reach_ok=None paths) unchanged.
    if name in _MTG_PROTOCOLS and dc_reach_ok is False:
        data_ok = False

    pr = ProtocolResult(
        handshake_count=handshake_count,
        data_transfer_ok=data_ok,
        avg_throughput_mbps=avg_throughput,
        responder_self_test_ok=self_test_ok,
    )
    pr.finalize()
    return pr


def _mtproto_orig_failure_note(responder: Responder, self_test_ok: bool | None) -> str | None:
    """Return a vantage-specific diagnostic note for a failed
    ``mtproto_orig`` session, or ``None`` if the responder reported OK.

    Two distinct failure shapes both surface as ``self_test_ok=False``
    AND a session-time BLOCKED verdict (handshake_count=0, no data):

    * **All upstreams unreachable** (``responder.unavailable=True``):
      every IP in ``proxy-multi.conf`` failed TCP/8888 at prune time,
      so the C MTProxy subprocess was never even launched. Typical for
      RU vantages where ТСПУ drops TCP/8888 to ``91.108.4.0/24`` and
      ``149.154.0.0/16`` outright. The prune itself is **positive
      network-block evidence** — the Telegram DC fleet is confirmed
      unreachable from this vantage, which IS the censorship signal.

    * **Daemon launched but wedged anyway**
      (``responder.unavailable=False`` AND ``self_test_ok=False``):
      prune found ≥ 1 alive upstream and the C binary actually started,
      but the 12-s loopback self-test still timed out. On RU hosts the
      empirical cause is that ТСПУ filters the L7 ``auth_cluster`` RPC
      heartbeat *after* the TCP-handshake (so the SYN-probe at prune
      time passes), starving ``accept4()`` — verified on 2026-05-13
      at 89.169.137.79 (18/19 upstreams alive, 12-s timeout). On non-RU
      hosts this can also be a local daemon issue; the operator
      interprets the note against vantage location.

    Both produce ``Verdict.BLOCKED`` (per the 2026-05-14 design — the
    protocol genuinely does not work end-to-end from this vantage; the
    note disambiguates the L7 vs local cause for the rare non-RU case).
    """
    if self_test_ok is not False:
        return None
    alive = getattr(responder, "upstream_alive_count", 0)
    total = getattr(responder, "upstream_total_count", 0)
    if getattr(responder, "unavailable", False):
        return (
            f"mtproto-proxy not launched: {alive}/{total} proxy-multi.conf "
            f"upstreams reachable on TCP/8888 — Telegram's proxy fleet is "
            f"confirmed unreachable from this vantage (typical for RU hosts "
            f"behind ТСПУ which drops TCP/8888 to 91.108.4.0/24 and "
            f"149.154.0.0/16). The prune itself is the network-block "
            f"signal — mtproto_orig cannot work end-to-end here."
        )
    return (
        f"mtproto-proxy launched with {alive}/{total} upstreams alive "
        f"but the listener-side loopback self-test still timed out "
        f"after 12 s — the C MTProxy slave never accepted its own "
        f"connection. On RU vantages this is consistently caused by "
        f"L7 ТСПУ filtering of the daemon's auth_cluster RPC heartbeat "
        f"(TCP/8888 SYN passes prune but the RPC payload is dropped). "
        f"On non-RU vantages it can also be a local daemon issue — "
        f"strace the slave pid + tune -M N to disambiguate."
    )


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
    ts = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
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
    # Deliberately NOT wrapped in a Rich Panel: the panel borders and any
    # mid-command line wrapping introduced by Rich become literal `│`
    # characters when the operator copies the line on Windows terminals,
    # corrupting the command. We print a short header, then the bare
    # command on its own line with `soft_wrap=True` so the terminal (not
    # Rich) handles wrapping — copying still yields a single clean line.
    console.print()
    console.rule("[bold green]Client setup command[/bold green]", style="green")
    console.print(
        "[bold]Run this on the client machine[/bold] (in your local clone). "
        "Works as-is on Linux, macOS, and Windows (PowerShell or cmd):"
    )
    console.print()
    console.print(cmd, style="cyan", soft_wrap=True, highlight=False, markup=False)
    console.print()
    console.print(
        "[dim]The credentials are served once over a TLS-pinned channel "
        "(self-signed cert, fingerprint above). Token is single-use.[/dim]"
    )
    console.rule(style="green")


def _print_responder_status(
    responders: dict[str, Responder],
    errors: dict[str, str],
    creds: ProtocolCredentials,
) -> None:
    """Show port + run status for every protocol the operator asked for.

    The set of rows comes from the runtime config (``protocols.enabled``)
    intersected with the registry — a protocol disabled in
    censprobe.yaml never appears, and a typo in the YAML produces a
    warning at start_responders rather than a phantom row here. Per-
    protocol port comes from the live :class:`ProtocolCredentials` so
    a port override propagates into this table without code changes.
    """
    cfg = get_config()
    table = Table(title="Listener Status", show_header=True, header_style="bold cyan")
    table.add_column("Protocol", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Status")

    port_attr_for = {
        "openvpn": ("openvpn_port", "UDP"),
        "wireguard": ("wg_port", "UDP"),
        "amneziawg": ("awg_port", "UDP"),
        "shadowsocks": ("ss_port", "TCP"),
        "vless_reality": ("vless_port", "TCP"),
        "hysteria2": ("hy2_port", "UDP"),
        "mtproto_proxy": ("mtproxy_port", "TCP"),
        "mtproto_proxy_alt": ("mtproxy_alt_port", "TCP"),
        "mtproto_orig": ("mtproxy_orig_port", "TCP"),
    }

    for spec in enabled_protocols(cfg.protocols.enabled):
        if spec.name not in port_attr_for:
            raise KeyError(
                f"Listener status table missing port mapping for {spec.name!r} — "
                f"add it to port_attr_for when registering a new protocol."
            )
        attr, transport = port_attr_for[spec.name]
        port_value = getattr(creds, attr)
        port_str = f"{transport}/{port_value}"
        if spec.name in responders:
            responder = responders[spec.name]
            if getattr(responder, "unavailable", False):
                alive = getattr(responder, "upstream_alive_count", 0)
                total = getattr(responder, "upstream_total_count", 0)
                table.add_row(
                    spec.name,
                    port_str,
                    f"[yellow]Skipped ({alive}/{total} upstreams)[/yellow]",
                )
            else:
                table.add_row(spec.name, port_str, "[green]Running[/green]")
        else:
            err = errors.get(spec.name, "unknown error")
            table.add_row(spec.name, port_str, f"[red]Failed: {err[:40]}[/red]")

    console.print(table)


def _print_client_summary(connected: bool, meta: EndpointMeta | None) -> None:
    """Operator-facing summary of which client network this session saw.

    Three states match the report's tri-state (see ListenerReport docstring).
    No IPs are printed here either — only the structured network identity.
    """
    if not connected:
        console.print(
            Panel.fit(
                "[red]Client never reached the credentials endpoint.[/red]\n"
                "[dim]Per-protocol BLOCKED verdicts in this run reflect the "
                "client network's inability to reach 8443/tcp at all, not "
                "protocol-specific blocking.[/dim]",
                title=_CLIENT_NETWORK_PANEL_TITLE,
                border_style="red",
            )
        )
        return

    if meta is None:
        console.print(
            Panel.fit(
                "[yellow]Client connected, but ipapi enrichment failed.[/yellow]\n"
                "[dim]Per-protocol verdicts are still meaningful; only the "
                "client-network identity is missing in the report.[/dim]",
                title=_CLIENT_NETWORK_PANEL_TITLE,
                border_style="yellow",
            )
        )
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
        # Bare DATACENTER label — no "likely behind self-hosted VPN"
        # qualifier. ipapi.is misclassifies a meaningful fraction of
        # residential / mobile-carrier prefixes (free-WiFi gateways,
        # carrier NAT pools that share /24s with hosting) as datacenter,
        # so the flag is not a reliable VPN indicator. We still surface
        # it for visibility but no longer infer intent from it.
        flags.append("[yellow]DATACENTER[/yellow]")
    flag_line = " · ".join(flags) if flags else "[dim]residential[/dim]"

    console.print(
        Panel.fit(
            f"Org: [cyan]{line_org}[/cyan]\n"
            f"ASN: [cyan]{line_asn}[/cyan]  Route: [dim]{line_route}[/dim]\n"
            f"Location: [cyan]{line_loc}[/cyan]\n"
            f"Type: {flag_line}",
            title="Client network",
            border_style="green",
        )
    )


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
