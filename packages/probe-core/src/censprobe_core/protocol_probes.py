"""
protocol_probes.py — Client-side VPN handshake probes using real binaries.

Verdicts:
  OK              — handshake succeeded AND data echo round-trip succeeded
  HANDSHAKE_ONLY  — handshake succeeded, data phase failed/timed out
  BLOCKED         — handshake never completed (refused / timeout / RST)
  ERROR           — probe error (binary missing, config invalid, ...)

For SS / VLESS+Reality / Hysteria-2 the listener-side runs a TCP echo
server on 127.0.0.1:ECHO_PORTS[protocol]. The client does:
    curl -x socks5h://127.0.0.1:<proxy_port>  http://127.0.0.1:<echo_port>/ping
The `socks5h` scheme makes the tunnel server resolve "127.0.0.1" on ITS
side, which means the listener's own echo endpoint.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import socket
import tempfile
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ParamSpec

from censprobe_core.echo_ports import ECHO_PORTS, TUN_ECHO_PORTS, VPN_TUN_LISTENER_IPS
from censprobe_core.link_utils import async_delete_iface, async_rm_amneziawg_socket
from censprobe_core.models import Verdict
from censprobe_core.utils import graceful_terminate, write_secret

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 15.0

# Black-hole sink for curl bodies in echo / throughput probes — we only
# care about the wall-clock + bandwidth metrics, never the response body
# (zero-byte payload for /ping, throwaway zeros for /throughput).
# Hoisted to a constant (Sonar S1192) so the three curl invocations
# below all reference the same literal.
_CURL_BODY_SINK = "/dev/null"

# Re-exported so existing callers that did `from
# censprobe_core.protocol_probes import ECHO_PORTS` keep working — the
# canonical home is censprobe_core.echo_ports.
__all__ = [
    "ASYMMETRIC_DPI_ERROR_MARKERS",
    "ECHO_PORTS",
    "PROBE_TIMEOUT",
    "AmneziaWGObfuscation",
    "ProbeResult",
    "probe_amneziawg",
    "probe_hysteria2",
    "probe_openvpn",
    "probe_shadowsocks",
    "probe_vless_reality",
    "probe_wireguard",
    "probe_mtproto_proxy",
    "probe_mtproto_orig",
    "ping_echo",
    "proxy_echo",
]


# Error-string substrings emitted by ``_mtg_error_result`` that the
# client-side cross-verifier treats as evidence of asymmetric DPI when
# the listener-side counter reports the handshake reached it. Exported
# as a frozen tuple so the client (and any future analyser) imports the
# canonical contract rather than copying string literals — a refactor
# that renames these markers in one file would otherwise silently break
# the cross-verify attribution (regression of commit 280cf77 / memory
# ``mts_round_2026-05-13``).
#
# Adding a new marker: emit the substring from ``_mtg_error_result``,
# add the prefix here, document the failure shape in
# :class:`ProbeResult` history. The substring match is intentional —
# many actual error strings carry a record-index suffix
# (``welcome_read_timeout_record0``) and a category-level prefix
# match keeps the contract stable across that suffix variation.
ASYMMETRIC_DPI_ERROR_MARKERS: tuple[str, ...] = (
    "welcome_read_timeout",
    "orig_resPQ_len_timeout",
    "orig_resPQ_body_timeout",
    "orig_resPQ_truncated",
)

# Deterministic interface names so a crashed run leaves something we can
# proactively clean up (otherwise a stale tun/wg device keeps holding the
# tunnel-IP route and silently blackholes the next probe).
_OVPN_CLI_IFACE = "censovpn1"
_WG_CLI_IFACE = "censwg1"
_AWG_CLI_IFACE = "censawg1"


@dataclass(frozen=True, slots=True)
class AmneziaWGObfuscation:
    """The 9 magic numbers AmneziaWG mixes into its handshake.

    Bundled into a single argument so client and listener don't have to
    pass nine separate ints around — also keeps :func:`probe_amneziawg`
    under Sonar's S107 "too many parameters" cap. The defaults match a
    "no-op" obfuscation profile that still produces a valid AmneziaWG
    handshake.
    """

    jc: int = 4
    jmin: int = 40
    jmax: int = 70
    s1: int = 0
    s2: int = 0
    h1: int = 0
    h2: int = 0
    h3: int = 0
    h4: int = 0


@dataclass
class ProbeResult:
    verdict: Verdict = Verdict.BLOCKED
    handshake_ok: bool = False
    data_ok: bool = False
    # Protocol-specific latency signal. Semantics differ by probe:
    #   * openvpn / wireguard / amneziawg — ICMP-ping RTT measured
    #     *through* the established tunnel (data-plane). None until
    #     handshake completed.
    #   * shadowsocks / hysteria2 / vless_reality — TCP/QUIC connect
    #     RTT to the listener.
    #   * mtproto_proxy / mtproto_proxy_alt / mtproto_orig — TCP connect
    #     RTT to the proxy (NOT the full req_pq→resPQ round-trip; for
    #     that, see ``elapsed_ms``).
    # rtt_ms is intentionally NOT "total probe duration" — that field is
    # ``elapsed_ms`` below. For a probe that times out reading L7 frames
    # after a fast TCP-connect, rtt_ms will be in the ms range while
    # elapsed_ms will be the full PROBE_TIMEOUT. That distinction is the
    # whole reason elapsed_ms exists: prior to its introduction (May 2026)
    # display layers rendered rtt_ms as "(Xms)" next to verdicts, which
    # silently misled operators on every timeout-failing probe.
    rtt_ms: float | None = None
    # Total wall-clock time from probe function entry to return,
    # regardless of verdict. Always set when the probe ran. The display
    # layer prefers this for "(Xms)" labels because it's the only field
    # whose semantics are uniform across protocols and across OK/error
    # return paths.
    elapsed_ms: float | None = None
    error: str | None = None
    # Sustained-data signal — populated for every protocol whose data
    # phase carries real bytes:
    #   * SOCKS-routed protocols (SS / VLESS / Hy2) — measured through
    #     the SOCKS proxy to the loopback echo on 127.0.0.1.
    #   * VPN protocols (OpenVPN / WG / AmneziaWG) — measured directly
    #     through the tun to the listener-side echo bound on the
    #     listener tun IP (see :data:`VPN_TUN_LISTENER_IPS`).
    # MTProto protocols stay `None` because they speak MTProto (not
    # plain HTTP) and our echo doesn't talk back in MTProto framing.
    #
    # NOT used as a scoring criterion: a slow VPS with a narrow uplink
    # would otherwise be penalised for non-censorship reasons. The value
    # is for operator inspection (CLI + dashboard) only.
    throughput_mbps: float | None = None
    # True iff the throughput download didn't complete inside
    # ``cfg.throughput.timeout_sec``. That's a strong indication the
    # data plane is heavily throttled — but it can also fire on a
    # server with a small uplink, so the flag is informational, not a
    # verdict.
    throughput_throttled: bool = False


_P = ParamSpec("_P")


def _stamp_elapsed(
    fn: Callable[_P, Coroutine[Any, Any, ProbeResult]],
) -> Callable[_P, Coroutine[Any, Any, ProbeResult]]:
    """Wrap a probe coroutine so its ProbeResult always carries
    ``elapsed_ms`` set to the function's total wall-clock runtime.

    Centralised here so individual probes don't have to stamp the field
    at every return site (each has 10+ early-exit ProbeResult paths for
    parsing, TCP-connect, handshake-fail, timeout, etc.). The wrapper
    only writes the field when the inner function left it ``None``, so
    a probe is free to override with a more nuanced measurement if it
    wants (none currently do).

    Declared return type is ``Coroutine`` rather than ``Awaitable`` so
    callers wrapping the result in ``asyncio.create_task`` typecheck
    cleanly — ``create_task`` rejects bare ``Awaitable``.
    """

    @functools.wraps(fn)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> ProbeResult:
        t0 = time.monotonic()
        result = await fn(*args, **kwargs)
        if result.elapsed_ms is None:
            result.elapsed_ms = (time.monotonic() - t0) * 1000
        return result

    return wrapper


async def run_cmd(cmd: list[str], timeout: float = PROBE_TIMEOUT) -> tuple[int, str, str]:
    """Run a command with timeout and return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        # Python 3.11+ context manager (S7483) instead of asyncio.wait_for(...).
        async with asyncio.timeout(timeout):
            stdout, stderr = await proc.communicate()
        # proc.returncode is documented as non-None after communicate()
        # returns. Defensive check (not ``assert``, which python -O
        # strips) so a future asyncio race or a SIGCHLD interleaving
        # that leaves returncode unset surfaces as a real error instead
        # of a mypy-only attribute violation in production.
        if proc.returncode is None:
            raise RuntimeError(
                f"subprocess {cmd[0]!r} communicate() returned without "
                f"setting returncode — likely an asyncio race"
            )
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except TimeoutError:
        with contextlib.suppress(OSError):
            proc.kill()
        # Reap the process so it doesn't linger as a zombie. wait() can
        # race with kill — we only need the upper bound.
        with contextlib.suppress(Exception):
            await proc.wait()
        return -1, "", "Timeout"


_HS_SUCCESS_TOKENS = (
    # sing-box / xray / hysteria2 markers proving an UPSTREAM tunnel
    # handshake actually completed (not just a local SOCKS listener
    # spinning up). These promote BLOCKED→HANDSHAKE_ONLY when the
    # data-plane curl failed but the upstream proved reachable, so it
    # is critical they be evidence of remote-peer activity, not local
    # bookkeeping. Anything that fires from listener bring-up alone
    # ("started listen", "listening on …") is excluded — the local
    # SOCKS proxy logging that line is a startup event, not handshake
    # evidence, and including it caused BLOCKED to be falsely promoted
    # to HANDSHAKE_ONLY.
    "inbound connection",
    "connection established",
    "handshake complete",
    "tunnel established",
    "authenticated",
    "accepted tcp:",
    "client connected",
    "server connected",
    "new connection:",
)

_HS_FAILURE_TOKENS = (
    "handshake failed",
    "connection refused",
    "no route to host",
    "i/o timeout",
    "context deadline exceeded",
    "tls: ",
    "reality verify failed",
    "auth failed",
    "authentication failed",
    "dial tcp",
    "dial udp",
)


def _start_log_drain(
    proc: asyncio.subprocess.Process,
    buf: bytearray,
    max_bytes: int = 65536,
) -> asyncio.Task[None] | None:
    """Drain proc.stdout continuously so the child never blocks on a full pipe.

    Linux pipes are ~64 KiB. If the tunnel binary (sing-box / xray /
    hysteria) logs more than that while proxy_echo is still running and
    nothing is reading, the child's next write() stalls and the whole
    tunnel freezes — proxy_echo then times out and we wrongly report
    "blocked". The drain task reads continuously into an in-memory buffer
    (bounded so a chatty binary doesn't eat RAM); after proxy_echo
    returns we decode the buffer for handshake-success classification.

    Synchronous (non-coroutine) by design — Sonar S7503 flagged the
    previous ``async def`` as having no awaits of its own. The function
    *creates* an async task; it doesn't need to be a coroutine itself.
    Callers must drop the ``await`` (the function returns the task
    directly).
    """
    if proc.stdout is None:
        return None
    # Pin the local for type narrowing — mypy can't follow ``proc.stdout
    # is not None`` from the enclosing scope into the inner coroutine,
    # and an ``assert`` here would be stripped by python -O.
    stdout = proc.stdout

    async def _drain() -> None:
        try:
            while True:
                chunk = await stdout.read(4096)
                if not chunk:
                    return
                remaining = max_bytes - len(buf)
                if remaining > 0:
                    buf.extend(chunk[:remaining])
                # Once the buffer is full, keep reading (and discarding) so
                # the producer never blocks on a full pipe.
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    return asyncio.create_task(_drain())


async def _stop_log_drain(task: asyncio.Task[None] | None) -> None:
    if task is None or task.done():
        return
    task.cancel()
    # CancelledError on cancel() is expected; any other exception means
    # the drain task already errored and we're tearing down anyway.
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task


def _classify_proxy_outcome(
    status: str,
    log_text: str,
) -> tuple[bool, bool]:
    """Return (handshake_ok, is_real_handshake_only).

    Given proxy_echo's status and tunnel log, decide whether the outcome
    actually reflects a completed upstream handshake.

    "blocked" used to short-circuit straight to (False, False), but that
    conflated two distinct cases: curl-through-SOCKS could fail because
    the upstream handshake never completed (true BLOCKED) or because the
    handshake succeeded but the tunneled HTTP request itself died (data
    plane failure — semantically HANDSHAKE_ONLY, matching the listener's
    own ``handshake_count > 0 and not data_transfer_ok`` aggregation).
    Both "blocked" and "inconclusive" therefore consult tunnel logs for
    a success marker; if one is present and no failure marker appears,
    we elevate to HANDSHAKE_ONLY so client- and listener-side verdicts
    line up on the dashboard's per-protocol-per-session row.

    Accepts statuses: "ok", "blocked", "inconclusive" (legacy alias
    "handshake_only" from older callers also tolerated).
    """
    if status == "ok":
        return True, False

    # Both "blocked" and "inconclusive" inspect logs — see docstring.
    low = log_text.lower()
    saw_success = any(tok in low for tok in _HS_SUCCESS_TOKENS)
    saw_failure = any(tok in low for tok in _HS_FAILURE_TOKENS)
    if saw_success and not saw_failure:
        return True, True
    return False, False


async def ping_echo(
    ip: str, timeout: float = 3.0, count: int = 3, min_received: int = 2
) -> tuple[bool, float | None]:
    """Ping a tunnel IP and return (data_plane_ok, avg_rtt_ms).

    Sends ``count`` ICMP echoes, requires at least ``min_received`` replies
    to declare the data plane working. A single ping is too weak: in some
    container/host networking edge cases (Windows Docker Desktop with
    ``network_mode: host``, certain VPN-on-VPN nesting setups) a lone
    echo can spuriously succeed even when the listener never observed any
    traffic — producing client-side OK / listener-side BLOCKED splits.
    Requiring ≥2 echoes out of 3 makes those single-shot quirks visible.

    The ``ping`` exit status is ``0`` only when at least one reply was
    received, so we additionally parse "N received" out of stdout to apply
    the stricter ``min_received`` threshold.

    The avg-RTT we surface is iputils' own ``rtt min/avg/max/mdev``
    summary line. WG / AWG probes use this as the displayed RTT
    instead of the previous "time to first non-zero
    latest-handshakes timestamp" reading: that one was a polling-
    resolution artifact (1 ms when the handshake completed during
    ``wg-quick up``, 505 ms when the polling tick was 0.5 s) and
    misled operators about actual data-plane latency. Ping RTT is
    the honest data-plane round-trip after the tunnel is up.
    """
    deadline = max(int(timeout), 1)
    code, out, _ = await run_cmd(
        ["ping", "-c", str(count), "-W", str(deadline), "-i", "0.3", ip],
        # Worst case: count * deadline (pings can stall up to deadline each).
        timeout=count * deadline + 2,
    )
    if code != 0:
        return False, None
    received = _parse_ping_received(out)
    avg_rtt = _parse_ping_avg_rtt(out)
    return received >= min_received, avg_rtt


def _parse_ping_received(out: str) -> int:
    """Extract ``N received`` from iputils-ping's summary line.

    Format::

        <count> packets transmitted, <received> received, 0% packet loss, ...

    Exit code 0 from ``ping`` means ≥1 reply was received, but the
    ``ping_echo`` data-plane gate requires a stricter ``min_received``
    threshold to filter Docker-Desktop / nested-VPN host-network quirks
    that fake a single ICMP reply even when the tunnel never came up.
    Returns 0 if the summary line is missing or unparseable — caller
    treats that the same as "no replies".
    """
    for line in out.splitlines():
        stripped = line.strip()
        if "packets transmitted" not in stripped or " received" not in stripped:
            continue
        parts = stripped.split(",")
        if len(parts) < 2:
            continue
        tokens = parts[1].strip().split()
        if tokens and tokens[0].isdigit():
            return int(tokens[0])
        return 0
    return 0


def _parse_ping_avg_rtt(out: str) -> float | None:
    """Extract the ``avg`` from iputils-ping's RTT summary line.

    Format::

        rtt min/avg/max/mdev = 0.067/0.094/0.123/0.024 ms

    Returned to surface honest data-plane round-trip latency in the
    WG/AWG probe display path (replaces the previous "time to first
    non-zero handshakes timestamp" reading, which was a polling-
    resolution artifact). Returns ``None`` if the line is missing or
    malformed.
    """
    for line in out.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("rtt ") and "/" in stripped):
            continue
        try:
            values = stripped.split("=", 1)[1].strip().split()[0]
            fields = values.split("/")
            if len(fields) >= 2:
                return float(fields[1])
        except (IndexError, ValueError):
            return None
    return None


async def _wg_peer_rx_bytes(tool: str, iface: str) -> int:
    """Return the cumulative rx_bytes the local WG/AWG iface received from
    its peer, parsed from ``<tool> show <iface> transfer``.

    Output format (one line per peer, tab-separated):
        <peer_pubkey>\\t<rx_bytes>\\t<tx_bytes>

    Why this matters: ``ping_echo`` can spuriously succeed on Windows
    Docker Desktop with ``network_mode: host`` even when the tunnel
    never came up — the host's networking layer fakes ICMP echo replies
    for routes that fall through to the WG/AWG interface. The transfer
    counters are updated by the WG userspace daemon only when actual
    encrypted bytes from the peer have been decrypted, so a ``rx_bytes
    > 0`` reading is unforgeable from the OS network stack: it proves
    the listener-side responder really sent crypto traffic to us.

    Returns the highest rx counter across all peer rows (we only
    configure one peer, but the parser tolerates any count). Any parse
    failure returns 0 so callers treat it as "no proof of return
    traffic" and downgrade to HANDSHAKE_ONLY rather than OK.
    """
    code, out, _ = await run_cmd([tool, "show", iface, "transfer"], timeout=2.0)
    if code != 0:
        return 0
    best = 0
    for line in out.splitlines():
        parts = line.split()
        # parts = [peer_pubkey, rx_bytes, tx_bytes] — accept whitespace
        # too in case some build emits spaces instead of tabs.
        if len(parts) >= 2 and parts[1].isdigit():
            rx = int(parts[1])
            if rx > best:
                best = rx
    return best


async def _wait_port_listening(
    port: int,
    host: str = "127.0.0.1",
    timeout: float = 5.0,
    interval: float = 0.05,
) -> bool:
    """Poll TCP <host>:<port> until something accepts a connection.

    Closes the race where the tunnel binary (sing-box/xray/hysteria) has
    spawned but hasn't yet bound its local SOCKS port — without this poll,
    an early curl gets ECONNREFUSED (exit 7) and the probe wrongly reports
    BLOCKED even though the tunnel will come up a moment later.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            async with asyncio.timeout(0.5):
                _reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            # Reachability already proven by SYN-ACK; clean shutdown is
            # incidental and may race with peer-side close.
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True
        except OSError:
            # TimeoutError and ConnectionRefusedError are both OSError
            # subclasses (since Python 3.10 / always, respectively) —
            # Sonar S5713 flagged the tuple as redundant.
            await asyncio.sleep(interval)
    return False


def _pick_free_local_port() -> int:
    """Reserve a free TCP port from the OS and return its number.

    Sets SO_REUSEADDR (and SO_REUSEPORT where available) on the picker
    socket so that even if a colliding listener manages to bind during
    the close → tunnel-start gap (network_mode: host containers do
    expose us to busy-port races on shared VPS), the tunnel binary's
    rebind succeeds rather than refusing with EADDRINUSE.

    Closing-then-rebinding is still a race, just a much smaller one
    than `random.randint(50000, 60000)` would be — port collisions in
    a 16-bit space happened often enough in CI to fail builds.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


# ─────────────────────────────────────────────────────────────────────────────
# Proxy-based echo: distinguishes handshake from data-phase.
# Returns: ("ok", rtt_ms)             — data phase OK (curl exit 0, HTTP 200)
#          ("handshake_only", None)   — SOCKS connect succeeded but data didn't
#          ("blocked", None)          — local SOCKS port not listening at all
#          ("inconclusive", None)     — SOCKS reachable, outcome ambiguous
#                                        (caller should consult tunnel logs)
# ─────────────────────────────────────────────────────────────────────────────
async def proxy_echo(
    proxy_port: int,
    echo_port: int,
    proxy_type: str = "socks5h",
    timeout: float = 5.0,
    socks_ready: bool = True,
) -> tuple[str, float | None]:
    """Run a single curl through the local SOCKS proxy.

    `socks_ready` should be True when the caller has already confirmed the
    SOCKS port is listening (via _wait_port_listening). If False, exit
    code 7 is treated as "tunnel never came up" rather than "remote side
    blocked us".
    """
    t0 = time.monotonic()
    cmd = [
        "curl",
        "-s",
        "-o",
        _CURL_BODY_SINK,
        "--max-time",
        str(timeout),
        "-w",
        "%{http_code}",
        "-x",
        f"{proxy_type}://127.0.0.1:{proxy_port}",
        f"http://127.0.0.1:{echo_port}/ping",
    ]
    code, out, _err = await run_cmd(cmd, timeout=timeout + 1)
    rtt = (time.monotonic() - t0) * 1000

    # Success: echo server reached, HTTP 2xx returned.
    if code == 0 and out.strip().startswith("2"):
        return "ok", rtt

    # Local SOCKS port unreachable. This means the tunnel binary itself is
    # not listening — neither a "blocked" remote nor "handshake only", just
    # a startup problem. We still report "blocked" upstream so the verdict
    # reflects "no working tunnel from this client".
    # Exit 7  = couldn't connect (TCP refused) — only meaningful when the
    #           caller hasn't already polled the SOCKS port.
    # Exit 5  = couldn't resolve proxy host — impossible with literal
    #           127.0.0.1, but kept for completeness.
    if code in (5, 7) and not socks_ready:
        return "blocked", None

    # Curl exit 97 (CURLE_PROXY): "error during SOCKS proxy negotiation"
    # — the local SOCKS server *did* accept our TCP connect but rejected
    # the handshake. That can mean either:
    #   (a) the upstream VPN tunnel has not actually established a session
    #       (so the proxy can't satisfy CONNECT), or
    #   (b) the tunnel is up but the server-side rejected the destination.
    # We can't tell from curl alone — return "inconclusive" and let the
    # caller decide via tunnel-log inspection (_classify_proxy_outcome).
    # Same for any other non-zero curl exit (28=timeout, 52=got_nothing,
    # 56=recv_error, 18=partial, …): SOCKS connect plausibly succeeded but
    # the remote data phase did not.
    return "inconclusive", None


# ─────────────────────────────────────────────────────────────────────────────
# Sustained-data throughput probe (SS / VLESS / Hy2 only).
# Returns: (mbps, throttled)
#   mbps:      client-measured download rate in Mbps; None if the curl
#              call failed for any reason other than timeout.
#   throttled: True iff curl exited 28 (operation timed out), i.e. the
#              tunnel could not deliver cfg.throughput.target_bytes
#              inside the window. Caller surfaces this as a flag, not a
#              verdict.
# ─────────────────────────────────────────────────────────────────────────────
async def proxy_throughput(
    proxy_port: int,
    echo_port: int,
    target_bytes: int | None = None,
    timeout: float | None = None,
) -> tuple[float | None, bool]:
    """Download ``target_bytes`` from the listener echo via the local SOCKS proxy.

    When ``target_bytes`` / ``timeout`` are omitted (the common path —
    callers in this module always omit them), values come from
    :class:`censprobe_core.config.ThroughputConfig`. Explicit arguments
    win, so tests can pin specific values without touching the global
    config singleton.

    The numeric result is informational and intentionally not consumed
    by scoring — narrow server uplink would otherwise look like
    censorship. Caller is expected to print the value in the CLI / pass
    it through into the report and let the dashboard show it as a
    side channel.
    """
    from censprobe_core.config import get_config

    tcfg = get_config().throughput
    if not tcfg.enabled:
        return None, False
    n_bytes = target_bytes if target_bytes is not None else tcfg.target_bytes
    n_timeout = timeout if timeout is not None else tcfg.timeout_sec
    cmd = [
        "curl",
        "-s",
        "-o",
        _CURL_BODY_SINK,
        "--max-time",
        str(n_timeout),
        # %{exitcode}: curl's own exit; %{size_download}: total bytes
        # received (rejects partial transfers); %{time_total} and
        # %{time_starttransfer}: TIMING in seconds — we use their
        # difference as pure stream duration. ``%{speed_download}``
        # is curl's whole-transfer average and includes the TCP+SOCKS+
        # HTTP setup overhead (~one RTT on intercontinental hops),
        # which biases the measurement DOWN by 30-70% on small 8 MiB
        # payloads. The size/(t_total - t_starttransfer) formula
        # matches what the listener-side echo records (first-byte to
        # last-byte) so the two columns are comparable.
        "-w",
        "%{exitcode} %{size_download} %{time_total} %{time_starttransfer}",
        "-x",
        f"socks5h://127.0.0.1:{proxy_port}",
        f"http://127.0.0.1:{echo_port}/throughput?bytes={n_bytes}",
    ]
    code, out, _err = await run_cmd(cmd, timeout=n_timeout + 2)
    parts = out.strip().split()
    if len(parts) < 4:
        return None, False
    try:
        exit_code = int(parts[0])
        size = int(parts[1])
        time_total = float(parts[2])
        time_starttransfer = float(parts[3])
    except ValueError:
        return None, False

    # curl exit 28 = CURLE_OPERATION_TIMEDOUT — the link did not deliver
    # the requested payload inside the deadline. We surface this as the
    # throttled flag (not a verdict) so the operator can see "data plane
    # established but heavily throttled" in the CLI / dashboard.
    if exit_code == 28:
        return None, True

    if code != 0 or size <= 0:
        return None, False

    pure_duration = time_total - time_starttransfer
    # Sub-millisecond windows are kernel-buffer-absorption regimes
    # (same artefact echo_server._MIN_THROUGHPUT_DURATION_SEC guards
    # against on the listener side). Match that 30 ms floor so the
    # client-side number is similarly artefact-proof.
    if pure_duration < 0.03:
        return None, False
    return (size * 8) / pure_duration / 1_000_000, False


# ─────────────────────────────────────────────────────────────────────────────
# Direct (tun-routed) throughput probe — OpenVPN / WG / AmneziaWG.
# Mirrors ``proxy_throughput`` but the curl runs against the listener-side
# tun IP without going through a SOCKS proxy. Bandwidth measured the same
# way (curl's ``%{speed_download}`` averaged over the transfer).
# ─────────────────────────────────────────────────────────────────────────────
async def tunnel_throughput(
    target_host: str,
    target_port: int,
    target_bytes: int | None = None,
    timeout: float | None = None,
) -> tuple[float | None, bool]:
    """Download ``target_bytes`` from the listener echo direct via the tun.

    Used by ``probe_openvpn`` / ``probe_wireguard`` / ``probe_amneziawg``
    after data_ok==True to surface the same sustained-throughput signal
    the SOCKS-routed probes already produce via ``proxy_throughput``.
    The listener side binds an HTTP echo at
    ``http://<listener_tun_ip>:<port>/throughput?bytes=N`` only AFTER its
    tun is up (see :meth:`EchoServer.add_tun_bind`), so this curl is
    routed by the kernel through the tun device and meters real link
    capacity rather than loopback buffer absorption.

    Return shape matches ``proxy_throughput`` so the caller can swap in
    either function without changing the result handling.
    """
    from censprobe_core.config import get_config

    tcfg = get_config().throughput
    if not tcfg.enabled:
        return None, False
    n_bytes = target_bytes if target_bytes is not None else tcfg.target_bytes
    n_timeout = timeout if timeout is not None else tcfg.timeout_sec
    cmd = [
        "curl",
        "-s",
        "-o",
        _CURL_BODY_SINK,
        "--max-time",
        str(n_timeout),
        # Same write-out tokens as proxy_throughput; see the long
        # comment there for why we compute pure stream duration as
        # (time_total - time_starttransfer) instead of trusting
        # curl's whole-transfer-averaged ``%{speed_download}``.
        "-w",
        "%{exitcode} %{size_download} %{time_total} %{time_starttransfer}",
        f"http://{target_host}:{target_port}/throughput?bytes={n_bytes}",
    ]
    code, out, _err = await run_cmd(cmd, timeout=n_timeout + 2)
    parts = out.strip().split()
    if len(parts) < 4:
        return None, False
    try:
        exit_code = int(parts[0])
        size = int(parts[1])
        time_total = float(parts[2])
        time_starttransfer = float(parts[3])
    except ValueError:
        return None, False

    if exit_code == 28:
        return None, True
    if code != 0 or size <= 0:
        return None, False

    pure_duration = time_total - time_starttransfer
    if pure_duration < 0.03:
        return None, False
    return (size * 8) / pure_duration / 1_000_000, False


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN probe
# ─────────────────────────────────────────────────────────────────────────────
@_stamp_elapsed
async def probe_openvpn(host: str, port: int, psk_pem: str) -> ProbeResult:
    result = ProbeResult()
    if not psk_pem or "BEGIN OpenVPN Static key" not in psk_pem:
        result.error = "bad PSK: missing OpenVPN Static key V1 envelope"
        return result

    # Pre-clean any stale tun from a previously-crashed run. With a fixed
    # interface name we can reliably scrub the leftover /32 peer route to
    # 10.200.0.1, which would otherwise blackhole this probe.
    await async_delete_iface(_OVPN_CLI_IFACE)

    with tempfile.TemporaryDirectory(prefix="censprobe_client_ovpn_") as tmpdir:
        tmp_path = Path(tmpdir)
        psk_path = tmp_path / "static.key"
        # write_secret opens with O_CREAT mode 0o600 in one syscall — closes
        # the TOCTOU window where ``write_text`` + follow-up ``chmod`` would
        # briefly leave the file world-readable under the process umask.
        write_secret(psk_path, psk_pem)

        # Server side uses ifconfig 10.200.0.1 10.200.0.2 → client mirrors.
        # Cipher must match the server (AES-256-CBC; AEAD ciphers are not
        # allowed with `secret` / static-key mode).
        # `dev <name>` + `dev-type tun` forces a deterministic interface
        # name so we can reliably clean it up after a SIGKILL.
        config = f"""
proto udp
remote {host} {port}
dev {_OVPN_CLI_IFACE}
dev-type tun
secret {psk_path}
ifconfig 10.200.0.2 10.200.0.1
keepalive 10 60
cipher AES-256-CBC
resolv-retry infinite
nobind
verb 1
"""
        conf_path = tmp_path / "client.conf"
        conf_path.write_text(config)

        proc = await asyncio.create_subprocess_exec(
            "openvpn",
            "--config",
            str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        # PIPE above guarantees proc.stdout is not None; pin to a local so
        # mypy narrows inside the loop below without an assert that python -O
        # would strip.
        if proc.stdout is None:  # pragma: no cover — defensive
            raise RuntimeError("openvpn subprocess opened without a stdout pipe")
        proc_stdout = proc.stdout

        try:
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                try:
                    async with asyncio.timeout(1.0):
                        line_bytes = await proc_stdout.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode(errors="replace")
                    if "Initialization Sequence Completed" in line:
                        hs_ok = True
                        result.rtt_ms = (time.monotonic() - t0) * 1000
                        break
                except TimeoutError:
                    continue

            result.handshake_ok = hs_ok
            if hs_ok:
                # Once handshake is done, openvpn keeps logging. Drain stdout
                # in the background so verb-1 status pings don't fill the
                # pipe and stall the tunnel during ping_echo.
                drain_buf = bytearray()
                drain_task = _start_log_drain(proc, drain_buf)
                try:
                    result.verdict = Verdict.HANDSHAKE_ONLY
                    ok, _avg_rtt = await ping_echo("10.200.0.1")
                    if ok:
                        result.data_ok = True
                        result.verdict = Verdict.OK
                        # Sustained-throughput follow-up via the
                        # listener-side echo bound on 10.200.0.1:9994 by
                        # OpenVPNResponder.start(). Informational only —
                        # never affects the verdict (a narrow uplink must
                        # not look like censorship).
                        mbps, throttled = await tunnel_throughput(
                            VPN_TUN_LISTENER_IPS["openvpn"],
                            TUN_ECHO_PORTS["openvpn"],
                        )
                        result.throughput_mbps = mbps
                        result.throughput_throttled = throttled
                        # Keep the existing rtt_ms (time-to-handshake from
                        # OpenVPN's "Initialization Sequence Completed"
                        # marker) — that's the metric operators are used
                        # to seeing for OpenVPN. Ping RTT becomes useful
                        # if we ever surface data-plane latency, but for
                        # OpenVPN the handshake-to-completion window is
                        # the dominant slow step on flaky links.
                finally:
                    await _stop_log_drain(drain_task)
        finally:
            await graceful_terminate(proc)
            # Belt-and-braces: openvpn normally tears down its own tun on
            # exit, but if it was SIGKILLed the device leaks.
            await async_delete_iface(_OVPN_CLI_IFACE)

    return result


async def _poll_wg_handshake(tool: str, iface: str, timeout: float) -> bool:
    """Poll ``<tool> show <iface> latest-handshakes`` until a non-zero
    timestamp appears (peer replied) or ``timeout`` elapses.

    Shared by ``probe_wireguard`` (``tool="wg"``) and ``probe_amneziawg``
    (``tool="awg"``) — extracting the loop keeps each probe under
    Sonar S3776's cognitive-complexity ceiling and removes the prior
    near-duplicate code blocks.

    The function used to also return a "time to first non-zero
    timestamp" reading, but that was a polling-resolution artifact
    (1 ms when the handshake completed during ``wg-quick up`` and
    the first poll caught it; 505 ms when the next poll tick was
    0.5 s later) and was misinterpreted as data-plane RTT. The
    actual round-trip is now sourced from ``ping_echo`` after
    handshake completion — see :func:`probe_wireguard` and
    :func:`probe_amneziawg`.
    """
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        _, out, _ = await run_cmd([tool, "show", iface, "latest-handshakes"], timeout=1.0)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "0":
                return True
        await asyncio.sleep(0.5)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard probe
# ─────────────────────────────────────────────────────────────────────────────
@_stamp_elapsed
async def probe_wireguard(
    host: str,
    port: int,
    server_public: str,
    preshared: str,
    private_key: str,
) -> ProbeResult:
    # The previous signature carried ``client_public`` for symmetry with
    # the listener side, but the WG client peer block only needs the
    # client's *private* key (the public one is derived by wg-quick).
    # Sonar S1172 flagged it as unused.
    result = ProbeResult()
    if not private_key:
        result.error = "Missing client private key"
        return result

    with tempfile.TemporaryDirectory(prefix="censprobe_client_wg_") as tmpdir:
        tmp_path = Path(tmpdir)
        # WG client subnet must match listener (moved off 10.200/24 to
        # avoid OpenVPN-tun routing collision in host netns).
        config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.202.0.2/24

[Peer]
PublicKey = {server_public}
PresharedKey = {preshared}
Endpoint = {host}:{port}
AllowedIPs = 10.202.0.1/32
PersistentKeepalive = 25
"""
        conf_path = tmp_path / f"{_WG_CLI_IFACE}.conf"
        # WG conf carries the client private key + preshared key — write
        # with O_CREAT mode 0o600 in one syscall to close the TOCTOU
        # window where ``write_text`` + follow-up ``chmod`` would briefly
        # leave the file world-readable under the process umask.
        write_secret(conf_path, config)

        # Remove any stale interface from a previously killed run. wg-quick
        # up would otherwise fail with "File exists" in host netns.
        await async_delete_iface(_WG_CLI_IFACE)

        code, _, err = await run_cmd(["wg-quick", "up", str(conf_path)])
        if code != 0:
            result.error = f"wg-quick up failed: {err}"
            # Even on failure, scrub anything wg-quick may have half-set-up.
            await async_delete_iface(_WG_CLI_IFACE)
            return result

        try:
            hs_ok = await _poll_wg_handshake("wg", _WG_CLI_IFACE, PROBE_TIMEOUT)
            result.handshake_ok = hs_ok
            if hs_ok:
                result.verdict = Verdict.HANDSHAKE_ONLY
                # Two independent signals required for OK: ping_echo
                # (≥2/3 ICMP echoes return) AND ``wg show transfer``
                # (rx_bytes > 0). The second guards against Windows
                # Docker Desktop ``network_mode: host`` spoofing ICMP
                # replies — see _wg_peer_rx_bytes docstring.
                ping_ok, ping_rtt = await ping_echo("10.202.0.1")
                # Surface the ping-derived RTT regardless of OK
                # promotion: even a HANDSHAKE_ONLY verdict is more
                # informative when the operator can see "≥2 echoes
                # came back this fast" vs "no echoes at all".
                if ping_rtt is not None:
                    result.rtt_ms = ping_rtt
                if ping_ok:
                    rx = await _wg_peer_rx_bytes("wg", _WG_CLI_IFACE)
                    if rx > 0:
                        result.data_ok = True
                        result.verdict = Verdict.OK
                        # Sustained-throughput follow-up — informational
                        # only, never affects the verdict.
                        mbps, throttled = await tunnel_throughput(
                            VPN_TUN_LISTENER_IPS["wireguard"],
                            TUN_ECHO_PORTS["wireguard"],
                        )
                        result.throughput_mbps = mbps
                        result.throughput_throttled = throttled
        finally:
            # Try `wg-quick down` first (also drops routes/rules); fall
            # back to a hard `ip link del` so a leftover interface never
            # survives this probe.
            await run_cmd(["wg-quick", "down", str(conf_path)])
            await async_delete_iface(_WG_CLI_IFACE)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# AmneziaWG probe
# ─────────────────────────────────────────────────────────────────────────────
@_stamp_elapsed
async def probe_amneziawg(
    host: str,
    port: int,
    server_public: str,
    preshared: str,
    private_key: str,
    obfuscation: AmneziaWGObfuscation,
) -> ProbeResult:
    # The previous signature exposed all 9 obfuscation magic ints
    # individually plus an unused ``client_public``; bundling the magic
    # ints into :class:`AmneziaWGObfuscation` and dropping the unused
    # field brings us under Sonar's S107 cap and resolves S1172.
    result = ProbeResult()
    if not private_key:
        result.error = "Missing client private key"
        return result

    with tempfile.TemporaryDirectory(prefix="censprobe_client_awg_") as tmpdir:
        tmp_path = Path(tmpdir)
        o = obfuscation
        config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.201.0.2/24
Jc = {o.jc}
Jmin = {o.jmin}
Jmax = {o.jmax}
S1 = {o.s1}
S2 = {o.s2}
H1 = {o.h1}
H2 = {o.h2}
H3 = {o.h3}
H4 = {o.h4}

[Peer]
PublicKey = {server_public}
PresharedKey = {preshared}
Endpoint = {host}:{port}
AllowedIPs = 10.201.0.1/32
PersistentKeepalive = 25
"""
        conf_path = tmp_path / f"{_AWG_CLI_IFACE}.conf"
        # AWG conf carries the client private key + preshared key + the 9
        # H/S/Jc obfuscation magic ints (secret per session). Same
        # TOCTOU-safe write as WG above.
        write_secret(conf_path, config)

        # Remove any stale interface AND its userspace control socket from
        # a previously killed run. amneziawg-go writes a unix socket under
        # /var/run/amneziawg/<iface>.sock; `ip link del` only drops the
        # TUN, leaving the socket behind to confuse the next bring-up.
        await async_delete_iface(_AWG_CLI_IFACE)
        await async_rm_amneziawg_socket(_AWG_CLI_IFACE)

        code, _, err = await run_cmd(["awg-quick", "up", str(conf_path)])
        if code != 0:
            result.error = f"awg-quick up failed: {err}"
            await async_delete_iface(_AWG_CLI_IFACE)
            await async_rm_amneziawg_socket(_AWG_CLI_IFACE)
            return result

        try:
            # Must use `awg` (not `wg`) — amneziawg-go is a userspace
            # implementation whose socket lives in /var/run/amneziawg/,
            # which vanilla `wg` does not look at and silently fails on.
            # Without this, hs_ok would always stay False, the data-phase
            # ping never fires, and the probe wrongly reports BLOCKED
            # while the listener side reports HANDSHAKE_ONLY (because
            # awg-quick already pushed an initiation on bring-up).
            hs_ok = await _poll_wg_handshake("awg", _AWG_CLI_IFACE, PROBE_TIMEOUT)
            result.handshake_ok = hs_ok
            if hs_ok:
                result.verdict = Verdict.HANDSHAKE_ONLY
                # Same two-signal gate as the WireGuard probe: ping
                # alone is not enough on Windows Docker Desktop with
                # ``network_mode: host``. ``awg show transfer``
                # rx_bytes can only be raised by the userspace
                # daemon when real encrypted bytes from the peer
                # have been decrypted, so a non-zero reading proves
                # the listener-side responder actually answered.
                ping_ok, ping_rtt = await ping_echo("10.201.0.1")
                if ping_rtt is not None:
                    result.rtt_ms = ping_rtt
                if ping_ok:
                    rx = await _wg_peer_rx_bytes("awg", _AWG_CLI_IFACE)
                    if rx > 0:
                        result.data_ok = True
                        result.verdict = Verdict.OK
                        # Sustained-throughput follow-up — informational
                        # only, never affects the verdict.
                        mbps, throttled = await tunnel_throughput(
                            VPN_TUN_LISTENER_IPS["amneziawg"],
                            TUN_ECHO_PORTS["amneziawg"],
                        )
                        result.throughput_mbps = mbps
                        result.throughput_throttled = throttled
        finally:
            # awg-quick down handles routing/socket cleanup when the conf
            # is still readable; the hard fallbacks ensure no leftovers.
            await run_cmd(["awg-quick", "down", str(conf_path)])
            await async_delete_iface(_AWG_CLI_IFACE)
            await async_rm_amneziawg_socket(_AWG_CLI_IFACE)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Shadowsocks-2022 probe
# ─────────────────────────────────────────────────────────────────────────────
@_stamp_elapsed
async def probe_shadowsocks(host: str, port: int, method: str, password_b64: str) -> ProbeResult:
    return await _tunnel_via_singbox_or_xray(
        binary_cmd=["sing-box", "run", "-c", "{conf}"],
        proto_label="shadowsocks",
        config_builder=lambda local_port: {
            "log": {"level": "warn", "output": "stdout", "timestamp": True},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": local_port,
                }
            ],
            "outbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "ss-out",
                    "server": host,
                    "server_port": port,
                    "method": method,
                    "password": password_b64,
                }
            ],
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# VLESS+Reality probe
# ─────────────────────────────────────────────────────────────────────────────
@_stamp_elapsed
async def probe_vless_reality(
    host: str, port: int, uuid: str, public_key: str, short_id: str, server_name: str
) -> ProbeResult:
    return await _tunnel_via_singbox_or_xray(
        binary_cmd=["xray", "run", "-c", "{conf}"],
        proto_label="vless_reality",
        config_builder=lambda local_port: {
            "inbounds": [
                {
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": host,
                                "port": port,
                                "users": [
                                    {
                                        "id": uuid,
                                        "encryption": "none",
                                        "flow": "xtls-rprx-vision",
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": server_name,
                            "fingerprint": "chrome",
                            "show": False,
                            "publicKey": public_key,
                            "shortId": short_id,
                            "spiderX": "",
                        },
                    },
                }
            ],
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Hysteria 2 probe
# ─────────────────────────────────────────────────────────────────────────────
@_stamp_elapsed
async def probe_hysteria2(host: str, port: int, auth: str, obfs_password: str) -> ProbeResult:
    result = ProbeResult()
    local_port = _pick_free_local_port()
    with tempfile.TemporaryDirectory(prefix="censprobe_client_hy2_") as tmpdir:
        tmp_path = Path(tmpdir)
        config = f"""
server: {host}:{port}
auth: {auth}
tls:
  sni: censprobe-test
  insecure: true
obfs:
  type: salamander
  salamander:
    password: {obfs_password}
bandwidth:
  up: 100 mbps
  down: 100 mbps
socks5:
  listen: 127.0.0.1:{local_port}
"""
        conf_path = tmp_path / "config.yaml"
        # Hysteria 2 conf carries the operator auth password + salamander
        # obfs password — TOCTOU-safe write so the 0o600 perms are
        # set at file-creation time.
        write_secret(conf_path, config)

        proc = await asyncio.create_subprocess_exec(
            "hysteria",
            "client",
            "-c",
            str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        log_buf = bytearray()
        drain_task = _start_log_drain(proc, log_buf)
        try:
            # Wait until hysteria actually binds its local SOCKS port
            # (or until it gives up). Replaces a fixed `sleep(1.0)` that
            # raced the probe on slow boxes.
            socks_ready = await _wait_port_listening(local_port, timeout=PROBE_TIMEOUT)
            if proc.returncode is not None:
                await _stop_log_drain(drain_task)
                result.error = (
                    f"hysteria failed to start: {bytes(log_buf).decode(errors='replace')}"
                )
                return result

            status, rtt = await proxy_echo(
                local_port,
                ECHO_PORTS["hysteria2"],
                "socks5h",
                socks_ready=socks_ready,
            )
            log_text = bytes(log_buf).decode("utf-8", errors="replace")
            hs_ok, is_hs_only = _classify_proxy_outcome(status, log_text)
            if status == "ok":
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = rtt
                # Sustained-throughput follow-up — strictly informational,
                # never affects the verdict (see proxy_throughput docstring).
                mbps, throttled = await proxy_throughput(
                    local_port,
                    ECHO_PORTS["hysteria2"],
                )
                result.throughput_mbps = mbps
                result.throughput_throttled = throttled
            elif is_hs_only:
                result.handshake_ok = True
                result.verdict = Verdict.HANDSHAKE_ONLY
            else:
                result.handshake_ok = hs_ok
                result.verdict = Verdict.BLOCKED
        finally:
            await _stop_log_drain(drain_task)
            await graceful_terminate(proc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Shared helper: start sing-box/xray with a local SOCKS, probe echo, tear down.
# ─────────────────────────────────────────────────────────────────────────────
async def _populate_proxy_result(
    result: ProbeResult,
    proto_label: str,
    local_port: int,
    socks_ready: bool,
    log_buf: bytearray,
) -> None:
    """Drive proxy_echo + outcome classification onto ``result`` in place.

    Extracted so ``_tunnel_via_singbox_or_xray`` stays under Sonar's S3776
    cognitive-complexity threshold; the verdict-mapping fan-out alone is
    five branches.
    """
    status, rtt = await proxy_echo(
        local_port,
        ECHO_PORTS[proto_label],
        "socks5h",
        socks_ready=socks_ready,
    )
    log_text = bytes(log_buf).decode("utf-8", errors="replace")
    hs_ok, is_hs_only = _classify_proxy_outcome(status, log_text)
    if status == "ok":
        result.handshake_ok = True
        result.data_ok = True
        result.verdict = Verdict.OK
        result.rtt_ms = rtt
        # Same informational throughput follow-up as in probe_hysteria2;
        # surfaced in CLI and dashboard but never modifies the verdict.
        mbps, throttled = await proxy_throughput(local_port, ECHO_PORTS[proto_label])
        result.throughput_mbps = mbps
        result.throughput_throttled = throttled
    elif is_hs_only:
        result.handshake_ok = True
        result.verdict = Verdict.HANDSHAKE_ONLY
    else:
        result.handshake_ok = hs_ok
        result.verdict = Verdict.BLOCKED


async def _tunnel_via_singbox_or_xray(
    binary_cmd: list[str],
    proto_label: str,
    config_builder: Callable[[int], dict[str, Any]],
) -> ProbeResult:
    result = ProbeResult()
    local_port = _pick_free_local_port()
    with tempfile.TemporaryDirectory(prefix=f"censprobe_client_{proto_label}_") as tmpdir:
        conf_path = Path(tmpdir) / "config.json"
        # SOCKS-routed config carries protocol-specific secrets (Reality
        # private/public key + short-id, SS password, etc) — TOCTOU-safe
        # write with mode 0o600 at file-creation.
        write_secret(conf_path, json.dumps(config_builder(local_port), indent=2))
        cmd = [c.format(conf=str(conf_path)) for c in binary_cmd]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        log_buf = bytearray()
        drain_task = _start_log_drain(proc, log_buf)
        try:
            # Poll for the local SOCKS port instead of a fixed sleep — on
            # slow VPS hardware sing-box/xray can take >1 s to bind, and
            # an early curl returns ECONNREFUSED, which we'd previously
            # mis-classify as BLOCKED.
            socks_ready = await _wait_port_listening(local_port, timeout=PROBE_TIMEOUT)
            if proc.returncode is not None:
                result.error = (
                    f"{cmd[0]} failed to start: {bytes(log_buf).decode(errors='replace')}"
                )
                return result
            await _populate_proxy_result(result, proto_label, local_port, socks_ready, log_buf)
        finally:
            await _stop_log_drain(drain_task)
            await graceful_terminate(proc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# MTProto Proxy probe
# ─────────────────────────────────────────────────────────────────────────────
#
# mtg (the responder we run server-side) speaks **fake-TLS** — a Telegram
# client opens a connection that looks like TLS 1.2 on the wire and the
# proxy validates the ClientHello via an HMAC over its own bytes (with the
# 32-byte client_random nullified) keyed on the secret. If the HMAC check
# fails, mtg falls back to **domain fronting**: it transparently proxies
# the connection to the secret-embedded host (google.com by default), so
# *any* TCP connect — including a censor's active-probe — gets a real TLS
# response back. That makes "did we get bytes?" a useless reachability
# signal: the only meaningful probe is one that constructs a valid fake-
# TLS ClientHello and verifies the proxy's matching ServerHello.
#
# Reference for the on-wire format:
#   - mtg (server side):  mtglib/internal/tls/fake/{client,server}_side.go
#   - alexbers/mtprotoproxy (server-side handler that documents the same
#     algorithm in Python):  handle_fake_tls_handshake()
#
# The HMAC trick (Telegram's spec):
#   1. Build the full 517-byte ClientHello with the 32 random bytes
#      placeholder-zeroed.
#   2. Compute digest = HMAC-SHA256(secret_key, clientHello_with_zero_random).
#   3. Real client_random = digest[0:28] || (digest[28:32] XOR LE(now_unix)).
#      The server XORs digest into received random and gets back zeros +
#      timestamp; both equal-prefix and freshness are checked.
def _mtg_error_result(error: str, verdict: Verdict = Verdict.ERROR) -> ProbeResult:
    r = ProbeResult()
    r.error = error
    r.verdict = verdict
    return r


def _parse_mtproto_secret(secret_hex: str) -> tuple[bytes, str] | ProbeResult:
    """Parse the ee-secret. Returns (16-byte key, ASCII SNI host) or a failed ProbeResult.

    ee-secret = 'ee' || 16-byte random key || hostname (latin1 ASCII).
    'dd'-prefixed and prefixless legacy formats predate fake-TLS and are
    not accepted by mtg, so we reject them here rather than building a
    ClientHello the server can't possibly validate.
    """
    try:
        secret_bytes = bytes.fromhex(secret_hex)
    except ValueError:
        return _mtg_error_result("secret_not_hex")

    if len(secret_bytes) < 18 or secret_bytes[0] != 0xEE:
        return _mtg_error_result("secret_not_faketls")

    try:
        sni_host = secret_bytes[17:].decode("ascii")
    except UnicodeDecodeError:
        return _mtg_error_result("secret_sni_not_ascii")
    if not sni_host:
        return _mtg_error_result("secret_sni_empty")

    return secret_bytes[1:17], sni_host


def _build_mtproto_clienthello(
    secret_key: bytes, sni_host: str
) -> tuple[bytearray, bytes, bytes] | ProbeResult:
    """Build the 517-byte fake-TLS ClientHello with HMAC-derived client_random.

    Returns ``(hello_bytes, session_id, client_random)`` or a failed
    ProbeResult if length invariants would be violated. ``client_random``
    is the exact 32-byte block we end up writing into the ClientHello —
    needed verbatim later as the first input to mtg's WelcomePacket HMAC,
    which is what distinguishes a real mtg response from a domain-fronting
    fallback (mtg falls back to fronting on ANY validation failure: bad
    HMAC, ≥3 s clock skew, replay, even a captive-portal MitM serving its
    own real TLS would clear the session-id-only check).

    Layout copied from the reference implementations; the ciphersuite list,
    session-id length (32), and extension layout are all checked by mtg's
    parser, so we cannot freely mutate them. The 32-byte session_id is
    tracked locally and must be echoed back by the proxy in ServerHello.
    """
    import hashlib
    import hmac
    import secrets as _secrets

    session_id = _secrets.token_bytes(32)
    sni_bytes = sni_host.encode("ascii")

    hello = bytearray()
    # TLS record header: ContentType=22 (Handshake), version=0x0301 (TLS 1.0
    # for record-layer compatibility), record length=0x0200 (=512). The
    # record-layer total is 5 (header) + 512 = 517 bytes.
    hello += b"\x16\x03\x01\x02\x00"
    # HandshakeType=1 (ClientHello), 24-bit length=0x0001fc (=508), version
    # 0x0303 (TLS 1.2).
    hello += b"\x01\x00\x01\xfc\x03\x03"
    random_offset = len(hello)  # 11 bytes of headers precede client_random
    hello += b"\x00" * 32  # client_random placeholder (zeroed for HMAC)
    hello += b"\x20" + session_id  # session_id_len=32, then session_id
    # Cipher suites + compression methods (verbatim from mtprotoproxy
    # reference; mtg accepts any non-GREASE suite, but we use a known-good
    # modern list to look like a stock browser handshake).
    hello += (
        b"\x00\x22\x4a\x4a\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f"
        b"\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c"
        b"\x00\x9d\x00\x2f\x00\x35\x00\x0a"
    )
    # compression_methods: 1 byte length, then 1 byte value (null compression).
    hello += b"\x01\x00"

    # Extensions block — total length is patched in once we know it.
    ext = bytearray()
    # extended_master_secret (no payload).
    ext += b"\x00\x17\x00\x00"
    # renegotiation_info (length=1, value=0).
    ext += b"\xff\x01\x00\x01\x00"
    # SNI (server_name).
    sni_ext = bytearray()
    sni_ext += b"\x00"  # name_type byte 0 (host_name)
    sni_ext += len(sni_bytes).to_bytes(2, "big") + sni_bytes
    sni_list = len(sni_ext).to_bytes(2, "big") + bytes(sni_ext)
    ext += b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    # supported_groups (curves).
    ext += b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18"
    # ec_point_formats.
    ext += b"\x00\x0b\x00\x02\x01\x00"
    # signature_algorithms.
    ext += (
        b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03"
        b"\x02\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    )
    # supported_versions: TLS 1.3, 1.2.
    ext += b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    # psk_key_exchange_modes.
    ext += b"\x00\x2d\x00\x02\x01\x01"
    # key_share — single x25519 group with a 32-byte random "public" (mtg
    # never decrypts past the handshake, so the bytes need only have the
    # right length).
    ext += b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" + _secrets.token_bytes(32)

    # Pad the extensions out so the final record is exactly 517 bytes.
    # (mtg validates record length structurally — too short or too long
    # both fail parseClientHello.)
    target_total = 517
    # 5 (record hdr) + 4 (handshake hdr) + 2 (version) + 32 (random)
    #   + 1 (sid_len) + 32 (sid) + 2 (cs_len) + 34 (cs) + 1 (comp_len)
    #   + 1 (comp) + 2 (ext_total_len) + len(ext) + padding == 517
    fixed_prefix = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 34 + 1 + 1 + 2
    pad_len = target_total - fixed_prefix - len(ext)
    if pad_len >= 4:
        # padding extension (type 0x0015, len=N-4, then zeros).
        ext += b"\x00\x15"
        ext += (pad_len - 4).to_bytes(2, "big")
        ext += b"\x00" * (pad_len - 4)
    elif pad_len > 0:
        # Should never happen with the chosen extension set, but keep the
        # length invariant intact rather than emitting a malformed record.
        ext += b"\x00" * pad_len

    hello += len(ext).to_bytes(2, "big") + bytes(ext)

    if len(hello) != target_total:
        return _mtg_error_result(f"clienthello_len={len(hello)}")

    # ── Compute the HMAC-derived client_random ─────────────────────────────
    digest = hmac.new(secret_key, bytes(hello), hashlib.sha256).digest()
    timestamp = int(time.time())
    ts_bytes = timestamp.to_bytes(4, "little")
    new_random = bytearray(digest)
    for i in range(4):
        new_random[28 + i] ^= ts_bytes[i]
    hello[random_offset : random_offset + 32] = new_random
    return hello, session_id, bytes(new_random)


async def _open_mtproto_tcp(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, float] | ProbeResult:
    t0 = time.monotonic()
    try:
        async with asyncio.timeout(PROBE_TIMEOUT):
            reader, writer = await asyncio.open_connection(host, port)
    except TimeoutError:
        return _mtg_error_result("tcp_timeout", Verdict.BLOCKED)
    except ConnectionRefusedError:
        return _mtg_error_result("connection_refused", Verdict.BLOCKED)
    except OSError as e:
        return _mtg_error_result(str(e).lower(), Verdict.BLOCKED)
    return reader, writer, (time.monotonic() - t0) * 1000


async def _send_clienthello(writer: asyncio.StreamWriter, hello: bytearray) -> ProbeResult | None:
    writer.write(bytes(hello))
    try:
        async with asyncio.timeout(5.0):
            await writer.drain()
    except (TimeoutError, ConnectionResetError, BrokenPipeError) as e:
        return _mtg_error_result(f"write_failed:{type(e).__name__}", Verdict.BLOCKED)
    return None


async def _read_one_welcome_record(
    reader: asyncio.StreamReader,
    idx: int,
    expected_type: int,
    current_total: int,
    max_total: int,
) -> bytes | ProbeResult:
    """Read+validate one TLS record from mtg's WelcomePacket.

    Returns the raw header+body bytes on success, or a BLOCKED
    ProbeResult tagged with the specific failure point. Split out from
    ``_read_mtproto_welcome_packet`` so the outer 3-record loop and the
    inner per-record validation each stay below Sonar S3776's
    cognitive-complexity ceiling.
    """
    try:
        async with asyncio.timeout(5.0):
            header = await reader.readexactly(5)
    except asyncio.IncompleteReadError:
        return _mtg_error_result(f"welcome_truncated_record{idx}", Verdict.BLOCKED)
    except TimeoutError:
        return _mtg_error_result(f"welcome_read_timeout_record{idx}", Verdict.BLOCKED)
    if header[0] != expected_type:
        return _mtg_error_result(f"welcome_bad_type_record{idx}={header[0]:#x}", Verdict.BLOCKED)
    if header[1:3] != b"\x03\x03":
        return _mtg_error_result(f"welcome_bad_version_record{idx}", Verdict.BLOCKED)
    record_len = int.from_bytes(header[3:5], "big")
    if record_len == 0:
        return _mtg_error_result(f"welcome_zero_len_record{idx}", Verdict.BLOCKED)
    if current_total + 5 + record_len > max_total:
        return _mtg_error_result(f"welcome_oversize_record{idx}={record_len}", Verdict.BLOCKED)
    try:
        async with asyncio.timeout(5.0):
            body = await reader.readexactly(record_len)
    except asyncio.IncompleteReadError:
        return _mtg_error_result(f"welcome_short_body_record{idx}", Verdict.BLOCKED)
    except TimeoutError:
        return _mtg_error_result(f"welcome_read_timeout_body_record{idx}", Verdict.BLOCKED)
    return bytes(header) + body


async def _read_mtproto_welcome_packet(reader: asyncio.StreamReader) -> bytes | ProbeResult:
    """Read mtg's full WelcomePacket — three concatenated TLS records.

    On a valid faketls handshake mtg always sends, in this exact order
    (mtglib/internal/faketls/welcome.go::SendWelcomePacket):

      1. Handshake (0x16)        — ServerHello with HMAC-bearing random
      2. ChangeCipherSpec (0x14) — single 0x01 byte payload
      3. ApplicationData (0x17)  — 1024…4115 bytes of random padding

    All three bear version 0x0303 (TLS 1.2). The HMAC that authenticates
    the response is computed over the *entire* concatenation (with the
    32 bytes at WelcomePacketRandomOffset zeroed), so we MUST read all
    three records to validate. A domain-fronted real-TLS ServerHello may
    pass the session-id check, but cannot reproduce mtg's HMAC because
    the fronted server doesn't know the secret key.

    Capped at 16 KiB total (real welcome packet ≤ ~4.2 KiB; anything
    larger is a stalling middlebox or bulk fronted transfer) so a
    misbehaving peer can't make us read forever.
    """
    packet = bytearray()
    max_total = 16 * 1024
    for idx, expected_type in enumerate((0x16, 0x14, 0x17)):
        record_or_err = await _read_one_welcome_record(
            reader, idx, expected_type, len(packet), max_total
        )
        if isinstance(record_or_err, ProbeResult):
            return record_or_err
        packet += record_or_err
    return bytes(packet)


# ServerHello body starts 5 bytes (record hdr) + 4 bytes (handshake hdr) +
# 2 bytes (server-version) into the packet, so the welcome-random sits at
# offset 11. mtg's WelcomePacketRandomOffset constant agrees.
_MTG_WELCOME_RANDOM_OFFSET = 11
_MTG_WELCOME_RANDOM_LEN = 32


def _validate_welcome_packet(
    packet: bytes, session_id: bytes, client_random: bytes, secret_key: bytes
) -> ProbeResult | None:
    """Validate mtg's WelcomePacket. Three checks, in order of strictness:

      1. ServerHello structurally well-formed and echoes our 32-byte
         session-id (a real TLS server also echoes session-id, so this
         alone is NOT enough — but it cheaply rejects RST / HTTP error
         pages before we hit HMAC).
      2. Welcome random == HMAC-SHA256(secret, client_random || packet
         with bytes [11:43] zeroed). This is the cryptographic proof
         that the peer holds the same ee-secret. A domain-fronted
         google.com cannot fake this, regardless of session-id echo.

    We use ``hmac.compare_digest`` to keep the comparison constant-time
    against an attacker-controlled HMAC byte string (theoretical here,
    but the safer default).
    """
    if len(packet) < _MTG_WELCOME_RANDOM_OFFSET + _MTG_WELCOME_RANDOM_LEN:
        return _mtg_error_result("welcome_too_short", Verdict.BLOCKED)
    # ServerHello sits at the start of record 1's payload — i.e. byte 5
    # (after the 5-byte record header). HandshakeType(server) = 0x02.
    if packet[5] != 0x02:
        return _mtg_error_result("not_server_hello", Verdict.BLOCKED)
    # session_id offset inside record 1: 5 (rec hdr) + 4 (hs hdr) + 2 (ver)
    # + 32 (random) + 1 (sid_len) = 44; sid follows.
    sid_offset = 5 + 4 + 2 + 32
    if len(packet) < sid_offset + 1:
        return _mtg_error_result("welcome_truncated_pre_sid", Verdict.BLOCKED)
    sid_len = packet[sid_offset]
    if sid_len != len(session_id):
        return _mtg_error_result(f"bad_sid_len={sid_len}", Verdict.BLOCKED)
    if len(packet) < sid_offset + 1 + sid_len:
        return _mtg_error_result("welcome_truncated_in_sid", Verdict.BLOCKED)
    if packet[sid_offset + 1 : sid_offset + 1 + sid_len] != session_id:
        return _mtg_error_result("session_id_mismatch", Verdict.BLOCKED)

    import hashlib
    import hmac

    received_random = bytes(
        packet[_MTG_WELCOME_RANDOM_OFFSET : _MTG_WELCOME_RANDOM_OFFSET + _MTG_WELCOME_RANDOM_LEN]
    )
    zeroed = bytearray(packet)
    zeroed[_MTG_WELCOME_RANDOM_OFFSET : _MTG_WELCOME_RANDOM_OFFSET + _MTG_WELCOME_RANDOM_LEN] = (
        b"\x00" * _MTG_WELCOME_RANDOM_LEN
    )
    expected = hmac.new(secret_key, client_random + bytes(zeroed), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, received_random):
        # Almost certainly mtg's domain-fronting fallback — the peer
        # served a real TLS ServerHello (so type/version/sid_echo all
        # checked out) but did not know our ee-secret. Treat as BLOCKED:
        # the proxy is not actually reachable by Telegram clients.
        return _mtg_error_result("welcome_hmac_mismatch", Verdict.BLOCKED)
    return None


@_stamp_elapsed
async def probe_mtproto_proxy(host: str, port: int, secret_hex: str) -> ProbeResult:
    """Three-signal probe of mtg (faketls + obfuscated2 + relayed MTProto).

    Sequence:
        1. Open TCP, send fake-TLS ClientHello with HMAC-derived random.
        2. Receive WelcomePacket (3 TLS records), validate the HMAC over
           the entire concatenation — proves the peer holds the same
           ee-secret. A captive-portal / domain-fronting MitM cannot
           reproduce this HMAC because the secret never leaves the
           listener-issued credentials channel.
        3. **Send obfuscated2 init + encrypted req_pq_multi as a TLS
           ApplicationData record** (mtg unwraps records on read; see
           ``_exchange_obfuscated2_respq`` docstring) and validate the
           encrypted resPQ that comes back from the upstream Telegram DC
           via mtg's relay. This third stage is what raised the
           cryptographic bar from "WelcomePacket HMAC valid" to "full
           MTProto handshake completed end-to-end through mtg → DC".

    Why three signals: stage 2 alone proved the *responder* holds the
    secret, but did not exercise mtg's relay or the DC reachability.
    Stage 3 closes that gap — a censor that allows the faketls handshake
    but blocks subsequent mtproto traffic (the realistic ТСПУ pattern of
    "let TLS through, drop everything else") gets caught at stage 3,
    not at stage 2.

    Verdicts:
        OK              — all three stages succeeded; full data-plane
                          path through mtg → Telegram DC verified.
        HANDSHAKE_ONLY  — WelcomePacket HMAC OK but resPQ length-read
                          timed out: mtg accepted our obfuscated2 init,
                          DC-side blackholed (or DPI severed mid-stream
                          before the DC could reply).
        BLOCKED         — anything tearing the TCP / failing structural
                          checks. Each preserves the strict
                          "BLOCKED implies confirmed block" invariant.
    """
    parsed = _parse_mtproto_secret(secret_hex)
    if isinstance(parsed, ProbeResult):
        return parsed
    secret_key, sni_host = parsed

    built = _build_mtproto_clienthello(secret_key, sni_host)
    if isinstance(built, ProbeResult):
        return built
    hello, session_id, client_random = built

    opened = await _open_mtproto_tcp(host, port)
    if isinstance(opened, ProbeResult):
        return opened
    reader, writer, rtt_ms = opened

    try:
        write_err = await _send_clienthello(writer, hello)
        if write_err is not None:
            return write_err

        packet = await _read_mtproto_welcome_packet(reader)
        if isinstance(packet, ProbeResult):
            return packet

        validation_err = _validate_welcome_packet(packet, session_id, client_random, secret_key)
        if validation_err is not None:
            return validation_err

        # WelcomePacket HMAC validated → peer holds the same ee-secret
        # (real mtg, not a domain-fronting fallback or captive-portal
        # MitM). Continue with the obfuscated2 + req_pq_multi exchange
        # to also prove that mtg's upstream relay to a real Telegram DC
        # is alive — otherwise a DPI box that allows the faketls
        # handshake (which looks like a real TLS 1.3 session) but blocks
        # subsequent obfuscated bytes would still report OK.
        respq_err = await _exchange_obfuscated2_respq(
            reader, writer, secret_key, wrap_inner_in_tls_record=True
        )
        if respq_err is not None:
            if respq_err.rtt_ms is None:
                respq_err.rtt_ms = rtt_ms
            return respq_err

        # All three stages passed: TCP + faketls (HMAC-secret proof) +
        # full MTProto resPQ via the relayed DC connection. End-to-end
        # data-plane reachability cryptographically proven. ``data_ok``
        # stays False to keep the same convention as mtproto_orig — the
        # one-shot resPQ is not a sustained data exchange.
        result = ProbeResult()
        result.handshake_ok = True
        result.data_ok = False
        result.rtt_ms = rtt_ms
        result.verdict = Verdict.OK
        return result
    finally:
        # Best-effort connection close — peer may have torn down already
        # on the error path.
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


# ─────────────────────────────────────────────────────────────────────────────
# Original Telegram MTProxy (obfuscated2 / padded-intermediate) probe
# ─────────────────────────────────────────────────────────────────────────────
#
# Unlike mtg, the original ``mtproto-proxy`` (TelegramMessenger/MTProxy, C)
# does NOT speak fakeTLS. Wire format is "obfuscated2" — a 64-byte init
# frame the client sends in plaintext; the proxy derives AES-CTR keys
# from bytes [8:56] of the frame plus the operator secret, and decrypts
# bytes [56:60] to verify the chosen MTProto transport tag (we use
# ``0xdddddddd`` four times = padded-intermediate, the mode public
# Telegram proxies typically deploy because random-padding defeats
# packet-size fingerprinting).
#
# After the init frame, the proxy is a TRANSPARENT proxy to a real
# Telegram DC: it re-frames the obfuscated2 payload onto a plain MTProto
# connection to the appropriate DC (chosen via the ``proxy-multi.conf``
# topology baked into the listener image). Therefore "is the proxy
# alive" cannot be checked locally — the probe must send a real MTProto
# request (``req_pq_multi``) and verify the resulting ``resPQ`` echoes
# the nonce we picked. This gives two independent failure surfaces:
#
#   1. The 64-byte init / first padded-intermediate frame survives the
#      path without RST → censor doesn't blacklist obfuscated2 init
#      bytes per se.
#   2. The proxy returned a structurally valid MTProto resPQ with our
#      nonce → proxy holds the same secret AND has reachable upstream
#      to a Telegram DC.
#
# Verdict on success: ``OK`` once resPQ is validated end-to-end. For
# the partial case where TCP stays open past PROBE_TIMEOUT without a
# resPQ length prefix arriving, we downgrade to ``HANDSHAKE_ONLY`` —
# the listener provably accepted our obfuscated2 init (a wrong-secret
# frame would have been RST'd immediately), but upstream Telegram DC
# never replied. The verdict aggregator counts both as "reached".
#
# CAVEAT: this probe depends on the listener having outbound reachability
# to the Telegram DC IPs in proxy-multi.conf. If outbound is blocked at
# the listener (rather than the client), verdicts collapse to BLOCKED
# without that being a client-side DPI signal. In practice, listeners
# that successfully run mtg (which also dials Telegram DCs upstream)
# will satisfy this — but worth keeping in mind when interpreting RU
# vs IR vs CN-vantage results.
#
# References:
#   - core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
#   - core.telegram.org/mtproto/mtproto-transports#intermediate
#   - alexbers/mtprotoproxy (Python server-side reference)


# Set of 4-byte LE prefixes the obfuscated2 init MUST NOT match (would be
# misinterpreted as HTTP/SOCKS or the protocol-tag values used elsewhere).
_OBF2_FORBIDDEN_FIRST_INTS: frozenset[int] = frozenset(
    {
        0x44414548,  # "HEAD"
        0x54534F50,  # "POST"
        0x20544547,  # "GET "
        0x4954504F,  # "OPTI" (HTTP OPTIONS prefix)
        0xEEEEEEEE,  # intermediate-transport tag (would self-confuse)
        0xDDDDDDDD,  # padded-intermediate tag
        0x02010316,  # MTProto-proxy obfuscation HTTP-disambiguator
    }
)

# Padded-intermediate transport tag: 4 bytes of 0xdd, repeated.
_OBF2_TRANSPORT_TAG_DD: bytes = b"\xdd\xdd\xdd\xdd"

# MTProto TL ids.
_TL_ID_REQ_PQ_MULTI: int = 0xBE7E8EF1
_TL_ID_RES_PQ: int = 0x05162463


def _parse_mtproxy_orig_secret(secret_hex: str) -> bytes | ProbeResult:
    """Parse the 'dd<32-hex>' or bare 32-hex secret into 16 raw bytes.

    Both formats are accepted because the C ``mtproto-proxy`` itself
    treats them interchangeably for key-derivation purposes (the ``dd``
    prefix only signals the chosen MTProto transport, which we encode
    separately into the init frame). Censprobe currently always
    generates the ``dd`` form; bare hex is tolerated for hand-edited
    operator overrides.
    """
    s = secret_hex.lower()
    if s.startswith("dd"):
        s = s[2:]
    try:
        secret_bytes = bytes.fromhex(s)
    except ValueError:
        return _mtg_error_result("orig_secret_not_hex")
    if len(secret_bytes) != 16:
        return _mtg_error_result(f"orig_secret_bad_len={len(secret_bytes)}")
    return secret_bytes


def _build_obfuscated2_init(
    secret_key: bytes,
) -> tuple[bytes, Any, Any]:
    """Build the 64-byte obfuscated2 init frame and AES-CTR cipher pair.

    Returns ``(init_64_bytes, send_cipher, recv_cipher)`` where the
    ciphers are :class:`cryptography.CipherContext` instances already
    advanced past the init keystream — i.e. ``send_cipher.update(payload)``
    yields the ciphertext for the FIRST encrypted byte after init, and
    ``recv_cipher.update(server_bytes)`` yields the corresponding
    plaintext.

    Asymmetric advance: the send cipher is consumed 64 bytes (matching
    the proxy's recv-side keystream that decodes the init's transport
    tag), but the recv cipher is NOT advanced — the proxy's send stream
    starts fresh at counter 0 because there is no server-side init
    handshake to skip past.
    """
    import hashlib
    import secrets as _secrets

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Generate init[0:56] satisfying wire-level constraints. Bytes [56:64]
    # are filled in below with the encrypted transport tag and dc_id.
    while True:
        init_buf = bytearray(_secrets.token_bytes(56))
        if init_buf[0] == 0xEF:
            # 0xef as the very first byte == abridged-transport tag,
            # which would short-circuit some proxy parsers.
            continue
        first4 = int.from_bytes(init_buf[0:4], "little")
        if first4 in _OBF2_FORBIDDEN_FIRST_INTS:
            continue
        if int.from_bytes(init_buf[4:8], "little") == 0:
            # Spec mandates non-zero second int32 — picking a fresh
            # 56-byte random satisfies this with overwhelming probability,
            # but the loop guards the rare zero-draw.
            continue
        break

    # Key derivation: bytes [8:56] feed both directions, with one half
    # reversed for the recv side.
    key_part = bytes(init_buf[8:56])  # 48 bytes
    rev_key_part = key_part[::-1]
    send_key_raw, send_iv = key_part[:32], key_part[32:48]
    recv_key_raw, recv_iv = rev_key_part[:32], rev_key_part[32:48]

    send_key = hashlib.sha256(send_key_raw + secret_key).digest()
    recv_key = hashlib.sha256(recv_key_raw + secret_key).digest()

    send_cipher = Cipher(algorithms.AES(send_key), modes.CTR(send_iv)).encryptor()
    recv_cipher = Cipher(algorithms.AES(recv_key), modes.CTR(recv_iv)).encryptor()

    # Compute the server's recv-direction keystream over the first 64
    # bytes — this is what the proxy will XOR against init bytes to
    # recover the transport tag. We use a one-shot cipher so the real
    # send_cipher above stays available for later .update() calls.
    ks_cipher = Cipher(algorithms.AES(send_key), modes.CTR(send_iv)).encryptor()
    keystream_64 = ks_cipher.update(b"\x00" * 64)

    # Extend init_buf to 64 bytes, then patch positions [56:64]:
    #   [56:60] = transport_tag (0xdddddddd) XOR keystream
    #   [60:62] = dc_id LE int16 (1 = main DC) XOR keystream
    #   [62:64] = filler — random; proxy doesn't validate these.
    init_buf.extend(b"\x00" * 8)
    for i in range(4):
        init_buf[56 + i] = _OBF2_TRANSPORT_TAG_DD[i] ^ keystream_64[56 + i]
    dc_id_bytes = (1).to_bytes(2, "little", signed=True)
    for i in range(2):
        init_buf[60 + i] = dc_id_bytes[i] ^ keystream_64[60 + i]
    filler = _secrets.token_bytes(2)
    init_buf[62] = filler[0]
    init_buf[63] = filler[1]

    # Advance the live send_cipher 64 bytes so subsequent .update() lines
    # up with the proxy's recv counter at byte position 64+. The recv
    # cipher stays at counter=0 because the proxy starts its outbound
    # encrypted stream from there.
    send_cipher.update(b"\x00" * 64)

    return bytes(init_buf), send_cipher, recv_cipher


def _generate_mtproto_msg_id() -> bytes:
    """8-byte little-endian MTProto msg_id (mod-4 == 0 for client→server)."""
    msg_id = int(time.time() * 2**32) & ~0x3
    return msg_id.to_bytes(8, "little")


def _build_req_pq_frame(nonce: bytes, send_cipher: Any) -> bytes:
    """Build & encrypt the padded-intermediate frame carrying req_pq_multi.

    Inner (unencrypted-MTProto) layout:
        auth_key_id (8 bytes, all zeros) ||
        msg_id      (8 bytes) ||
        msg_len     (4 bytes LE = 20) ||
        method_id   (4 bytes LE = 0xbe7e8ef1 req_pq_multi) ||
        nonce       (16 bytes)
    = 40 bytes.

    Padded-intermediate wrapper:
        length     (4 bytes LE = 40 + pad_len) ||
        inner      (40 bytes) ||
        padding    (pad_len bytes random, 0..15)

    Entire wrapper goes through ``send_cipher`` (AES-CTR continuing from
    byte position 64 — see :func:`_build_obfuscated2_init`).
    """
    import secrets as _secrets

    auth_key_id = b"\x00" * 8
    msg_id = _generate_mtproto_msg_id()
    method_id = _TL_ID_REQ_PQ_MULTI.to_bytes(4, "little")
    msg_body = method_id + nonce  # 4 + 16 = 20 bytes
    msg_len_bytes = len(msg_body).to_bytes(4, "little")
    inner = auth_key_id + msg_id + msg_len_bytes + msg_body  # 40 bytes

    pad_len = _secrets.randbelow(16)  # 0..15
    pad = _secrets.token_bytes(pad_len)
    length_bytes = (len(inner) + pad_len).to_bytes(4, "little")
    frame = length_bytes + inner + pad

    return bytes(send_cipher.update(frame))


def _validate_res_pq(body_pt: bytes, expected_nonce: bytes) -> ProbeResult | None:
    """Validate a decrypted padded-intermediate body holds resPQ with our nonce.

    Body layout (after AES-CTR decryption + outer length stripped):
        auth_key_id (8 bytes, must be zero — unencrypted MTProto) ||
        msg_id      (8 bytes, server-chosen, not validated) ||
        msg_len     (4 bytes LE) ||
        msg_body    (msg_len bytes; first 4 are TL ID, next 16 are nonce) ||
        padding     (rest, ignored)

    Returns ``None`` on success, or a populated :class:`ProbeResult`
    with verdict=BLOCKED on any structural / nonce mismatch.
    """
    if len(body_pt) < 24:
        return _mtg_error_result(f"orig_resPQ_truncated={len(body_pt)}", Verdict.BLOCKED)
    auth_key_id = body_pt[0:8]
    if auth_key_id != b"\x00" * 8:
        return _mtg_error_result("orig_resPQ_bad_auth_key_id", Verdict.BLOCKED)
    msg_len = int.from_bytes(body_pt[16:20], "little")
    if msg_len < 20 or 20 + msg_len > len(body_pt):
        return _mtg_error_result(f"orig_resPQ_bad_msg_len={msg_len}", Verdict.BLOCKED)
    msg_body = body_pt[20 : 20 + msg_len]
    tl_id = int.from_bytes(msg_body[0:4], "little")
    if tl_id != _TL_ID_RES_PQ:
        return _mtg_error_result(f"orig_resPQ_bad_tl_id={tl_id:#x}", Verdict.BLOCKED)
    received_nonce = msg_body[4:20]
    if received_nonce != expected_nonce:
        return _mtg_error_result("orig_resPQ_nonce_mismatch", Verdict.BLOCKED)
    return None


class _TlsRecordReader:
    """Streaming demuxer for mtg's faketls server→client direction.

    mtg wraps the proxy's outbound bytes in TLS application_data records
    via ``mtglib/internal/doppel/conn.go::Conn.start``: doppelGanger's
    ``Write`` buffers bytes from the upstream relay, then a goroutine
    chunks them into ApplicationData records with size/delay drawn from
    measured cert-chain noise distribution and writes via
    ``tls.WriteRecordInPlace``. So we can NOT just ``readexactly(N)`` on
    the raw socket and feed it to ``recv_cipher`` — the first 5 bytes
    are the TLS record header, the next ``record_len`` are payload, then
    the next 5 are another header, and so on.

    Verified empirically by pcap capture of an mtg session on 2026-05-10:
    the resPQ response landed as a single 182-byte segment whose first
    five bytes were ``17 03 03 00 b1`` — an ApplicationData record of
    length 0xb1=177, followed by 177 bytes of obfuscated2 ciphertext.

    This reader strips the record framing and exposes a flat inner-byte
    interface to the caller. Records that aren't ApplicationData are
    treated as a protocol error (mtg never sends Handshake/Alert
    records post-WelcomePacket).
    """

    _RECORD_HDR_LEN = 5
    _APP_DATA_TYPE = 0x17

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader
        self._buf = bytearray()

    async def read_inner(self, n: int, timeout: float) -> bytes | ProbeResult:
        """Read exactly ``n`` inner-stream bytes across as many TLS records
        as needed.

        Returns the requested bytes on success, or a populated
        :class:`ProbeResult` describing the failure mode. The error
        string and verdict mirror the raw-read failure modes of the
        non-faketls path so the caller doesn't need to distinguish
        "record framing broke" from "underlying socket broke" — both
        surface as the same probe-layer outcome.
        """
        while len(self._buf) < n:
            try:
                async with asyncio.timeout(timeout):
                    hdr = await self._reader.readexactly(self._RECORD_HDR_LEN)
            except asyncio.IncompleteReadError:
                return _mtg_error_result("orig_resPQ_truncated_len", Verdict.BLOCKED)
            except TimeoutError:
                # Empty buffer + record-header timeout = mtg accepted our
                # obfuscated2 init but no encrypted resPQ ever surfaced.
                # That means: TCP held open, faketls handshake survived,
                # init bytes (which a wrong-secret frame would have RST'd)
                # were accepted — but the L7 resPQ exchange did not
                # complete. Preflight already verified DC reach from the
                # listener host, so a silent stall here is a confirmed
                # L7 block (DPI silent-drop after fingerprinting the
                # obfuscated2 envelope). Verdict is BLOCKED — the
                # protocol cannot move data, the invariant holds.
                # Body-read timeout (buf already has bytes) stays ERROR
                # because mid-stream stall is genuinely ambiguous.
                if not self._buf:
                    return _mtg_error_result("orig_resPQ_len_timeout_post_init", Verdict.BLOCKED)
                return _mtg_error_result("orig_resPQ_body_timeout", Verdict.ERROR)
            if hdr[0] != self._APP_DATA_TYPE:
                return _mtg_error_result(
                    f"orig_resPQ_unexpected_tls_record_type=0x{hdr[0]:02x}",
                    Verdict.BLOCKED,
                )
            record_len = int.from_bytes(hdr[3:5], "big")
            # Bound the per-record allocation so a misbehaving peer (or
            # DPI injection of a fake header advertising 64 KiB) can't
            # wedge the probe forever.
            if record_len <= 0 or record_len > 16384:
                return _mtg_error_result(
                    f"orig_resPQ_bad_tls_record_len={record_len}", Verdict.BLOCKED
                )
            try:
                async with asyncio.timeout(timeout):
                    body = await self._reader.readexactly(record_len)
            except asyncio.IncompleteReadError:
                return _mtg_error_result(
                    f"orig_resPQ_truncated_record_body_expected={record_len}",
                    Verdict.BLOCKED,
                )
            except TimeoutError:
                return _mtg_error_result("orig_resPQ_body_timeout", Verdict.ERROR)
            self._buf.extend(body)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


async def _exchange_obfuscated2_respq(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    secret_key: bytes,
    *,
    wrap_inner_in_tls_record: bool,
) -> ProbeResult | None:
    """Send obfuscated2 init + req_pq_multi over an open TCP stream and
    validate the encrypted resPQ that comes back from the upstream Telegram
    DC, hop-relayed by the proxy.

    Shared by ``probe_mtproto_orig`` (raw obfuscated2 stream — pass
    ``wrap_inner_in_tls_record=False``) and ``probe_mtproto_proxy``
    (post-WelcomePacket — pass ``wrap_inner_in_tls_record=True``).

    The ``wrap_inner_in_tls_record`` flag applies to BOTH directions on
    an mtg connection. Verified against
    ``github.com/9seconds/mtg/mtglib/proxy.go::doFakeTLSHandshake`` (commit
    269852a4):

      * client→server: ``tls.New(ctx.clientConn, true, false)`` — read
        side ON, write side OFF. mtg unwraps TLS application_data
        records sent by the client.
      * server→client: doppelGanger wraps every relayed write in a TLS
        application_data record (see
        ``mtglib/internal/doppel/conn.go``: ``Conn.start`` calls
        ``tls.WriteRecordInPlace`` on every drained chunk). The
        doppelGanger layer is chained AFTER ``tls.New`` and adds its
        own framing, so the bytes on wire from server→client ARE
        TLS-framed even though the ``tls.New`` write side wouldn't
        have added them.

    Returns ``None`` on a fully-validated resPQ exchange. Returns a
    populated :class:`ProbeResult` with verdict already set on any
    failure mode:

      * ``BLOCKED`` for a TCP-layer slam (write fail / FIN-before-len /
        body truncation after a valid length prefix). Each of these
        means a third party severed the connection AFTER we wrote the
        obfuscated init — i.e. observed the L7 content and acted on it.
      * ``BLOCKED`` for a length-read timeout while TCP stays open —
        proxy accepted our init (a wrong-secret frame would have
        RST'd) but no L7 resPQ ever surfaced. Preflight DC-reach has
        already verified the upstream is reachable from the listener,
        so a silent stall is the canonical DPI signature: a confirmed
        block of the protocol's data path.
      * ``ERROR`` for a body-read timeout after we already got a valid
        length — ambiguous mid-stream stall, neither confirmed BLOCK
        nor confirmed reachability. Preserves the strict
        "BLOCKED implies confirmed block" invariant.
    """
    import secrets as _secrets

    init_bytes, send_cipher, recv_cipher = _build_obfuscated2_init(secret_key)
    nonce = _secrets.token_bytes(16)
    req_pq_encrypted = _build_req_pq_frame(nonce, send_cipher)

    inner = init_bytes + req_pq_encrypted
    if wrap_inner_in_tls_record:
        # ApplicationData(0x17) || TLS1.2 version(0x0303) || 2-byte BE length
        # || payload. The init+req_pq is < 200 B in practice, well under
        # the 16 KiB TLS record limit, so a single record fits.
        on_wire = b"\x17\x03\x03" + len(inner).to_bytes(2, "big") + inner
    else:
        on_wire = inner

    writer.write(on_wire)
    try:
        async with asyncio.timeout(5.0):
            await writer.drain()
    except (TimeoutError, ConnectionResetError, BrokenPipeError) as e:
        return _mtg_error_result(f"orig_write_failed:{type(e).__name__}", Verdict.BLOCKED)

    # Read 4 inner bytes (encrypted length prefix). For mtg this requires
    # demuxing TLS records (see ``_TlsRecordReader``); for the original
    # C mtproto-proxy it's a flat ``readexactly(4)`` because there is no
    # faketls layer. Declared above the if so mypy carries the
    # ``_TlsRecordReader | None`` type through to the body-read branch
    # below where ``is not None`` narrows it back.
    tls_reader: _TlsRecordReader | None = None
    if wrap_inner_in_tls_record:
        tls_reader = _TlsRecordReader(reader)
        length_or_err = await tls_reader.read_inner(4, timeout=PROBE_TIMEOUT)
        if isinstance(length_or_err, ProbeResult):
            return length_or_err
        length_ct = length_or_err
    else:
        try:
            async with asyncio.timeout(PROBE_TIMEOUT):
                length_ct = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            return _mtg_error_result("orig_resPQ_truncated_len", Verdict.BLOCKED)
        except TimeoutError:
            # Same reasoning as the faketls path: TCP held open + init
            # accepted (would have RST'd on wrong secret) + zero L7
            # data ⇒ confirmed L7 block of the obfuscated2 protocol.
            # Preflight DC-reach guarantees the upstream isn't the
            # cause. BLOCKED preserves the invariant.
            return _mtg_error_result("orig_resPQ_len_timeout_post_init", Verdict.BLOCKED)

    length_pt = recv_cipher.update(length_ct)
    length = int.from_bytes(length_pt, "little")
    # Sanity bounds: a real resPQ frame is ~92-160 bytes plus 0..15
    # padding; upper bound generously to 4 KiB so a slightly bigger
    # Telegram-side variant doesn't trip false-blocked.
    if length < 24 or length > 4096:
        return _mtg_error_result(f"orig_resPQ_bad_outer_len={length}", Verdict.BLOCKED)

    if tls_reader is not None:
        body_or_err = await tls_reader.read_inner(length, timeout=PROBE_TIMEOUT)
        if isinstance(body_or_err, ProbeResult):
            return body_or_err
        body_ct = body_or_err
    else:
        try:
            async with asyncio.timeout(PROBE_TIMEOUT):
                body_ct = await reader.readexactly(length)
        except asyncio.IncompleteReadError:
            return _mtg_error_result(
                f"orig_resPQ_truncated_body_expected={length}", Verdict.BLOCKED
            )
        except TimeoutError:
            return _mtg_error_result("orig_resPQ_body_timeout", Verdict.ERROR)

    body_pt = recv_cipher.update(body_ct)
    return _validate_res_pq(body_pt, nonce)


@_stamp_elapsed
async def probe_mtproto_orig(host: str, port: int, secret_hex: str) -> ProbeResult:
    """Two-signal probe of the original Telegram MTProxy (C, obfuscated2).

    Sequence: open TCP → send obfuscated2 init + encrypted req_pq_multi
    in one drain → read encrypted resPQ → validate decrypted body has
    our nonce.

    Verdict semantics (see ``_exchange_obfuscated2_respq`` for full
    failure-mode rationale):
        OK              — resPQ validated end-to-end. Proves both
                          "obfuscated2 survives the path" AND "proxy +
                          its upstream Telegram DC are reachable".
        HANDSHAKE_ONLY  — TCP/init accepted, length-read timed out:
                          peer alive, DC-side silent.
        BLOCKED         — any TCP RST / decrypted-frame mismatch.
        ERROR           — body-read timed out mid-stream (ambiguous).
    """
    parsed = _parse_mtproxy_orig_secret(secret_hex)
    if isinstance(parsed, ProbeResult):
        return parsed
    secret_key = parsed

    opened = await _open_mtproto_tcp(host, port)
    if isinstance(opened, ProbeResult):
        return opened
    reader, writer, rtt_ms = opened

    try:
        err = await _exchange_obfuscated2_respq(
            reader, writer, secret_key, wrap_inner_in_tls_record=False
        )
        if err is not None:
            if err.rtt_ms is None:
                err.rtt_ms = rtt_ms
            return err

        # Full resPQ echoed back with our nonce: listener accepted the
        # obfuscated2 init AND its upstream Telegram DC responded with a
        # structurally-valid resPQ keyed to our session. End-to-end
        # MTProto reachability proven — verdict is OK by protocol
        # semantic. ``data_ok`` stays False because there is no sustained
        # data exchange beyond the one-shot resPQ.
        result = ProbeResult()
        result.handshake_ok = True
        result.data_ok = False
        result.rtt_ms = rtt_ms
        result.verdict = Verdict.OK
        return result
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()
