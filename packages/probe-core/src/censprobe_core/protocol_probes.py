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
import json
import logging
import socket
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from censprobe_core.echo_ports import ECHO_PORTS
from censprobe_core.link_utils import async_delete_iface, async_rm_amneziawg_socket
from censprobe_core.models import Verdict
from censprobe_core.utils import graceful_terminate

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 15.0

# Re-exported so existing callers that did `from
# censprobe_core.protocol_probes import ECHO_PORTS` keep working — the
# canonical home is censprobe_core.echo_ports.
__all__ = [
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
    rtt_ms: float | None = None
    error: str | None = None
    # Sustained-data signal — populated only for SS / VLESS / Hy2 (the
    # three SOCKS-routed protocols that go through the listener echo
    # server). OpenVPN / WG / AmneziaWG keep `None` because their
    # data-phase verification is a single ping, not a bulk download.
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
        # proc.returncode is set after communicate() completes; assert for mypy.
        assert proc.returncode is not None
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

    async def _drain() -> None:
        assert proc.stdout is not None
        try:
            while True:
                chunk = await proc.stdout.read(4096)
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


async def ping_echo(ip: str, timeout: float = 3.0, count: int = 3, min_received: int = 2) -> bool:
    """Ping a tunnel IP and verify the peer actually replies.

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
    """
    deadline = max(int(timeout), 1)
    code, out, _ = await run_cmd(
        ["ping", "-c", str(count), "-W", str(deadline), "-i", "0.3", ip],
        # Worst case: count * deadline (pings can stall up to deadline each).
        timeout=count * deadline + 2,
    )
    if code != 0:
        return False
    # iputils-ping summary line:
    #   "<count> packets transmitted, <received> received, 0% packet loss, ..."
    # Exit code 0 means ≥1 reply received, but we need a stricter
    # threshold to filter the single-shot quirk above.
    received = 0
    for line in out.splitlines():
        stripped = line.strip()
        if "packets transmitted" in stripped and " received" in stripped:
            parts = stripped.split(",")
            if len(parts) >= 2:
                tokens = parts[1].strip().split()
                if tokens and tokens[0].isdigit():
                    received = int(tokens[0])
                    break
    return received >= min_received


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
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5
            )
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
        "/dev/null",
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
        "/dev/null",
        "--max-time",
        str(n_timeout),
        # %{exitcode}: curl's own exit; %{speed_download}: bytes/sec
        # (curl's already-averaged rate over the whole transfer);
        # %{size_download}: total bytes received — used to ignore
        # partial transfers that the tunnel cut short.
        "-w",
        "%{exitcode} %{speed_download} %{size_download}",
        "-x",
        f"socks5h://127.0.0.1:{proxy_port}",
        f"http://127.0.0.1:{echo_port}/throughput?bytes={n_bytes}",
    ]
    code, out, _err = await run_cmd(cmd, timeout=n_timeout + 2)
    parts = out.strip().split()
    if len(parts) < 3:
        return None, False
    try:
        exit_code = int(parts[0])
        speed_bps = float(parts[1])
        size = int(parts[2])
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

    return (speed_bps * 8) / 1_000_000, False


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN probe
# ─────────────────────────────────────────────────────────────────────────────
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
        psk_path.write_text(psk_pem, encoding="utf-8")
        psk_path.chmod(0o600)

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

        try:
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                try:
                    assert proc.stdout is not None
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
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
                    if await ping_echo("10.200.0.1"):
                        result.data_ok = True
                        result.verdict = Verdict.OK
                finally:
                    await _stop_log_drain(drain_task)
        finally:
            await graceful_terminate(proc)
            # Belt-and-braces: openvpn normally tears down its own tun on
            # exit, but if it was SIGKILLed the device leaks.
            await async_delete_iface(_OVPN_CLI_IFACE)

    return result


async def _poll_wg_handshake(tool: str, iface: str, timeout: float) -> tuple[bool, float | None]:
    """Poll ``<tool> show <iface> latest-handshakes`` until a non-zero
    timestamp appears (peer replied) or ``timeout`` elapses.

    Shared by ``probe_wireguard`` (``tool="wg"``) and ``probe_amneziawg``
    (``tool="awg"``) — extracting the loop keeps each probe under
    Sonar S3776's cognitive-complexity ceiling and removes the prior
    near-duplicate code blocks.

    Returns ``(hs_ok, rtt_ms)``. ``rtt_ms`` is ``None`` when the loop
    times out without a handshake — callers leave ``result.rtt_ms``
    at its default in that case.
    """
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        _, out, _ = await run_cmd([tool, "show", iface, "latest-handshakes"], timeout=1.0)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "0":
                return True, (time.monotonic() - t0) * 1000
        await asyncio.sleep(0.5)
    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard probe
# ─────────────────────────────────────────────────────────────────────────────
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
        conf_path.write_text(config)

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
            hs_ok, rtt_ms = await _poll_wg_handshake("wg", _WG_CLI_IFACE, PROBE_TIMEOUT)
            if rtt_ms is not None:
                result.rtt_ms = rtt_ms

            result.handshake_ok = hs_ok
            if hs_ok:
                result.verdict = Verdict.HANDSHAKE_ONLY
                # Two independent signals required for OK: ping_echo
                # (≥2/3 ICMP echoes return) AND ``wg show transfer``
                # (rx_bytes > 0). The second guards against Windows
                # Docker Desktop ``network_mode: host`` spoofing ICMP
                # replies — see _wg_peer_rx_bytes docstring.
                if await ping_echo("10.202.0.1"):
                    rx = await _wg_peer_rx_bytes("wg", _WG_CLI_IFACE)
                    if rx > 0:
                        result.data_ok = True
                        result.verdict = Verdict.OK
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
        conf_path.write_text(config)

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
            hs_ok, rtt_ms = await _poll_wg_handshake("awg", _AWG_CLI_IFACE, PROBE_TIMEOUT)
            if rtt_ms is not None:
                result.rtt_ms = rtt_ms

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
                if await ping_echo("10.201.0.1"):
                    rx = await _wg_peer_rx_bytes("awg", _AWG_CLI_IFACE)
                    if rx > 0:
                        result.data_ok = True
                        result.verdict = Verdict.OK
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
        conf_path.write_text(config)

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
        conf_path.write_text(json.dumps(config_builder(local_port), indent=2))
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
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=PROBE_TIMEOUT,
        )
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
        await asyncio.wait_for(writer.drain(), timeout=5.0)
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
        header = await asyncio.wait_for(reader.readexactly(5), timeout=5.0)
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
        body = await asyncio.wait_for(reader.readexactly(record_len), timeout=5.0)
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


async def probe_mtproto_proxy(host: str, port: int, secret_hex: str) -> ProbeResult:
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

        # Handshake validated by HMAC: peer holds the same ee-secret
        # (i.e. it really is mtg, not a domain-fronting fallback nor a
        # captive-portal MitM). Censprobe does not exercise the data
        # plane — that would require a real Telegram DC dial-out — so
        # the verdict is HANDSHAKE_ONLY. Scoring weighs this strictly
        # less than full OK.
        result = ProbeResult()
        result.handshake_ok = True
        result.data_ok = False
        result.rtt_ms = rtt_ms
        result.verdict = Verdict.HANDSHAKE_ONLY
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
# Verdict on success: ``HANDSHAKE_ONLY`` (matches the mtg fakeTLS probe
# semantics — no sustained data plane test).
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


async def probe_mtproto_orig(host: str, port: int, secret_hex: str) -> ProbeResult:
    """Two-signal probe of the original Telegram MTProxy (C, obfuscated2).

    Sequence:
        1. Open TCP.
        2. Build obfuscated2 init + AES-CTR pair from the secret.
        3. Build encrypted req_pq_multi padded-intermediate frame.
        4. Send (init || encrypted_req_pq) in one drain.
        5. Read 4-byte LE encrypted length, decrypt, sanity-check.
        6. Read ``length`` encrypted body bytes, decrypt.
        7. Validate decrypted body matches resPQ with our nonce.

    Verdicts:
        OK signal:        not produced — censprobe never exercises the
                          full MTProto auth-key flow.
        HANDSHAKE_ONLY:   resPQ validated end-to-end. Proves both
                          "obfuscated2 survives the path" AND "proxy +
                          its upstream Telegram DC are reachable".
        BLOCKED:          any TCP RST / timeout / decrypted-frame
                          mismatch. The error string distinguishes
                          init-side failures (TCP layer) from
                          resPQ-side failures (TL parsing) for triage.
    """
    import secrets as _secrets

    parsed = _parse_mtproxy_orig_secret(secret_hex)
    if isinstance(parsed, ProbeResult):
        return parsed
    secret_key = parsed

    init_bytes, send_cipher, recv_cipher = _build_obfuscated2_init(secret_key)
    nonce = _secrets.token_bytes(16)
    req_pq_encrypted = _build_req_pq_frame(nonce, send_cipher)

    opened = await _open_mtproto_tcp(host, port)
    if isinstance(opened, ProbeResult):
        return opened
    reader, writer, rtt_ms = opened

    try:
        writer.write(init_bytes + req_pq_encrypted)
        try:
            await asyncio.wait_for(writer.drain(), timeout=5.0)
        except (TimeoutError, ConnectionResetError, BrokenPipeError) as e:
            # Write failed = TCP-level slam during send. That's a real
            # network-side block (RST mid-stream / FIN), not a server-side
            # ambiguity, so BLOCKED stands.
            return _mtg_error_result(f"orig_write_failed:{type(e).__name__}", Verdict.BLOCKED)

        # Length prefix (4 bytes encrypted).
        try:
            length_ct = await asyncio.wait_for(reader.readexactly(4), timeout=PROBE_TIMEOUT)
        except asyncio.IncompleteReadError:
            # FIN/RST after write = peer accepted our bytes then severed.
            # Could be DPI cutting after L7 inspection or the proxy
            # rejecting init silently — both look like blocking.
            return _mtg_error_result("orig_resPQ_truncated_len", Verdict.BLOCKED)
        except TimeoutError:
            # mtproto-proxy is silent-by-design until upstream Telegram
            # DC replies with resPQ — verified 2026-05 via tcpdump+strace
            # (zero accept4 syscalls during the probe window, zero reply
            # bytes for valid AND deliberately invalid inits). So
            # "no bytes in PROBE_TIMEOUT" can mean DPI blackholed us OR
            # Telegram DC won't talk to the listener vantage (datacenter
            # anti-abuse, e.g. GCP egress to 149.154.175.50:8888 silently
            # ignored). Collapsing both into BLOCKED would violate the
            # "BLOCKED == confirmed block" invariant — surface as ERROR.
            return _mtg_error_result("orig_resPQ_len_timeout", Verdict.ERROR)

        length_pt = recv_cipher.update(length_ct)
        length = int.from_bytes(length_pt, "little")
        # Sanity bounds: a real resPQ frame is ~92-160 bytes plus 0..15
        # padding; pad upper bound generously to ~4 KiB so a slightly
        # bigger Telegram-side variant doesn't trip false-blocked.
        if length < 24 or length > 4096:
            return _mtg_error_result(f"orig_resPQ_bad_outer_len={length}", Verdict.BLOCKED)

        try:
            body_ct = await asyncio.wait_for(reader.readexactly(length), timeout=PROBE_TIMEOUT)
        except asyncio.IncompleteReadError:
            # Body truncation after we already received a valid 4-byte
            # length prefix means the server WAS responding then severed.
            # That's a real block.
            return _mtg_error_result(
                f"orig_resPQ_truncated_body_expected={length}", Verdict.BLOCKED
            )
        except TimeoutError:
            # Same ambiguity reasoning as the length-read timeout above —
            # we already saw a length prefix, but if the body never
            # arrives the silence could be DPI mid-stream OR a stalled
            # upstream DC. ERROR rather than BLOCKED preserves the
            # "BLOCKED implies confirmed block" invariant.
            return _mtg_error_result("orig_resPQ_body_timeout", Verdict.ERROR)

        body_pt = recv_cipher.update(body_ct)

        validation_err = _validate_res_pq(body_pt, nonce)
        if validation_err is not None:
            return validation_err

        result = ProbeResult()
        result.handshake_ok = True
        result.data_ok = False
        result.rtt_ms = rtt_ms
        result.verdict = Verdict.HANDSHAKE_ONLY
        return result
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()
