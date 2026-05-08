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
    # sing-box / xray / hysteria2 success markers when a remote tunnel
    # session has actually been established. If none of these show up
    # in the tunnel's stdout by the time proxy_echo completed, a curl
    # timeout means the upstream handshake never finished — not a
    # "handshake_only" (reachable) state.
    "inbound connection",
    "connection established",
    "handshake complete",
    "tunnel established",
    "authenticated",
    "accepted tcp:",
    "started listen",
    "client connected",
    "server connected",
    "reality: ",
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
    actually reflects a completed upstream handshake. If no success marker
    appeared in the logs, downgrade to BLOCKED.

    Accepts statuses: "ok", "blocked", "inconclusive" (legacy alias
    "handshake_only" from older callers also tolerated).
    """
    if status == "ok":
        return True, False
    if status == "blocked":
        return False, False

    # status == "inconclusive" (or legacy "handshake_only") — inspect logs.
    low = log_text.lower()
    saw_success = any(tok in low for tok in _HS_SUCCESS_TOKENS)
    saw_failure = any(tok in low for tok in _HS_FAILURE_TOKENS)
    if saw_success and not saw_failure:
        return True, True
    # No positive signal → treat as BLOCKED. This corrects the previous
    # bias of calling any curl timeout "handshake_only" even when the
    # outer tunnel never came up.
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
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                _, wg_out, _ = await run_cmd(
                    ["wg", "show", _WG_CLI_IFACE, "latest-handshakes"],
                    timeout=1.0,
                )
                for line in wg_out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] != "0":
                        hs_ok = True
                        break
                if hs_ok:
                    result.rtt_ms = (time.monotonic() - t0) * 1000
                    break
                await asyncio.sleep(0.5)

            result.handshake_ok = hs_ok
            if hs_ok:
                result.verdict = Verdict.HANDSHAKE_ONLY
                if await ping_echo("10.202.0.1"):
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
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                # Must use `awg` (not `wg`) — amneziawg-go is a userspace
                # implementation whose socket lives in /var/run/amneziawg/,
                # which vanilla `wg` does not look at and silently fails on.
                # Without this, hs_ok would always stay False, the data-phase
                # ping never fires, and the probe wrongly reports BLOCKED
                # while the listener side reports HANDSHAKE_ONLY (because
                # awg-quick already pushed an initiation on bring-up).
                _, wg_out, _ = await run_cmd(
                    ["awg", "show", _AWG_CLI_IFACE, "latest-handshakes"],
                    timeout=1.0,
                )
                for line in wg_out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] != "0":
                        hs_ok = True
                        break
                if hs_ok:
                    result.rtt_ms = (time.monotonic() - t0) * 1000
                    break
                await asyncio.sleep(0.5)

            result.handshake_ok = hs_ok
            if hs_ok:
                result.verdict = Verdict.HANDSHAKE_ONLY
                if await ping_echo("10.201.0.1"):
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
    expected_types = (0x16, 0x14, 0x17)
    max_total = 16 * 1024
    for idx, expected_type in enumerate(expected_types):
        try:
            header = await asyncio.wait_for(reader.readexactly(5), timeout=5.0)
        except asyncio.IncompleteReadError:
            return _mtg_error_result(f"welcome_truncated_record{idx}", Verdict.BLOCKED)
        except TimeoutError:
            return _mtg_error_result(f"welcome_read_timeout_record{idx}", Verdict.BLOCKED)
        if header[0] != expected_type:
            return _mtg_error_result(
                f"welcome_bad_type_record{idx}={header[0]:#x}", Verdict.BLOCKED
            )
        if header[1:3] != b"\x03\x03":
            return _mtg_error_result(f"welcome_bad_version_record{idx}", Verdict.BLOCKED)
        record_len = int.from_bytes(header[3:5], "big")
        if record_len == 0:
            return _mtg_error_result(f"welcome_zero_len_record{idx}", Verdict.BLOCKED)
        if len(packet) + 5 + record_len > max_total:
            return _mtg_error_result(f"welcome_oversize_record{idx}={record_len}", Verdict.BLOCKED)
        try:
            body = await asyncio.wait_for(reader.readexactly(record_len), timeout=5.0)
        except asyncio.IncompleteReadError:
            return _mtg_error_result(f"welcome_short_body_record{idx}", Verdict.BLOCKED)
        except TimeoutError:
            return _mtg_error_result(f"welcome_read_timeout_body_record{idx}", Verdict.BLOCKED)
        packet += header + body
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
