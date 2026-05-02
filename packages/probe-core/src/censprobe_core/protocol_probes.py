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
import json
import logging
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from censprobe_core.echo_ports import ECHO_PORTS
from censprobe_core.link_utils import async_delete_iface, async_rm_amneziawg_socket
from censprobe_core.models import Verdict
from censprobe_core.utils import graceful_terminate

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 15.0

# Throughput probe parameters. The server-side echo endpoint streams
# this many zero bytes back through the tunnel; the client measures
# end-to-end time via curl's `--write-out %{speed_download}`. 1 MiB is
# small enough that even a heavily-throttled link (~270 kbps) finishes
# inside the timeout, but large enough that fast networks register a
# meaningful number rather than sub-millisecond noise. Tuning these
# changes the floor of what we call "throttled" — see the THROTTLED
# flag handling in proxy_throughput.
THROUGHPUT_BYTES = 1 * 1024 * 1024
THROUGHPUT_TIMEOUT_SEC = 30.0

# Re-exported so existing callers that did `from
# censprobe_core.protocol_probes import ECHO_PORTS` keep working — the
# canonical home is censprobe_core.echo_ports.
__all__ = [
    "ECHO_PORTS",
    "PROBE_TIMEOUT",
    "ProbeResult",
    "probe_amneziawg",
    "probe_hysteria2",
    "probe_openvpn",
    "probe_shadowsocks",
    "probe_vless_reality",
    "probe_wireguard",
    "ping_echo",
    "proxy_echo",
]

# Deterministic interface names so a crashed run leaves something we can
# proactively clean up (otherwise a stale tun/wg device keeps holding the
# tunnel-IP route and silently blackholes the next probe).
_OVPN_CLI_IFACE = "censovpn1"
_WG_CLI_IFACE = "censwg1"
_AWG_CLI_IFACE = "censawg1"


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
    # ``THROUGHPUT_TIMEOUT_SEC``. That's a strong indication the data
    # plane is heavily throttled — but it can also fire on a server with
    # < 270 kbps uplink, so the flag is informational, not a verdict.
    throughput_throttled: bool = False


async def run_cmd(cmd: list[str], timeout: float = PROBE_TIMEOUT) -> tuple[int, str, str]:
    """Run a command with timeout and return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except OSError:
            pass
        # Reap the process so it doesn't linger as a zombie.
        try:
            await proc.wait()
        except Exception:
            pass
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


async def _start_log_drain(
    proc: asyncio.subprocess.Process,
    buf: bytearray,
    max_bytes: int = 65536,
) -> asyncio.Task | None:
    """Drain proc.stdout continuously so the child never blocks on a full pipe.

    Linux pipes are ~64 KiB. If the tunnel binary (sing-box / xray /
    hysteria) logs more than that while proxy_echo is still running and
    nothing is reading, the child's next write() stalls and the whole
    tunnel freezes — proxy_echo then times out and we wrongly report
    "blocked". The drain task reads continuously into an in-memory buffer
    (bounded so a chatty binary doesn't eat RAM); after proxy_echo
    returns we decode the buffer for handshake-success classification.
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


async def _stop_log_drain(task: asyncio.Task | None) -> None:
    if task is None or task.done():
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


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


async def ping_echo(ip: str, timeout: float = 3.0) -> bool:
    """Ping a tunnel IP to verify data echo."""
    code, _, _ = await run_cmd(
        ["ping", "-c", "1", "-W", str(int(timeout)), ip],
        timeout=timeout + 1,
    )
    return code == 0


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
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
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
        return s.getsockname()[1]
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
        "curl", "-s", "-o", "/dev/null",
        "--max-time", str(timeout),
        "-w", "%{http_code}",
        "-x", f"{proxy_type}://127.0.0.1:{proxy_port}",
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
#              tunnel could not deliver THROUGHPUT_BYTES inside the
#              window. Caller surfaces this as a flag, not a verdict.
# ─────────────────────────────────────────────────────────────────────────────
async def proxy_throughput(
    proxy_port: int,
    echo_port: int,
    target_bytes: int = THROUGHPUT_BYTES,
    timeout: float = THROUGHPUT_TIMEOUT_SEC,
) -> tuple[float | None, bool]:
    """Download ``target_bytes`` from the listener echo via the local SOCKS proxy.

    The numeric result is informational and intentionally not consumed
    by scoring — narrow server uplink would otherwise look like
    censorship. Caller is expected to print the value in the CLI / pass
    it through into the report and let the dashboard show it as a
    side channel.
    """
    cmd = [
        "curl", "-s", "-o", "/dev/null",
        "--max-time", str(timeout),
        # %{exitcode}: curl's own exit; %{speed_download}: bytes/sec
        # (curl's already-averaged rate over the whole transfer);
        # %{size_download}: total bytes received — used to ignore
        # partial transfers that the tunnel cut short.
        "-w", "%{exitcode} %{speed_download} %{size_download}",
        "-x", f"socks5h://127.0.0.1:{proxy_port}",
        f"http://127.0.0.1:{echo_port}/throughput?bytes={target_bytes}",
    ]
    code, out, _err = await run_cmd(cmd, timeout=timeout + 2)
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
            "openvpn", "--config", str(conf_path),
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
                except asyncio.TimeoutError:
                    continue

            result.handshake_ok = hs_ok
            if hs_ok:
                # Once handshake is done, openvpn keeps logging. Drain stdout
                # in the background so verb-1 status pings don't fill the
                # pipe and stall the tunnel during ping_echo.
                drain_buf = bytearray()
                drain_task = await _start_log_drain(proc, drain_buf)
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
    client_public: str,
    preshared: str,
    private_key: str,
) -> ProbeResult:
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
    client_public: str,
    preshared: str,
    private_key: str,
    jc: int, jmin: int, jmax: int, s1: int, s2: int,
    h1: int, h2: int, h3: int, h4: int,
) -> ProbeResult:
    result = ProbeResult()
    if not private_key:
        result.error = "Missing client private key"
        return result

    with tempfile.TemporaryDirectory(prefix="censprobe_client_awg_") as tmpdir:
        tmp_path = Path(tmpdir)
        config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.201.0.2/24
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}

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
            "inbounds": [{
                "type": "socks", "tag": "socks-in",
                "listen": "127.0.0.1", "listen_port": local_port,
            }],
            "outbounds": [{
                "type": "shadowsocks", "tag": "ss-out",
                "server": host, "server_port": port,
                "method": method, "password": password_b64,
            }],
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
            "inbounds": [{
                "port": local_port, "listen": "127.0.0.1",
                "protocol": "socks", "settings": {"udp": True},
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": host, "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": "xtls-rprx-vision",
                    }],
                }]},
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
            }],
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
            "hysteria", "client", "-c", str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        log_buf = bytearray()
        drain_task = await _start_log_drain(proc, log_buf)
        try:
            # Wait until hysteria actually binds its local SOCKS port
            # (or until it gives up). Replaces a fixed `sleep(1.0)` that
            # raced the probe on slow boxes.
            socks_ready = await _wait_port_listening(local_port, timeout=PROBE_TIMEOUT)
            if proc.returncode is not None:
                await _stop_log_drain(drain_task)
                result.error = (
                    f"hysteria failed to start: "
                    f"{bytes(log_buf).decode(errors='replace')}"
                )
                return result

            status, rtt = await proxy_echo(
                local_port, ECHO_PORTS["hysteria2"], "socks5h",
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
                    local_port, ECHO_PORTS["hysteria2"],
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
async def _tunnel_via_singbox_or_xray(
    binary_cmd: list[str],
    proto_label: str,
    config_builder,
) -> ProbeResult:
    result = ProbeResult()
    local_port = _pick_free_local_port()
    with tempfile.TemporaryDirectory(prefix=f"censprobe_client_{proto_label}_") as tmpdir:
        tmp_path = Path(tmpdir)
        conf_path = tmp_path / "config.json"
        conf_path.write_text(json.dumps(config_builder(local_port), indent=2))

        # Substitute conf path into the command template.
        cmd = [c.format(conf=str(conf_path)) for c in binary_cmd]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        log_buf = bytearray()
        drain_task = await _start_log_drain(proc, log_buf)
        try:
            # Poll for the local SOCKS port instead of a fixed sleep — on
            # slow VPS hardware sing-box/xray can take >1 s to bind, and
            # an early curl returns ECONNREFUSED, which we'd previously
            # mis-classify as BLOCKED.
            socks_ready = await _wait_port_listening(local_port, timeout=PROBE_TIMEOUT)
            if proc.returncode is not None:
                await _stop_log_drain(drain_task)
                result.error = (
                    f"{cmd[0]} failed to start: "
                    f"{bytes(log_buf).decode(errors='replace')}"
                )
                return result

            status, rtt = await proxy_echo(
                local_port, ECHO_PORTS[proto_label], "socks5h",
                socks_ready=socks_ready,
            )
            log_text = bytes(log_buf).decode("utf-8", errors="replace")
            hs_ok, is_hs_only = _classify_proxy_outcome(status, log_text)
            if status == "ok":
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = rtt
                # Same informational throughput follow-up as in
                # probe_hysteria2; the value is surfaced in the CLI and
                # dashboard but never modifies the verdict.
                mbps, throttled = await proxy_throughput(
                    local_port, ECHO_PORTS[proto_label],
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
