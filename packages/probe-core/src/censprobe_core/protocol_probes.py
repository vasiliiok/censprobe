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
import base64
import json
import logging
import random
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from censprobe_core.models import Verdict

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 15.0
# Must match censprobe_listener.echo_server.ECHO_PORTS.
ECHO_PORTS: dict[str, int] = {
    "shadowsocks": 9991,
    "vless_reality": 9992,
    "hysteria2": 9993,
}


@dataclass
class ProbeResult:
    verdict: Verdict = Verdict.BLOCKED
    handshake_ok: bool = False
    data_ok: bool = False
    rtt_ms: Optional[float] = None
    error: Optional[str] = None


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


async def _graceful_terminate(proc: asyncio.subprocess.Process, timeout: float = 0.5) -> None:
    """
    Terminate an asyncio subprocess and reap it.

    asyncio.Process.returncode is only updated once wait() observes exit, so
    a plain `terminate() + sleep + returncode is None` check would always
    end up calling kill() and leave the child as a zombie until wait() runs.
    """
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except (OSError, ProcessLookupError):
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
        return
    except asyncio.TimeoutError:
        pass
    try:
        proc.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        await proc.wait()
    except Exception:
        pass


async def ping_echo(ip: str, timeout: float = 3.0) -> bool:
    """Ping a tunnel IP to verify data echo."""
    code, _, _ = await run_cmd(
        ["ping", "-c", "1", "-W", str(int(timeout)), ip],
        timeout=timeout + 1,
    )
    return code == 0


# ─────────────────────────────────────────────────────────────────────────────
# Proxy-based echo: distinguishes handshake from data-phase.
# Returns: ("ok", rtt_ms)          — data phase OK (curl exit 0, HTTP 200)
#          ("handshake_only", None) — SOCKS connect succeeded but data didn't
#          ("blocked", None)        — handshake failed (SOCKS error / refused)
# ─────────────────────────────────────────────────────────────────────────────
async def proxy_echo(
    proxy_port: int,
    echo_port: int,
    proxy_type: str = "socks5h",
    timeout: float = 5.0,
) -> tuple[str, Optional[float]]:
    t0 = time.monotonic()
    cmd = [
        "curl", "-s", "-o", "/dev/null",
        "--max-time", str(timeout),
        "-w", "%{http_code}",
        "-x", f"{proxy_type}://127.0.0.1:{proxy_port}",
        f"http://127.0.0.1:{echo_port}/ping",
    ]
    code, out, err = await run_cmd(cmd, timeout=timeout + 1)
    rtt = (time.monotonic() - t0) * 1000

    # Success: echo server reached, HTTP 200 returned.
    if code == 0 and out.strip().startswith("2"):
        return "ok", rtt

    # SOCKS/proxy connect failed → handshake did not complete.
    # curl exit codes: 5=resolve, 7=refused, 97=SOCKS general failure.
    if code in (5, 7, 97):
        return "blocked", None

    # Anything else (timeout=28, got_nothing=52, recv_error=56, partial=18, ...):
    # SOCKS handshake plausibly succeeded but tunnel data phase failed.
    return "handshake_only", None


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN probe
# ─────────────────────────────────────────────────────────────────────────────
async def probe_openvpn(host: str, port: int, psk_b64: str) -> ProbeResult:
    result = ProbeResult()
    with tempfile.TemporaryDirectory(prefix="censprobe_client_ovpn_") as tmpdir:
        tmp_path = Path(tmpdir)
        psk_path = tmp_path / "static.key"
        try:
            psk_path.write_bytes(base64.b64decode(psk_b64))
        except Exception as e:
            result.error = f"bad PSK: {e}"
            return result
        psk_path.chmod(0o600)

        # Server side uses ifconfig 10.200.0.1 10.200.0.2 → client mirrors.
        config = f"""
proto udp
remote {host} {port}
dev tun
secret {psk_path}
ifconfig 10.200.0.2 10.200.0.1
keepalive 10 60
cipher AES-256-GCM
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
                result.verdict = Verdict.HANDSHAKE_ONLY
                if await ping_echo("10.200.0.1"):
                    result.data_ok = True
                    result.verdict = Verdict.OK
        finally:
            await _graceful_terminate(proc)

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
        config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.200.0.2/24

[Peer]
PublicKey = {server_public}
PresharedKey = {preshared}
Endpoint = {host}:{port}
AllowedIPs = 10.200.0.1/32
PersistentKeepalive = 25
"""
        conf_path = tmp_path / "censwg1.conf"
        conf_path.write_text(config)

        code, _, err = await run_cmd(["wg-quick", "up", str(conf_path)])
        if code != 0:
            result.error = f"wg-quick up failed: {err}"
            return result

        try:
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                _, wg_out, _ = await run_cmd(
                    ["wg", "show", "censwg1", "latest-handshakes"],
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
                if await ping_echo("10.200.0.1"):
                    result.data_ok = True
                    result.verdict = Verdict.OK
        finally:
            await run_cmd(["wg-quick", "down", str(conf_path)])

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
        conf_path = tmp_path / "censawg1.conf"
        conf_path.write_text(config)

        code, _, err = await run_cmd(["awg-quick", "up", str(conf_path)])
        if code != 0:
            result.error = f"awg-quick up failed: {err}"
            return result

        try:
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                _, wg_out, _ = await run_cmd(
                    ["wg", "show", "censawg1", "latest-handshakes"],
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
            await run_cmd(["awg-quick", "down", str(conf_path)])

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
    local_port = random.randint(10000, 60000)
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

        try:
            await asyncio.sleep(1.0)
            if proc.returncode is not None:
                out = await proc.stdout.read()
                result.error = f"hysteria failed to start: {out.decode(errors='replace')}"
                return result

            status, rtt = await proxy_echo(local_port, ECHO_PORTS["hysteria2"], "socks5h")
            if status == "ok":
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = rtt
            elif status == "handshake_only":
                result.handshake_ok = True
                result.verdict = Verdict.HANDSHAKE_ONLY
            else:
                result.verdict = Verdict.BLOCKED
        finally:
            await _graceful_terminate(proc)

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
    local_port = random.randint(10000, 60000)
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

        try:
            await asyncio.sleep(1.0)
            if proc.returncode is not None:
                out = await proc.stdout.read()
                result.error = f"{cmd[0]} failed to start: {out.decode(errors='replace')}"
                return result

            status, rtt = await proxy_echo(local_port, ECHO_PORTS[proto_label], "socks5h")
            if status == "ok":
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = rtt
            elif status == "handshake_only":
                result.handshake_ok = True
                result.verdict = Verdict.HANDSHAKE_ONLY
            else:
                result.verdict = Verdict.BLOCKED
        finally:
            await _graceful_terminate(proc)

    return result
