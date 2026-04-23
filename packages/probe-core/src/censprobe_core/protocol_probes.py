"""
protocol_probes.py — Client-side VPN handshake probes using real binaries.

Verdicts:
  OK              — full handshake + data echo succeeded
  HANDSHAKE_ONLY  — handshake succeeded, data echo failed/timeout
  BLOCKED         — connection refused, timeout, or RST
  ERROR           — probe error
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from censprobe_core.models import Verdict

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 10.0


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
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode(errors='replace'), stderr.decode(errors='replace')
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except OSError:
            pass
        return -1, "", "Timeout"


async def ping_echo(ip: str, timeout: float = 3.0) -> bool:
    """Ping a tunnel IP to verify data echo."""
    code, _, _ = await run_cmd(["ping", "-c", "1", "-W", str(int(timeout)), ip], timeout=timeout + 1)
    return code == 0


async def proxy_echo(proxy_port: int, proxy_type: str = "socks5h", timeout: float = 5.0) -> bool:
    """Test proxy using curl to a non-existent internal IP."""
    cmd = [
        "curl", "-s", "--max-time", str(timeout),
        "-x", f"{proxy_type}://127.0.0.1:{proxy_port}",
        "http://10.255.255.1"
    ]
    code, out, err = await run_cmd(cmd, timeout=timeout + 1)
    if code in (52, 56, 97):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# OpenVPN probe
# ─────────────────────────────────────────────────────────────────────────────
async def probe_openvpn(host: str, port: int, psk_b64: str) -> ProbeResult:
    result = ProbeResult()
    with tempfile.TemporaryDirectory(prefix="censprobe_client_ovpn_") as tmpdir:
        tmp_path = Path(tmpdir)
        psk_path = tmp_path / "static.key"
        psk_path.write_bytes(base64.b64decode(psk_b64))
        psk_path.chmod(0o600)
        
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
"""
        conf_path = tmp_path / "client.conf"
        conf_path.write_text(config)

        proc = await asyncio.create_subprocess_exec(
            "openvpn", "--config", str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        try:
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                try:
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                    if not line_bytes:
                        break
                    line = line_bytes.decode(errors='replace')
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
            try:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.poll() is None:
                    proc.kill()
            except OSError:
                pass
            
    return result


# ─────────────────────────────────────────────────────────────────────────────
# WireGuard probe
# ─────────────────────────────────────────────────────────────────────────────
async def probe_wireguard(
    host: str, port: int, server_public: str, client_public: str, preshared: str, private_key: str
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

        # Bring up wg
        code, out, err = await run_cmd(["wg-quick", "up", str(conf_path)])
        if code != 0:
            result.error = f"wg-quick up failed: {err}"
            return result
        
        try:
            # Wait for handshake
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                _, wg_out, _ = await run_cmd(["wg", "show", "censwg1", "latest-handshakes"], timeout=1.0)
                if wg_out and "0" not in wg_out.split()[1:]:
                    hs_ok = True
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
    host: str, port: int, server_public: str, client_public: str, preshared: str, private_key: str,
    jc: int, jmin: int, jmax: int, s1: int, s2: int, h1: int, h2: int, h3: int, h4: int
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

        # Bring up awg
        code, out, err = await run_cmd(["awg-quick", "up", str(conf_path)])
        if code != 0:
            result.error = f"awg-quick up failed: {err}"
            return result
        
        try:
            t0 = time.monotonic()
            hs_ok = False
            while time.monotonic() - t0 < PROBE_TIMEOUT:
                # Some amneziawg-go installations still use wg command to read stats
                _, wg_out, _ = await run_cmd(["wg", "show", "censawg1", "latest-handshakes"], timeout=1.0)
                if wg_out and "0" not in wg_out.split()[1:]:
                    hs_ok = True
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
    result = ProbeResult()
    local_port = random.randint(10000, 60000)
    with tempfile.TemporaryDirectory(prefix="censprobe_client_ss_") as tmpdir:
        tmp_path = Path(tmpdir)
        config = {
            "log": {"level": "info", "output": "stdout", "timestamp": True},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": local_port
                }
            ],
            "outbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "ss-out",
                    "server": host,
                    "server_port": port,
                    "method": method,
                    "password": password_b64
                }
            ]
        }
        conf_path = tmp_path / "config.json"
        conf_path.write_text(json.dumps(config, indent=2))

        proc = await asyncio.create_subprocess_exec(
            "sing-box", "run", "-c", str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        try:
            # wait for sing-box to start
            await asyncio.sleep(1.0)
            if proc.poll() is not None:
                out = await proc.stdout.read()
                result.error = f"sing-box failed to start: {out.decode(errors='replace')}"
                return result

            # proxy_echo attempts curl through the local socks proxy
            # SOCKS5 success -> handshake success -> wait, SS 2022 connects immediately over TCP
            # If server blocks or resets data, curl will return (52,56,97). SOCKS connect will succeed.
            t0 = time.monotonic()
            if await proxy_echo(local_port, "socks5h"):
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = (time.monotonic() - t0) * 1000
            else:
                # In shadowsocks, if proxy fails completely, it might be handshake error or block
                # Let's check sing-box logs to see if handshake worked but data failed
                # This is tricky because SS is connectionless. If DPI drops SS connection, proxy_echo fails.
                # If server auth succeeds but data is blocked by listener route, proxy_echo returns True (because 52/56).
                # So if proxy_echo fails, it means DPI blocked it or timeout!
                pass

        finally:
            try:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.poll() is None:
                    proc.kill()
            except OSError:
                pass
            
    return result


# ─────────────────────────────────────────────────────────────────────────────
# VLESS+Reality probe
# ─────────────────────────────────────────────────────────────────────────────
async def probe_vless_reality(
    host: str, port: int, uuid: str, public_key: str, short_id: str, server_name: str
) -> ProbeResult:
    result = ProbeResult()
    local_port = random.randint(10000, 60000)
    with tempfile.TemporaryDirectory(prefix="censprobe_client_vless_") as tmpdir:
        tmp_path = Path(tmpdir)
        config = {
            "inbounds": [
                {
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True}
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": host,
                            "port": port,
                            "users": [{
                                "id": uuid,
                                "encryption": "none",
                                "flow": "xtls-rprx-vision"
                            }]
                        }]
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
                            "spiderX": ""
                        }
                    }
                }
            ]
        }
        conf_path = tmp_path / "config.json"
        conf_path.write_text(json.dumps(config, indent=2))

        proc = await asyncio.create_subprocess_exec(
            "xray", "run", "-c", str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        try:
            await asyncio.sleep(1.0)
            if proc.poll() is not None:
                out = await proc.stdout.read()
                result.error = f"xray failed to start: {out.decode(errors='replace')}"
                return result

            t0 = time.monotonic()
            if await proxy_echo(local_port, "socks5h"):
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = (time.monotonic() - t0) * 1000
        finally:
            try:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.poll() is None:
                    proc.kill()
            except OSError:
                pass
            
    return result


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
  sni: real.example.com
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
            stderr=asyncio.subprocess.STDOUT
        )
        
        try:
            await asyncio.sleep(1.0)
            if proc.poll() is not None:
                out = await proc.stdout.read()
                result.error = f"hysteria failed to start: {out.decode(errors='replace')}"
                return result

            t0 = time.monotonic()
            if await proxy_echo(local_port, "socks5h"):
                result.handshake_ok = True
                result.data_ok = True
                result.verdict = Verdict.OK
                result.rtt_ms = (time.monotonic() - t0) * 1000
        finally:
            try:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.poll() is None:
                    proc.kill()
            except OSError:
                pass
            
    return result
