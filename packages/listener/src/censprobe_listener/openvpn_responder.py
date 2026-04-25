"""
openvpn_responder.py — OpenVPN static-key test responder.

Runs openvpn in static-key (p2p) mode.
Listens on UDP/<port>, accepts connection, records events.
Does NOT forward traffic — purely a measurement endpoint.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Deterministic tun name so we can scrub a stale interface left behind by
# a SIGKILL — without this, a leftover tun keeps the 10.200.0.x peer route
# alive in host netns and silently blackholes the next session.
_OVPN_SRV_IFACE = "censovpn0"


class OpenVPNResponder:
    """
    Wraps openvpn process in static-key p2p mode.
    Client connects, OpenVPN establishes tunnel, client can ping the server IP
    through the tunnel — kernel replies to ICMP on its own tun IP, which we
    observe as "TCP/UDP read bytes" > 0 in status file.
    """

    def __init__(self, psk_pem: str, port: int = 1194) -> None:
        self.psk_pem = psk_pem
        self.port = port
        self._proc: subprocess.Popen | None = None
        self._config_dir: tempfile.TemporaryDirectory | None = None
        self._status_path: Path | None = None
        # Cached snapshot of connection/transfer state captured before teardown.
        self._final_handshake_count: int = 0
        self._final_bytes_received: int = 0

    async def start(self) -> None:
        """Write config files and launch openvpn subprocess."""
        self._config_dir = tempfile.TemporaryDirectory(prefix="censprobe_ovpn_")
        tmpdir = Path(self._config_dir.name)

        # Write PSK file in OpenVPN "Static key V1" PEM format.
        psk_path = tmpdir / "static.key"
        psk_path.write_text(self.psk_pem, encoding="utf-8")
        psk_path.chmod(0o600)

        # Status/log files colocated with config (never shared across instances).
        self._status_path = tmpdir / "status.log"
        log_path = tmpdir / "openvpn.log"

        # Pre-clean any leftover tun device from a crashed previous run —
        # `dev <name>` makes OpenVPN refuse to start if the interface is
        # already present, so we must drop it first.
        await asyncio.get_running_loop().run_in_executor(None, _delete_iface, _OVPN_SRV_IFACE)

        # AEAD ciphers (GCM / ChaCha20-Poly1305) require TLS mode; in
        # static-key / `secret` mode OpenVPN 2.4+ refuses them with
        # "AEAD cipher options --cipher is not allowed in --secret mode".
        # Use AES-256-CBC instead — the only realistic option for p2p PSK.
        config = f"""
proto udp
port {self.port}
dev {_OVPN_SRV_IFACE}
dev-type tun
secret {psk_path}
ifconfig 10.200.0.1 10.200.0.2
keepalive 10 60
cipher AES-256-CBC
persist-key
persist-tun
status {self._status_path} 5
log-append {log_path}
verb 1
"""
        conf_path = tmpdir / "server.conf"
        conf_path.write_text(config)

        loop = asyncio.get_running_loop()
        self._proc = await loop.run_in_executor(
            None,
            lambda: subprocess.Popen(
                ["openvpn", "--config", str(conf_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ),
        )
        # Give it a moment to start
        await asyncio.sleep(1.0)
        if self._proc.poll() is not None:
            tail = log_path.read_text(errors="replace") if log_path.exists() else "<no log>"
            raise RuntimeError(f"OpenVPN failed to start:\n{tail[-2000:]}")
        logger.info("OpenVPN responder started on UDP/%d (iface: %s)", self.port, _OVPN_SRV_IFACE)

    def _read_status(self) -> tuple[int, int]:
        """Parse status file → (handshake_count_approx, bytes_received)."""
        if not self._status_path or not self._status_path.exists():
            return 0, 0
        try:
            content = self._status_path.read_text(errors="replace")
            bytes_read = 0
            for line in content.splitlines():
                if "TCP/UDP read bytes" in line:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        try:
                            bytes_read = int(parts[1].strip())
                        except ValueError:
                            pass
            handshake = 1 if bytes_read > 0 else 0
            return handshake, bytes_read
        except Exception:
            return 0, 0

    async def stop(self) -> None:
        """Capture final state, then terminate openvpn and cleanup."""
        # Capture status BEFORE teardown so data_transfer_ok is observable.
        self._final_handshake_count, self._final_bytes_received = self._read_status()

        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.sleep(0.5)
                if self._proc.poll() is None:
                    self._proc.kill()
                # Wait so the process is reaped — otherwise it lingers as a
                # zombie until our own exit.
                try:
                    await asyncio.get_running_loop().run_in_executor(
                        None, self._proc.wait
                    )
                except Exception:
                    pass
            except Exception as e:
                logger.warning("OpenVPN stop error: %s", e)
            self._proc = None

        # Belt-and-braces tun removal: openvpn normally cleans up its own
        # tun on graceful exit, but if we had to SIGKILL it the device
        # leaks and would block the next start().
        await asyncio.get_running_loop().run_in_executor(
            None, _delete_iface, _OVPN_SRV_IFACE
        )

        if self._config_dir:
            try:
                self._config_dir.cleanup()
            except Exception:
                pass
            self._config_dir = None

        logger.info(
            "OpenVPN responder stopped (handshakes: %d, bytes: %d)",
            self._final_handshake_count,
            self._final_bytes_received,
        )

    @property
    def connection_count(self) -> int:
        """Handshake count snapshot (falls back to live read while running)."""
        if self._final_handshake_count:
            return self._final_handshake_count
        hs, _ = self._read_status()
        return hs

    @property
    def data_transfer_ok(self) -> bool:
        """Data traversed the tunnel if we observed read bytes > a small threshold."""
        if self._final_bytes_received:
            return self._final_bytes_received > 64  # above handshake noise
        _, b = self._read_status()
        return b > 64


def _delete_iface(name: str) -> None:
    """Best-effort `ip link del`; never raises."""
    subprocess.run(
        ["ip", "link", "del", name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
