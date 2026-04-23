"""
openvpn_responder.py — OpenVPN static-key test responder.

Runs openvpn in static-key (p2p) mode.
Listens on UDP/<port>, accepts connection, records events.
Does NOT forward traffic — purely a measurement endpoint.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class OpenVPNResponder:
    """
    Wraps openvpn process in static-key p2p mode.
    Protocol: client sends encrypted P_DATA_V1 -> server decrypts successfully.
    """

    def __init__(self, psk_b64: str, port: int = 1194) -> None:
        self.psk_b64 = psk_b64
        self.port = port
        self._proc: subprocess.Popen | None = None
        self._config_dir: tempfile.TemporaryDirectory | None = None

    async def start(self) -> None:
        """Write config files and launch openvpn subprocess."""
        self._config_dir = tempfile.TemporaryDirectory(prefix="censprobe_ovpn_")
        tmpdir = Path(self._config_dir.name)

        # Write PSK file
        psk_path = tmpdir / "static.key"
        psk_bytes = base64.b64decode(self.psk_b64)
        psk_path.write_bytes(psk_bytes)
        psk_path.chmod(0o600)

        # Write OpenVPN config (p2p mode, no 'mode server')
        config = f"""
proto udp
port {self.port}
dev tun
secret {psk_path}
ifconfig 10.200.0.1 10.200.0.2
keepalive 10 60
cipher AES-256-GCM
persist-key
persist-tun
status /tmp/openvpn-status.log
verb 3
log /tmp/openvpn-censprobe.log
"""
        conf_path = tmpdir / "server.conf"
        conf_path.write_text(config)

        loop = asyncio.get_running_loop()
        self._proc = await loop.run_in_executor(
            None,
            lambda: subprocess.Popen(
                ["openvpn", "--config", str(conf_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ),
        )
        # Give it a moment to start
        await asyncio.sleep(1.0)
        if self._proc.poll() is not None:
            stderr = self._proc.stderr.read().decode(errors="replace")
            raise RuntimeError(f"OpenVPN failed to start: {stderr}")
        logger.info("OpenVPN responder started on UDP/%d", self.port)

    async def stop(self) -> None:
        """Terminate openvpn and cleanup."""
        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.sleep(0.5)
                if self._proc.poll() is None:
                    self._proc.kill()
            except Exception as e:
                logger.warning("OpenVPN stop error: %s", e)
            self._proc = None

        if self._config_dir:
            try:
                self._config_dir.cleanup()
            except Exception:
                pass
            self._config_dir = None

        logger.info("OpenVPN responder stopped")

    @property
    def connection_count(self) -> int:
        """Dynamically check openvpn-status.log for data transfer."""
        status_file = Path("/tmp/openvpn-status.log")
        if not status_file.exists():
            return 0
        
        try:
            content = status_file.read_text()
            # In p2p static key mode, there is no "CLIENT LIST". 
            # We check the bytes received. If > 0, connection happened.
            for line in content.splitlines():
                if "TCP/UDP read bytes" in line:
                    bytes_read = int(line.split(",")[1].strip())
                    if bytes_read > 0:
                        return 1
            return 0
        except Exception:
            return 0
