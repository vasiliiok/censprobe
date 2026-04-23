"""
hysteria_wrapper.py — Hysteria 2 test responder.

Runs hysteria server with salamander obfuscation.
In test mode: no real traffic forwarding — just handshake measurement.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class HysteriaResponder:
    """
    Runs hysteria 2 server for QUIC handshake testing.
    """

    def __init__(
        self,
        auth_password: str,
        obfs_password: str,
        port: int = 443,
    ) -> None:
        self.auth_password = auth_password
        self.obfs_password = obfs_password
        self.port = port
        self._proc: subprocess.Popen | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._log_task: asyncio.Task | None = None
        self.connection_count = 0

    async def start(self) -> None:
        """Write hysteria config and start server."""
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_hy2_")
        tmpdir = Path(self._tmpdir.name)

        # Generate a self-signed cert for TLS (hysteria handles this internally if acme=disabled)
        cert_path = tmpdir / "cert.pem"
        key_path = tmpdir / "key.pem"
        await self._generate_self_signed_cert(cert_path, key_path)

        config = {
            "listen": f":{self.port}",
            "tls": {
                "cert": str(cert_path),
                "key": str(key_path),
            },
            "obfs": {
                "type": "salamander",
                "salamander": {
                    "password": self.obfs_password,
                },
            },
            "auth": {
                "type": "password",
                "password": self.auth_password,
            },
            "masquerade": {
                "type": "proxy",
                "proxy": {
                    "url": "https://www.bing.com",
                    "rewriteHost": True,
                },
            },
        }

        conf_path = tmpdir / "config.json"
        conf_path.write_text(json.dumps(config, indent=2))

        self._proc = subprocess.Popen(
            ["hysteria", "server", "--config", str(conf_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        await asyncio.sleep(1.0)
        if self._proc.poll() is not None:
            out = self._proc.stdout.read()
            raise RuntimeError(f"hysteria failed to start: {out}")

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info("Hysteria 2 responder started on UDP/%d", self.port)

    async def _monitor_output(self) -> None:
        if not self._proc or not self._proc.stdout:
            return
        loop = asyncio.get_running_loop()
        try:
            while True:
                line = await loop.run_in_executor(None, self._proc.stdout.readline)
                if not line:
                    break
                line = line.strip()
                if line:
                    logger.debug("[hysteria] %s", line)
                    if "client connected" in line.lower() or "authenticated" in line.lower():
                        self.connection_count += 1
        except Exception as e:
            logger.debug("hysteria monitor ended: %s", e)

    async def stop(self) -> None:
        if self._log_task:
            self._log_task.cancel()
            try:
                await self._log_task
            except asyncio.CancelledError:
                pass

        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.sleep(0.5)
                if self._proc.poll() is None:
                    self._proc.kill()
            except Exception as e:
                logger.warning("hysteria stop error: %s", e)
            self._proc = None

        if self._tmpdir:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass

        logger.info("Hysteria 2 responder stopped (connections: %d)", self.connection_count)

    @staticmethod
    async def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
        """Generate a self-signed TLS certificate using openssl."""
        loop = asyncio.get_running_loop()

        def _gen():
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-keyout", str(key_path),
                    "-out", str(cert_path),
                    "-days", "1",
                    "-nodes",
                    "-subj", "/CN=censprobe-test",
                ],
                check=True,
                capture_output=True,
            )

        try:
            await loop.run_in_executor(None, _gen)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"openssl cert gen failed: {e.stderr.decode()}")
