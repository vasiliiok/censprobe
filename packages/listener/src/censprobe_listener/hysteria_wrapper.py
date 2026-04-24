"""
hysteria_wrapper.py — Hysteria 2 test responder.

Runs hysteria server with salamander obfuscation. No traffic forwarding to
the outside world — the only allowed destination is the local echo port
(127.0.0.1:ECHO_PORTS['hysteria2']). Non-authenticated traffic gets a small
static 404 response rather than being proxied externally.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path

from censprobe_listener.echo_server import ECHO_PORTS

logger = logging.getLogger(__name__)


class HysteriaResponder:
    def __init__(
        self,
        auth_password: str,
        obfs_password: str,
        port: int = 443,
        echo_port: int | None = None,
    ) -> None:
        self.auth_password = auth_password
        self.obfs_password = obfs_password
        self.port = port
        self.echo_port = echo_port or ECHO_PORTS["hysteria2"]
        self._proc: subprocess.Popen | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._log_task: asyncio.Task | None = None
        self.connection_count = 0
        self.echo_server = None  # type: ignore[assignment]

    @property
    def data_transfer_ok(self) -> bool:
        if self.echo_server is None:
            return False
        return self.echo_server.data_ok("hysteria2")

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_hy2_")
        tmpdir = Path(self._tmpdir.name)

        cert_path = tmpdir / "cert.pem"
        key_path = tmpdir / "key.pem"
        await self._generate_self_signed_cert(cert_path, key_path)

        # ACL: allow ONLY echo-port on loopback; reject everything else.
        # Hysteria 2 ACL expects `action(<cidr>, <proto>/<port>)` — a bare
        # port number is NOT valid grammar and the server will refuse to
        # start. Echo server is TCP-only, so scope the rule to tcp.
        acl_path = tmpdir / "acl.txt"
        acl_path.write_text(
            f"direct(127.0.0.1/32, tcp/{self.echo_port})\n"
            "reject(all)\n"
        )

        config = {
            "listen": f":{self.port}",
            "tls": {"cert": str(cert_path), "key": str(key_path)},
            "obfs": {
                "type": "salamander",
                "salamander": {"password": self.obfs_password},
            },
            "auth": {"type": "password", "password": self.auth_password},
            # 404 for unauthenticated traffic — no outbound proxying.
            "masquerade": {
                "type": "string",
                "string": {
                    "content": "Not Found",
                    "headers": {"Content-Type": "text/plain"},
                    "statusCode": 404,
                },
            },
            "acl": {"file": str(acl_path)},
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
            out = self._proc.stdout.read() if self._proc.stdout else ""
            raise RuntimeError(f"hysteria failed to start: {out}")

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info("Hysteria 2 responder started on UDP/%d (echo: 127.0.0.1:%d)",
                    self.port, self.echo_port)

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
                    low = line.lower()
                    if "client connected" in low or "authenticated" in low:
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
            self._log_task = None

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
            self._tmpdir = None

        logger.info("Hysteria 2 responder stopped (connections: %d)", self.connection_count)

    @staticmethod
    async def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
        loop = asyncio.get_running_loop()

        def _gen() -> None:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-keyout", str(key_path),
                    "-out", str(cert_path),
                    "-days", "7",
                    "-nodes",
                    "-subj", "/CN=censprobe-test",
                ],
                check=True,
                capture_output=True,
            )

        try:
            await loop.run_in_executor(None, _gen)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"openssl cert gen failed: {e.stderr.decode(errors='replace')}")
