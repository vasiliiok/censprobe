"""
ss_responder.py — Shadowsocks 2022 test responder via sing-box.

Runs sing-box with a Shadowsocks inbound (2022-blake3-aes-256-gcm).
The only allowed outbound is a local echo port (127.0.0.1:ECHO_PORTS['shadowsocks']);
any other traffic is blocked. Connection/handshake counts come from sing-box
stdout, data-phase success from the echo server's byte counter.
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


class ShadowsocksResponder:
    def __init__(
        self,
        password_b64: str,
        port: int = 8388,
        method: str = "2022-blake3-aes-256-gcm",
        echo_port: int | None = None,
    ) -> None:
        self.password_b64 = password_b64
        self.port = port
        self.method = method
        self.echo_port = echo_port or ECHO_PORTS["shadowsocks"]
        self._proc: subprocess.Popen | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._log_task: asyncio.Task | None = None
        self.connection_count = 0
        # Injected by listener main so we can observe data phase.
        self.echo_server = None  # type: ignore[assignment]

    @property
    def data_transfer_ok(self) -> bool:
        if self.echo_server is None:
            return False
        return self.echo_server.data_ok("shadowsocks")

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_ss_")
        tmpdir = Path(self._tmpdir.name)

        config = {
            "log": {"level": "info", "output": "stdout", "timestamp": True},
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "censprobe-ss",
                    "listen": "::",
                    "listen_port": self.port,
                    "method": self.method,
                    "password": self.password_b64,
                    "multiplex": {"enabled": False},
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": {
                "final": "block",
                "rules": [
                    {
                        "ip_cidr": ["127.0.0.1/32"],
                        "port": [self.echo_port],
                        "outbound": "direct",
                    }
                ],
            },
        }

        conf_path = tmpdir / "config.json"
        conf_path.write_text(json.dumps(config, indent=2))

        self._proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(conf_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        await asyncio.sleep(0.5)
        if self._proc.poll() is not None:
            out = self._proc.stdout.read() if self._proc.stdout else ""
            raise RuntimeError(f"sing-box failed to start: {out}")

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info("Shadowsocks responder started on TCP/%d (echo: 127.0.0.1:%d)",
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
                    logger.debug("[sing-box] %s", line)
                    if "inbound connection" in line.lower() or "accepted" in line.lower():
                        self.connection_count += 1
        except Exception as e:
            logger.debug("sing-box monitor ended: %s", e)

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
                logger.warning("sing-box stop error: %s", e)
            self._proc = None

        if self._tmpdir:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

        logger.info("Shadowsocks responder stopped (connections: %d)", self.connection_count)
