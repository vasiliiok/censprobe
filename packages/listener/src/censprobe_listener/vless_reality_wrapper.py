"""
vless_reality_wrapper.py — VLESS+Reality test responder via xray-core.

Runs xray with VLESS inbound + Reality TLS. The only permitted outbound
destination is the local echo port (127.0.0.1:ECHO_PORTS['vless_reality']);
anything else is blackholed. This lets us measure both handshake success
(xray log) and data-phase success (echo server counter).
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


class VlessRealityResponder:
    def __init__(
        self,
        uuid: str,
        private_key: str,
        public_key: str,
        short_id: str,
        server_name: str = "apimaps.yandex.ru",
        port: int = 443,
        echo_port: int | None = None,
    ) -> None:
        self.uuid = uuid
        self.private_key = private_key
        self.public_key = public_key
        self.short_id = short_id
        self.server_name = server_name
        self.port = port
        self.echo_port = echo_port or ECHO_PORTS["vless_reality"]
        self._proc: subprocess.Popen | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._log_task: asyncio.Task | None = None
        self.connection_count = 0
        self.echo_server = None  # type: ignore[assignment]

    @property
    def data_transfer_ok(self) -> bool:
        if self.echo_server is None:
            return False
        return self.echo_server.data_ok("vless_reality")

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_xray_")
        tmpdir = Path(self._tmpdir.name)

        config = {
            "log": {"loglevel": "info"},
            "inbounds": [
                {
                    "tag": "censprobe-vless",
                    "port": self.port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": self.uuid,
                                "flow": "xtls-rprx-vision",
                            }
                        ],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": f"{self.server_name}:443",
                            "xver": 0,
                            "serverNames": [self.server_name],
                            "privateKey": self.private_key,
                            "shortIds": [self.short_id],
                        },
                    },
                    "sniffing": {"enabled": False},
                }
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "ip": ["127.0.0.1/32"],
                        "port": str(self.echo_port),
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "inboundTag": ["censprobe-vless"],
                        "outboundTag": "block",
                    },
                ]
            },
        }

        conf_path = tmpdir / "config.json"
        conf_path.write_text(json.dumps(config, indent=2))

        self._proc = subprocess.Popen(
            ["xray", "run", "-c", str(conf_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        await asyncio.sleep(1.0)
        if self._proc.poll() is not None:
            out = self._proc.stdout.read() if self._proc.stdout else ""
            raise RuntimeError(f"xray failed to start: {out}")

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info("VLESS+Reality responder started on TCP/%d (echo: 127.0.0.1:%d)",
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
                    logger.debug("[xray] %s", line)
                    if "accepted" in line.lower():
                        self.connection_count += 1
        except Exception as e:
            logger.debug("xray monitor ended: %s", e)

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
                logger.warning("xray stop error: %s", e)
            self._proc = None

        if self._tmpdir:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

        logger.info("VLESS+Reality responder stopped (connections: %d)", self.connection_count)
