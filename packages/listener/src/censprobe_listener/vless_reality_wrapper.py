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
import os
import tempfile
from pathlib import Path

from censprobe_listener.echo_server import ECHO_PORTS

logger = logging.getLogger(__name__)


def _write_secret(path: Path, content: str) -> None:
    """Create `path` mode 0o600 — config holds the Reality server private key."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    with fh:
        fh.write(content)


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
        self._proc: asyncio.subprocess.Process | None = None
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
        _write_secret(conf_path, json.dumps(config, indent=2))

        self._proc = await asyncio.create_subprocess_exec(
            "xray", "run", "-c", str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        await asyncio.sleep(1.0)
        if self._proc.returncode is not None:
            out = b""
            if self._proc.stdout is not None:
                try:
                    out = await self._proc.stdout.read()
                except Exception:
                    pass
            raise RuntimeError(
                f"xray failed to start: {out.decode(errors='replace')}"
            )

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info("VLESS+Reality responder started on TCP/%d (echo: 127.0.0.1:%d)",
                    self.port, self.echo_port)

    async def _monitor_output(self) -> None:
        # Native async readline — see ss_responder for rationale.
        if self._proc is None or self._proc.stdout is None:
            return
        try:
            while True:
                line_bytes = await self._proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode(errors="replace").strip()
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
                if self._proc.returncode is None:
                    self._proc.terminate()
                    try:
                        await asyncio.wait_for(self._proc.wait(), timeout=0.5)
                    except asyncio.TimeoutError:
                        self._proc.kill()
                        try:
                            await self._proc.wait()
                        except Exception:
                            pass
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
