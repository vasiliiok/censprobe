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
import os
import tempfile
from pathlib import Path

from censprobe_listener.echo_server import ECHO_PORTS

logger = logging.getLogger(__name__)


def _write_secret(path: Path, content: str) -> None:
    """Create `path` mode 0o600 atomically — config holds the SS password."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    with fh:
        fh.write(content)


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
        self._proc: asyncio.subprocess.Process | None = None
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
        _write_secret(conf_path, json.dumps(config, indent=2))

        self._proc = await asyncio.create_subprocess_exec(
            "sing-box", "run", "-c", str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        await asyncio.sleep(0.5)
        if self._proc.returncode is not None:
            out = b""
            if self._proc.stdout is not None:
                try:
                    out = await self._proc.stdout.read()
                except Exception:
                    pass
            raise RuntimeError(
                f"sing-box failed to start: {out.decode(errors='replace')}"
            )

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info("Shadowsocks responder started on TCP/%d (echo: 127.0.0.1:%d)",
                    self.port, self.echo_port)

    async def _monitor_output(self) -> None:
        # Native async readline doesn't pin a thread from the default
        # ThreadPoolExecutor the way loop.run_in_executor(readline) does.
        # With three log-monitoring coroutines running simultaneously,
        # the old blocking approach starved the pool on small VPS's.
        if self._proc is None or self._proc.stdout is None:
            return
        try:
            while True:
                line_bytes = await self._proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode(errors="replace").strip()
                if line:
                    logger.debug("[sing-box] %s", line)
                    low = line.lower()
                    if "inbound connection" in low or "accepted" in low:
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
                logger.warning("sing-box stop error: %s", e)
            self._proc = None

        if self._tmpdir:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

        logger.info("Shadowsocks responder stopped (connections: %d)", self.connection_count)
