"""
mtproxy_responder.py — Manage the mtg MTProto proxy responder.
"""
from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)


class MTProxyResponder:
    """Manages an mtg MTProto proxy process for a single session."""

    def __init__(self, port: int, secret: str) -> None:
        self.port = port
        self.secret = secret
        self._proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        cmd = [
            "mtg", "simple-run",
            "-t", "30s",  # Shorter timeout since it's just a probe
            f"0.0.0.0:{self.port}",
            self.secret,
        ]
        logger.info(f"Starting mtg on port {self.port} with ee-secret")
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def stop(self) -> None:
        if self._proc is not None:
            logger.info("Stopping mtg")
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None

    @property
    def is_running(self) -> bool:
        if self._proc is None:
            return False
        return self._proc.poll() is None
