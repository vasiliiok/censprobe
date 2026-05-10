"""
_responder_base.py — Common lifecycle for SS / VLESS / Hysteria responders.

All three of those protocols are implemented as a single foreign binary
(sing-box / xray / hysteria) running off a JSON config file. The
lifecycle is identical:

    start(): mkdtemp → write 0o600 config → spawn subprocess → wait the
             post-spawn settle window → bail out if the child died → start
             a stdout monitor task that pattern-matches handshake events
             into a counter.
    stop():  cancel monitor → SIGTERM/SIGKILL the child → cleanup tempdir.

This base class captures that template; concrete responders only have to
provide:

  * ``proto_label`` (string used to query the echo server),
  * ``binary_argv`` (the full subprocess command),
  * ``config_dict()`` (returns the dict to JSON-dump as the config file),
  * ``handshake_log_pattern`` (lowercase substring; one line == one
    handshake count),
  * optionally ``startup_settle_sec`` (default 1.0) and
    ``pre_spawn_setup()`` (e.g. Hysteria generates its self-signed cert).

Everything else — process reaping, log-pipe drain semantics, tempdir
cleanup, snapshot accessors — lives here so a regression in one responder
fixes itself across all three.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from censprobe_core.echo_ports import ECHO_PORTS
from censprobe_core.models import LiveSnapshot
from censprobe_core.utils import graceful_terminate, write_secret

if TYPE_CHECKING:
    from censprobe_listener.echo_server import EchoServer

logger = logging.getLogger(__name__)


class SubprocessResponder(ABC):
    """Template-method base for sing-box / xray / hysteria responders."""

    # Subclasses override these two by setting class attributes; defining
    # them as class-level slots here keeps mypy/pyright happy.
    proto_label: str = ""
    handshake_log_pattern: str | tuple[str, ...] = ""
    startup_settle_sec: float = 1.0
    tempdir_prefix: str = "censprobe_resp_"
    log_prefix: str = ""  # what to print in DEBUG logs ("[xray] ...")

    def __init__(self, port: int, echo_port: int | None = None) -> None:
        self.port = port
        self.echo_port = echo_port if echo_port is not None else ECHO_PORTS[self.proto_label]
        self._proc: asyncio.subprocess.Process | None = None
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._log_task: asyncio.Task[None] | None = None
        self.connection_count: int = 0
        # Injected by listener/main.py so we can observe data phase via
        # the local TCP echo server. None means "echo unavailable" — the
        # responder still emits a meaningful handshake count.
        self.echo_server: EchoServer | None = None

    # ── Subclass hooks ───────────────────────────────────────────────────────

    @abstractmethod
    def binary_argv(self, config_path: Path) -> list[str]:
        """Argv for the foreign binary, e.g. ``["xray", "run", "-c", path]``."""

    @abstractmethod
    def config_dict(self) -> dict[str, Any]:
        """Return the dict serialized as the subprocess config file (JSON)."""

    async def pre_spawn_setup(self, tmpdir: Path) -> None:
        """Optional pre-spawn step (cert generation, ACL files, etc.).

        Async by contract: subclasses (e.g. hysteria_wrapper) perform
        async cert generation here. The base no-op stays ``async`` so
        every subclass override matches the parent's signature.
        """
        # Yield once so the function is a real coroutine (S7503 — Sonar
        # otherwise flags this as "no async features").
        await asyncio.sleep(0)

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if not self.proto_label:
            raise RuntimeError(f"{type(self).__name__} did not set proto_label; cannot start")

        self._tmpdir = tempfile.TemporaryDirectory(prefix=self.tempdir_prefix)
        tmpdir = Path(self._tmpdir.name)

        await self.pre_spawn_setup(tmpdir)

        conf_path = tmpdir / "config.json"
        # 0o600 from the moment of creation — the JSON usually carries
        # credential material (Reality privkey, SS password, hy2 auth/obfs).
        write_secret(conf_path, json.dumps(self.config_dict(), indent=2))

        argv = self.binary_argv(conf_path)
        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        await asyncio.sleep(self.startup_settle_sec)
        if self._proc.returncode is not None:
            tail = b""
            if self._proc.stdout is not None:
                # Best-effort tail capture for the error message — if the
                # pipe is already closed or read fails we still raise below
                # with whatever we have.
                with contextlib.suppress(Exception):
                    tail = await self._proc.stdout.read()
            raise RuntimeError(f"{argv[0]} failed to start: {tail.decode(errors='replace')}")

        self._log_task = asyncio.create_task(self._monitor_output())
        logger.info(
            "%s responder started on %d (echo: 127.0.0.1:%d)",
            self.proto_label,
            self.port,
            self.echo_port,
        )

    async def stop(self) -> None:
        if self._log_task is not None:
            self._log_task.cancel()
            # We cancelled the inner task ourselves; suppress its
            # CancelledError. ``contextlib.suppress`` instead of try/except
            # so Sonar S7497 doesn't flag this as missing a re-raise.
            with contextlib.suppress(asyncio.CancelledError):
                await self._log_task
            self._log_task = None

        if self._proc is not None:
            try:
                await graceful_terminate(self._proc, timeout=0.5)
            except Exception as e:
                logger.warning("%s stop error: %s", self.proto_label, e)
            self._proc = None

        if self._tmpdir is not None:
            # cleanup() can race with files still held open by the child
            # process during a SIGKILL; we don't want shutdown to fail
            # over a stray temp file. The OS reaps tmpdir on next reboot.
            with contextlib.suppress(Exception):
                self._tmpdir.cleanup()
            self._tmpdir = None

        logger.info(
            "%s responder stopped (connections: %d)",
            self.proto_label,
            self.connection_count,
        )

    # ── Monitoring + introspection ───────────────────────────────────────────

    async def _monitor_output(self) -> None:
        """Read the child's stdout line-by-line; count handshake events.

        Native ``readline`` (not ``loop.run_in_executor(readline)``) so the
        three concurrent log monitors don't pin three threads from the
        default ThreadPoolExecutor and starve other I/O on small VPSes.
        """
        if self._proc is None or self._proc.stdout is None:
            return
        patterns = (
            (self.handshake_log_pattern,)
            if isinstance(self.handshake_log_pattern, str)
            else self.handshake_log_pattern
        )
        prefix = self.log_prefix or f"[{self.proto_label}]"
        try:
            while True:
                line_bytes = await self._proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode(errors="replace").strip()
                if not line:
                    continue
                logger.debug("%s %s", prefix, line)
                low = line.lower()
                if any(p in low for p in patterns):
                    self.connection_count += 1
        except Exception as e:
            logger.debug("%s monitor ended: %s", self.proto_label, e)

    @property
    def data_transfer_ok(self) -> bool:
        if self.echo_server is None:
            return False
        return self.echo_server.data_ok(self.proto_label)

    def live_snapshot(self) -> LiveSnapshot:
        """Live snapshot for the cred-server /snapshot endpoint.

        ``connection_count`` is incremented in ``_monitor_output`` on
        every handshake-marker line, so reading it any time during
        the session is correct. Data-phase verdict is derived from
        the loopback echo server's per-protocol byte counter (same
        source as the property above) — the snapshot reflects exactly
        what the listener would commit to ``ProtocolResult`` if the
        session ended now.
        """
        bytes_seen: int | None = None
        if self.echo_server is not None:
            try:
                bytes_seen = int(
                    self.echo_server.snapshot()
                    .get(self.proto_label, {})
                    .get("bytes", 0)
                    or 0
                )
            except (TypeError, ValueError):
                bytes_seen = None
        return LiveSnapshot(
            handshake_count=self.connection_count,
            data_transfer_ok=self.data_transfer_ok,
            bytes_received=bytes_seen,
        )
