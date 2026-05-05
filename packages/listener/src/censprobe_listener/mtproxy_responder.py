"""
mtproxy_responder.py — Manage the mtg MTProto proxy responder.

mtg is started in ``simple-run`` mode with the operator-supplied ee-secret
(faketls). mtg's domain-fronting fallback for failed handshakes is its
default behaviour and is left in place: censprobe never connects to the
configured fronting host (google.com) outbound, so the fallback only
triggers if a third party reaches the listener with garbage — exactly the
case where domain fronting is meant to mask the proxy's existence.

The lifecycle mirrors :class:`SubprocessResponder` (start / stop coroutine
contract) but mtg's stdout schema differs enough that subclassing the base
template would obscure the format strings. We keep the stop semantics
(SIGTERM → 2s grace → SIGKILL) identical so the listener's
``_stop_responders`` deadline applies uniformly.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

logger = logging.getLogger(__name__)


class MTProxyResponder:
    """Manages an ``mtg simple-run`` process for a single session."""

    proto_label = "mtproto_proxy"

    def __init__(self, port: int, secret: str) -> None:
        self.port = port
        self.secret = secret
        self._proc: asyncio.subprocess.Process | None = None
        self._log_task: asyncio.Task[None] | None = None
        # Per-session counter incremented on every successful handshake we
        # observe in mtg's stdout. Surfaced via the same property name as
        # the SubprocessResponder template so _finalize_protocol_result
        # picks it up without a special case.
        self.connection_count: int = 0

    async def start(self) -> None:
        # ``-t`` is mtg's network-timeout knob (default 10s). 30s gives
        # slow client networks margin without affecting handshake-success
        # accounting; the responder runs until SIGTERM regardless.
        cmd = [
            "mtg",
            "simple-run",
            "-t",
            "30s",
            f"0.0.0.0:{self.port}",
            self.secret,
        ]
        logger.info(f"Starting mtg on port {self.port} with ee-secret")
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        # Settle window — mtg either binds within ~1s or it died with a
        # bind/parse error. Bail out with the captured tail so the listener
        # surfaces the real reason instead of a generic "responder failed".
        await asyncio.sleep(1.0)
        if self._proc.returncode is not None:
            tail = b""
            if self._proc.stdout is not None:
                # Best-effort tail capture — pipe may already be closed
                # if mtg crashed hard.
                with contextlib.suppress(Exception):
                    tail = await self._proc.stdout.read()
            raise RuntimeError(f"mtg failed to start: {tail.decode(errors='replace')}")

        self._log_task = asyncio.create_task(self._monitor_output())

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
            logger.info("Stopping mtg")
            try:
                self._proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=2.0)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.kill()
                # wait() can raise after kill() races with the OS reaping
                # the zombie — we only need an upper bound, not a clean exit.
                with contextlib.suppress(Exception):
                    await self._proc.wait()
            self._proc = None

        logger.info(
            "mtproto_proxy responder stopped (connections: %d)",
            self.connection_count,
        )

    async def _monitor_output(self) -> None:
        """Tail mtg stdout and count successful handshakes.

        mtg logs one ``Stream has been started`` line at the moment a
        client passes the faketls handshake (see mtglib/proxy.go). We
        match on that token rather than ``Stream has been finished`` so a
        single client that opens-and-closes still yields a count of 1.
        Domain-fronting fallbacks log under different tokens and are
        intentionally NOT counted — they would inflate the metric on any
        unrelated TCP probe that hits the port.
        """
        if self._proc is None or self._proc.stdout is None:
            return
        try:
            while True:
                line_bytes = await self._proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode(errors="replace").strip()
                if not line:
                    continue
                logger.debug("[mtg] %s", line)
                if "stream has been started" in line.lower():
                    self.connection_count += 1
        except Exception as e:
            logger.debug("mtg monitor ended: %s", e)

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def data_transfer_ok(self) -> bool:
        # mtg routes traffic upstream to Telegram DCs as a real proxy;
        # censprobe doesn't attempt the upstream tunnel during a probe,
        # so there is no separate "data plane" signal — handshake_count
        # is the source of truth.
        return self.connection_count > 0
