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
        #
        # ``-d`` (debug) is REQUIRED for handshake counting to work at
        # all. mtg's default zerolog level is WarnLevel (see
        # internal/cli/run_proxy.go::makeLogger), and the
        # ``Stream has been started`` event we count is emitted at
        # InfoLevel — which is BELOW Warn and therefore silently
        # dropped from stdout without ``-d``. Verified 2026-05 against
        # MTG_COMMIT 269852a4: in non-debug mode the responder never
        # prints anything until an ERROR is hit, so connection_count
        # stays at 0 forever and every probe reports listener-side
        # BLOCKED while the client validates the faketls handshake
        # cleanly. Log volume in debug mode is modest (~2 lines/sec
        # idle plus a few lines per stream) — survivable for the
        # typical 3-minute session.
        cmd = [
            "mtg",
            "simple-run",
            "-d",
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

        mtg's flow (mtglib/proxy.go::Serve): on every TCP accept it
        emits ``Stream has been started`` *before* attempting the
        faketls handshake. So a port-scanner sending garbage bytes
        increments that counter just like a real client would. We
        therefore *subtract* the per-stream failure markers mtg emits
        when the faketls or doppelganger steps fail — net result: the
        counter only retains streams that survived the faketls layer.
        ``Stream has been finished`` is intentionally ignored (every
        stream emits it, success or failure), and domain-fronting
        fallbacks are reflected by the doppelganger-failure marker.

        Failure markers grepped from MTG_COMMIT 269852a4
        (mtglib/proxy.go ~ln 95-205 and faketls path):
          * "cannot parse client hello"
          * "cannot read client hello"
          * "cannot send welcome packet"
          * "obfuscated handshake is failed"
          * "cannot wrap into doppelganger connection"
          * "ip was rejected by allowlist" / "ip was blacklisted"
          * "connection was concurrency limited"
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
                low = line.lower()
                if "stream has been started" in low:
                    self.connection_count += 1
                elif any(
                    marker in low
                    for marker in (
                        "cannot parse client hello",
                        "cannot read client hello",
                        "cannot send welcome packet",
                        "obfuscated handshake is failed",
                        "cannot wrap into doppelganger connection",
                        "ip was rejected by allowlist",
                        "ip was blacklisted",
                        "connection was concurrency limited",
                    )
                ):
                    # Subtract the start that preceded this failure so
                    # only streams that survived the faketls layer
                    # remain. Floor at 0 — extra/unmatched failures
                    # (e.g. concurrency limit before a stream-start)
                    # must not push the counter negative.
                    self.connection_count = max(0, self.connection_count - 1)
        except Exception as e:
            logger.debug("mtg monitor ended: %s", e)

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def data_transfer_ok(self) -> bool:
        # Censprobe's mtproto_proxy probe validates the faketls
        # WelcomePacket HMAC and then closes — it never opens an
        # upstream Telegram DC stream. So from the listener's
        # perspective there is NO data-plane evidence to observe:
        # everything we see is at the handshake layer. Returning
        # ``False`` here makes the verdict aggregator consistently
        # produce HANDSHAKE_ONLY (matching the client, which uses
        # exactly the same HMAC-only criterion). Returning ``True``
        # on connection_count > 0 — as the previous version did —
        # produced false-OK verdicts at the listener while the
        # client correctly reported HANDSHAKE_ONLY, splitting the
        # dashboard's reachability matrix without informational gain.
        return False
