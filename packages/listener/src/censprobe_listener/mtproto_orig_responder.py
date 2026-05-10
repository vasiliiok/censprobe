"""
mtproto_orig_responder.py — Run the original Telegram MTProxy (C, from
TelegramMessenger/MTProxy) as a sibling to the mtg fakeTLS responders.

Why a separate responder class instead of reusing :class:`MTProxyResponder`:

* Different binary (``mtproto-proxy`` vs ``mtg``).
* Different argv shape — original MTProxy needs ``-u`` (setuid),
  ``-p`` (loopback stats port), ``-H`` (client port), ``-S`` (secret),
  ``--aes-pwd`` (Telegram cloud secret blob), and a positional path
  to the cloud topology file ``proxy-multi.conf``. mtg's ``simple-run``
  has none of these.
* Different stdout schema — its handshake-success line is
  ``main_session_query: connection from`` (or similar) rather than
  mtg's ``Stream has been started``.
* Different runtime artifacts — the proxy-secret + proxy-multi.conf
  files are baked into the listener image at build time
  (``/usr/local/share/mtproxy-orig/``); a missing/corrupt file at
  start-up means an outdated image, not a per-session error.

Lifecycle and shutdown semantics mirror :class:`MTProxyResponder`
(SIGTERM → 2 s grace → SIGKILL) so the listener's
``_stop_responders`` deadline applies uniformly across mtproto siblings.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket

from censprobe_listener._iptables_counter import (
    install_counter,
    read_counter,
    remove_counter,
)

logger = logging.getLogger(__name__)

# Bake-time runtime artifacts location. Provisioned by the listener
# Dockerfile's mtproxy-orig-builder stage (see packages/listener/Dockerfile).
# (S105: this is a filesystem path, not a credential — name "secret" is the
# upstream Telegram filename, kept verbatim so operators recognise it.)
_PROXY_SECRET_PATH = "/usr/local/share/mtproxy-orig/proxy-secret"  # noqa: S105
_PROXY_MULTI_CONF_PATH = "/usr/local/share/mtproxy-orig/proxy-multi.conf"


def _pick_free_loopback_port() -> int:
    """Return a free TCP port on 127.0.0.1 (for ``-p`` stats endpoint).

    mtproto-proxy always opens a loopback statistics endpoint and refuses
    to start without one. We bind transiently to ask the kernel for a
    free port, then release it — there is a tiny TOCTOU window where
    another process could grab the same port between this call and
    mtproto-proxy's bind, but on a single-tenant listener container the
    risk is negligible. Falling back to a hardcoded port (e.g. 31337)
    would create a collision when two ``mtproto_orig`` instances ever
    share an image, so a kernel-provided ephemeral is preferred.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port
    finally:
        s.close()


class MTProxyOrigResponder:
    """Manages a ``mtproto-proxy`` (original C) process for one session."""

    proto_label = "mtproto_orig"

    def __init__(self, port: int, secret: str) -> None:
        self.port = port
        # ``secret`` is the operator-visible "dd<32-hex>" (34 chars). The ``dd``
        # is an obfuscated2 transport-tag for the client only; the C
        # ``mtproto-proxy`` binary's ``-S`` insists on the bare 16-byte secret
        # (exactly 32 hex digits) and exits with "'S' option requires exactly
        # 32 hex digits" otherwise. Stash both forms so the cli-arg path is
        # explicit and the operator-visible credential stays unchanged.
        self.secret = secret
        s = secret.lower()
        self._secret_for_argv = s[2:] if s.startswith("dd") else s
        self._proc: asyncio.subprocess.Process | None = None
        self._log_task: asyncio.Task[None] | None = None
        self.connection_count: int = 0
        # Comment used to identify our iptables counter rule. Includes
        # the port so multiple mtproto_orig instances on the same host
        # (different ports) don't share a counter.
        self._counter_comment = f"censprobe-mtorig-{self.port}"

    async def start(self) -> None:
        stats_port = _pick_free_loopback_port()
        cmd = [
            "mtproto-proxy",
            "-u",
            "nobody",
            "-p",
            str(stats_port),
            "-H",
            str(self.port),
            "-S",
            self._secret_for_argv,
            "--aes-pwd",
            _PROXY_SECRET_PATH,
            _PROXY_MULTI_CONF_PATH,
            "-M",
            "1",
        ]
        logger.info(
            "Starting mtproto-proxy (original C) on port %d with dd-secret",
            self.port,
        )
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        # Settle window — mtproto-proxy is a bit slower to come up than mtg
        # because it parses proxy-multi.conf and resolves Telegram DC IPs.
        # 2 s should be enough on any container that boots in <5 s. If it
        # exits early we surface the captured tail rather than a generic
        # "responder failed".
        await asyncio.sleep(2.0)
        if self._proc.returncode is not None:
            tail = b""
            if self._proc.stdout is not None:
                with contextlib.suppress(Exception):
                    tail = await self._proc.stdout.read()
            raise RuntimeError(f"mtproto-proxy failed to start: {tail.decode(errors='replace')}")

        self._log_task = asyncio.create_task(self._monitor_output())
        await install_counter("OUTPUT", self._counter_rule_args(), self._counter_comment)

    async def stop(self) -> None:
        # Read the iptables packet counter BEFORE we tear down — the
        # ``-D`` in ``remove_counter`` drops the rule and its counter
        # together. Sums across iptables + ip6tables so an IPv6 client
        # also flips ``data_transfer_ok``.
        observed = await read_counter("OUTPUT", self._counter_comment)
        if observed > self.connection_count:
            self.connection_count = observed
        await remove_counter("OUTPUT", self._counter_rule_args())

        if self._log_task is not None:
            self._log_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._log_task
            self._log_task = None

        if self._proc is not None:
            logger.info("Stopping mtproto-proxy (original C)")
            try:
                self._proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=2.0)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.kill()
                with contextlib.suppress(Exception):
                    await self._proc.wait()
            self._proc = None

        logger.info(
            "mtproto_orig responder stopped (connections: %d)",
            self.connection_count,
        )

    async def _monitor_output(self) -> None:
        """Drain mtproto-proxy stdout for diagnostic purposes only.

        Earlier versions counted handshakes by grepping the C binary's
        stdout for "main_session_query: connection from" / "new
        connection from" / "query from". Empirically the upstream
        TelegramMessenger/MTProxy build (commit cafc3380) does NOT
        emit any per-client-accept line at default verbosity (-v 1),
        so the grep-based counter stayed at 0 even when real clients
        completed obfuscated2 handshakes — confirmed against pcap on
        2026-05-10. The handshake counter has moved to an iptables
        OUTPUT counter rule (see ``_counter_install``); this monitor
        now only drains stdout to keep the pipe from filling up and
        surfaces lines at DEBUG level for triage when responder
        startup fails.
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
                logger.debug("[mtproto-proxy] %s", line)
        except Exception as e:
            logger.debug("mtproto-proxy monitor ended: %s", e)

    def _counter_rule_args(self) -> list[str]:
        """Rule args for the OUTPUT counter that ticks once per data
        segment the proxy emits from ``sport=<self.port>``.

        We count packets where the server emits a TCP segment with
        PSH+ACK set — i.e. a data-bearing response from mtproto-proxy
        back to the client. Each successful obfuscated2 + req_pq probe
        produces ≥ 1 such packet (the encrypted resPQ frame, ~165
        bytes inc. headers); failed/garbage clients get only TCP
        control packets (SYN-ACK, bare ACK, RST/FIN) which lack PSH
        and therefore don't tick the counter. This is more reliable
        than stdout-grep because it works regardless of mtproto-proxy
        verbosity flags or upstream version, and it's measured at the
        kernel level *after* the C binary actually wrote bytes onto
        the wire.

        The shared ``install_counter`` helper installs this on both
        ``iptables`` and ``ip6tables`` so an IPv6 client also flips
        ``data_transfer_ok``. The rule has no ``-j`` target — see
        ``_iptables_counter`` for the rationale on counter-only
        matches and ``-j ACCEPT`` avoidance.
        """
        return [
            "-p",
            "tcp",
            "--sport",
            str(self.port),
            "--tcp-flags",
            "PSH,ACK",
            "PSH,ACK",
            "-m",
            "comment",
            "--comment",
            self._counter_comment,
        ]

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def data_transfer_ok(self) -> bool:
        return self.connection_count > 0
