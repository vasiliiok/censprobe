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
import secrets
import socket
import tempfile
from pathlib import Path

from censprobe_core.models import LiveSnapshot

from censprobe_listener._iptables_counter import (
    install_counter,
    read_counter,
    read_counter_sync,
    remove_counter,
)
from censprobe_listener.preflight import (
    probe_all_proxy_multi_upstreams,
    write_pruned_proxy_multi_conf,
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
        # Set to True by start() when proxy-multi.conf's upstream IPs
        # are all unreachable from the listener's vantage — typically
        # an RU host where ТСПУ drops TCP/8888 to Telegram's proxy
        # fleet (91.108.4.0/24, 149.154.0.0/16). In that state we
        # deliberately do NOT spawn ``mtproto-proxy``: with zero alive
        # upstreams the C binary enters a 145 connect/s reconnect
        # storm that starves accept() and produces every session's
        # mtproto_orig verdict as a false BLOCKED. Skipping the spawn
        # costs 35% CPU we'd otherwise burn for nothing and surfaces
        # a clean "upstream unreachable" diagnostic instead.
        self.unavailable: bool = False
        # Diagnostic counts populated by start() so main.py can render
        # an accurate preflight line ("8/16 upstreams reachable",
        # "0/16 — protocol skipped") without re-probing.
        self.upstream_alive_count: int = 0
        self.upstream_total_count: int = 0
        # tempfile we wrote the pruned proxy-multi.conf into; tracked
        # so stop() can unlink it (without leaking /tmp entries across
        # repeated listener launches in long-running CI hosts).
        self._pruned_conf_path: Path | None = None

    async def start(self) -> None:
        # Prune unreachable upstreams BEFORE spawning the daemon. See
        # the ``unavailable`` field's docstring for the censorship-
        # vantage rationale: launching mtproto-proxy with a config
        # full of unreachable IPs guarantees a 100% CPU reconnect
        # storm and starved accept queue.
        alive, unreachable = await probe_all_proxy_multi_upstreams()
        self.upstream_alive_count = len(alive)
        self.upstream_total_count = len(alive) + len(unreachable)
        if self.upstream_total_count == 0:
            # proxy-multi.conf missing entirely — image built without
            # the mtproxy-orig stage. Mark unavailable but with a
            # different diagnostic shape so the operator knows it's
            # an image issue, not a network issue.
            self.unavailable = True
            logger.warning(
                "mtproto_orig responder skipped: proxy-multi.conf missing or empty "
                "(image built without mtproxy-orig stage); responder will not start"
            )
            return
        if not alive:
            self.unavailable = True
            unreachable_sample = ", ".join(f"{ip}:{p}" for ip, p, _ in unreachable[:5])
            logger.warning(
                "mtproto_orig responder skipped: 0/%d upstream IPs reachable on TCP/8888 "
                "(sample: %s%s) — Telegram proxy fleet not reachable from this vantage. "
                "Launching mtproto-proxy in this state would trigger a ~145 connect/s "
                "auth_cluster reconnect storm and starve accept(); sessions for this "
                "protocol will report ERROR with the same 'upstream unreachable' note.",
                self.upstream_total_count,
                unreachable_sample,
                "..." if len(unreachable) > 5 else "",
            )
            return

        # K>0 alive: write a pruned proxy-multi.conf into a per-process
        # tempfile and point mtproto-proxy at it. Original file on disk
        # is left untouched so the next launch re-probes from scratch.
        #
        # Path construction is deliberately split from file creation:
        #   * ``tempfile.gettempdir()`` returns the system tempdir
        #     (``/tmp`` in the container).
        #   * ``secrets.token_hex(8)`` gives a cryptographically random
        #     16-char suffix — no caller input flows into the path, so
        #     this is provably safe for Sonar S2083 (path-traversal
        #     taint) without a suppression comment.
        # The write itself is sync I/O wrapped in ``asyncio.to_thread``
        # so we don't block the responder-startup event loop (S7493).
        self._pruned_conf_path = (
            Path(tempfile.gettempdir())
            / f"proxy-multi-pruned-{secrets.token_hex(8)}.conf"
        )
        await asyncio.to_thread(
            write_pruned_proxy_multi_conf, alive, self._pruned_conf_path
        )
        logger.info(
            "mtproto_orig: pruned proxy-multi.conf — %d/%d upstreams reachable",
            self.upstream_alive_count,
            self.upstream_total_count,
        )

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
            str(self._pruned_conf_path),
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
        if self.unavailable:
            # start() never installed the iptables counter rule nor
            # launched a subprocess — nothing to tear down. Still log
            # a tidy stop line so the session-summary output reads the
            # same shape as the OK path.
            logger.info(
                "mtproto_orig responder on port %d stopped (skipped: %d/%d upstreams reachable)",
                self.port,
                self.upstream_alive_count,
                self.upstream_total_count,
            )
            self._unlink_pruned_conf()
            return

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
            logger.info("Stopping mtproto-proxy (original C) on port %d", self.port)
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

        self._unlink_pruned_conf()

        logger.info(
            "mtproto_orig responder on port %d stopped (connections: %d)",
            self.port,
            self.connection_count,
        )

    def _unlink_pruned_conf(self) -> None:
        if self._pruned_conf_path is None:
            return
        with contextlib.suppress(OSError):
            self._pruned_conf_path.unlink()
        self._pruned_conf_path = None

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
        # ``unavailable`` responders never spawned a subprocess in the
        # first place, so "running" is unambiguously False for them.
        if self.unavailable:
            return False
        return self._proc is not None and self._proc.returncode is None

    @property
    def data_transfer_ok(self) -> bool:
        return self.connection_count > 0

    def live_snapshot(self) -> LiveSnapshot:
        """Counter snapshot for the cred-server /snapshot endpoint.

        Post-``stop()`` (``self._proc is None``) returns the cached
        ``connection_count`` — iptables rules are removed by stop(),
        so a live read would return 0. The cached value is the
        canonical post-stop reading (stop() updates it from
        ``read_counter`` BEFORE removing the rule).

        ``mtproto-proxy`` (C) emits no per-connection stdout marker
        at default verbosity, so the iptables PSH-ACK counter is the
        ONLY ground-truth signal — pre-stop we read it sync.

        For ``unavailable`` responders (proxy fleet unreachable from
        this vantage), counters stay zero and ``responder_self_test_ok``
        is False — ``ProtocolResult.finalize()`` downgrades the resulting
        BLOCKED→ERROR shape with the diagnostic note. main.py also
        sets ``responder_self_test_ok=False`` explicitly so the client-
        side cross-verification table sees the same downgrade.
        """
        if self.unavailable or self._proc is None:
            return LiveSnapshot(
                handshake_count=self.connection_count,
                data_transfer_ok=self.connection_count > 0,
                data_packets=self.connection_count,
            )
        live_packets = read_counter_sync("OUTPUT", self._counter_comment)
        return LiveSnapshot(
            handshake_count=live_packets,
            data_transfer_ok=live_packets > 0,
            data_packets=live_packets,
        )
