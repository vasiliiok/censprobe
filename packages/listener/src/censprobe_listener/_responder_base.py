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

from censprobe_core._privsep import chown_tree, setpriv_available, with_privsep
from censprobe_core.echo_ports import ECHO_PORTS
from censprobe_core.models import LiveSnapshot
from censprobe_core.utils import graceful_terminate, write_secret

from censprobe_listener._iptables_counter import (
    install_counter,
    read_counter_bytes,
    remove_counter,
)

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
    # WAN-facing transport ("tcp" for SS / VLESS+Reality; "udp" for
    # Hysteria 2 = QUIC). Drives the iptables --protocol filter on the
    # throughput accounting rule installed in :meth:`start`. TCP rules
    # additionally constrain to PSH+ACK so scanner SYN-FINs don't
    # contaminate the byte counter; UDP has no equivalent flag, so the
    # filter is port-only and we rely on the responder running on a
    # dedicated port.
    transport: str = "tcp"

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
        # iptables accounting rule for wire-throughput delta sampling.
        # Installed on start() against OUTPUT --sport=<self.port>, read
        # by the echo-server's /throughput handler before and after the
        # transfer so Mbps is computed from the bytes that REALLY left
        # the listener (after tunnel encryption + WAN backpressure)
        # rather than from the loopback FIN-ACK time which collapses to
        # kernel buffer absorption on SOCKS-tunneled responders. None
        # when iptables is unavailable (no CAP_NET_ADMIN, alpine without
        # ip6tables, etc) — echo server then falls back to wait_closed.
        self._throughput_counter_comment = f"censprobe-throughput-{self.proto_label}-{self.port}"
        self._throughput_counter_installed: bool = False

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
        # Defense-in-depth: drop the tunnel binary's privileges before spawn.
        # xray/sing-box/hysteria parse network input + decode crypto frames —
        # an RCE inheriting the listener's root + NET_ADMIN bounding set
        # would otherwise escalate to host-net-mode root. setpriv drops to
        # nobody and zeroes the cap bounding set (keeping CAP_NET_BIND_SERVICE
        # only when the responder binds a privileged port). If setpriv is
        # absent (alpine / minimal image), the wrapper returns the argv
        # unchanged — same behaviour as before privsep was added.
        need_bind_service = self.port < 1024
        if setpriv_available():
            # Ensure the dropped-privilege child can read its own config and
            # any cert/key material we wrote into tmpdir. chown happens
            # AFTER write_secret so the 0o600 permissions are preserved.
            chown_tree(tmpdir)
        argv = with_privsep(argv, need_bind_service=need_bind_service)
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
        # Install the iptables byte-counter for wire-accurate throughput.
        # See _throughput_counter_comment docstring for the rationale.
        self._throughput_counter_installed = await install_counter(
            "OUTPUT",
            self._throughput_counter_rule_args(),
            self._throughput_counter_comment,
        )
        # Register the wire-throughput reader with the echo server so
        # /throughput requests for this protocol read the counter delta
        # instead of timing wait_closed on loopback. Skipped when the
        # iptables install failed (no CAP_NET_ADMIN) — echo server then
        # falls back automatically.
        if self._throughput_counter_installed and self.echo_server is not None:
            self.echo_server.register_throughput_reader(
                self.proto_label,
                self.read_throughput_bytes,
            )
        logger.info(
            "%s responder started on %d (echo: 127.0.0.1:%d) throughput-counter=%s",
            self.proto_label,
            self.port,
            self.echo_port,
            "wire" if self._throughput_counter_installed else "loopback-fallback",
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

        # Remove the throughput counter BEFORE we kill the process — the
        # rule's counters are zeroed on delete, but echo_server already
        # read them during the /throughput handler. Remove unconditionally
        # so a half-installed rule on iptables (but not ip6tables, or
        # vice versa) is still cleaned up.
        if self._throughput_counter_installed:
            await remove_counter("OUTPUT", self._throughput_counter_rule_args())
            self._throughput_counter_installed = False
        # Drop the echo-server reader registration so a subsequent
        # /throughput probe doesn't try to read a now-removed iptables
        # rule. Idempotent — no-op if no reader was registered (counter
        # install had failed at start time).
        if self.echo_server is not None:
            self.echo_server.unregister_throughput_reader(self.proto_label)

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
            "%s responder on port %d stopped (connections: %d)",
            self.proto_label,
            self.port,
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
                    # Promote handshake events to INFO so an operator
                    # reading the live console (or pasting logs to a
                    # diagnostician) sees every accepted session as it
                    # lands. The matched stdout line includes the client
                    # identity (sing-box/xray/hysteria emit `<addr>:<port>`
                    # in the same line as the marker), which is the
                    # signal future cross-verify reads against.
                    logger.info(
                        "%s handshake #%d: %s",
                        self.proto_label,
                        self.connection_count,
                        line,
                    )
        except Exception as e:
            logger.debug("%s monitor ended: %s", self.proto_label, e)

    @property
    def data_transfer_ok(self) -> bool:
        if self.echo_server is None:
            return False
        return self.echo_server.data_ok(self.proto_label)

    def _throughput_counter_rule_args(self) -> list[str]:
        """iptables match args for the WAN-side byte counter.

        TCP (SS / VLESS+Reality) — filter on ``--sport=<self.port>`` AND
        ``--tcp-flags PSH,ACK PSH,ACK`` so bare ACK/SYN/FIN/RST control
        segments and scanner SYN-FINs don't pad the byte total. The
        same filter mtg uses in :class:`mtproxy_responder.MTProxyResponder`.

        UDP (Hysteria 2 / QUIC) — filter only on ``--protocol udp
        --sport=<self.port>`` (UDP has no equivalent of PSH+ACK). The
        responder runs on a dedicated port (443) so there's no
        sibling-traffic to confuse the counter; in the rare host that
        terminates other UDP/443 on the same iface, the counter would
        over-attribute, which we accept as low cost vs the complexity
        of an L7 filter.

        No ``-j`` target — the rule is accounting-only, falling through
        to host firewall rules; see ``_iptables_counter`` module docstring.
        """
        if self.transport == "udp":
            return [
                "-p",
                "udp",
                "--sport",
                str(self.port),
                "-m",
                "comment",
                "--comment",
                self._throughput_counter_comment,
            ]
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
            self._throughput_counter_comment,
        ]

    async def read_throughput_bytes(self) -> int | None:
        """Read the current byte total from the WAN-side iptables counter.

        Returns ``None`` when no counter is installed (no CAP_NET_ADMIN,
        alpine without ip6tables, etc) — callers (echo_server) treat
        that as "no wire-side measurement available" and fall back to
        the loopback wait_closed timing. Otherwise returns the iptables
        + ip6tables sum so dual-stack clients account correctly.
        """
        if not self._throughput_counter_installed:
            return None
        return await read_counter_bytes("OUTPUT", self._throughput_counter_comment)

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
                    self.echo_server.snapshot().get(self.proto_label, {}).get("bytes", 0) or 0
                )
            except (TypeError, ValueError):
                bytes_seen = None
        return LiveSnapshot(
            handshake_count=self.connection_count,
            data_transfer_ok=self.data_transfer_ok,
            bytes_received=bytes_seen,
        )
