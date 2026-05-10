"""
openvpn_responder.py — OpenVPN static-key test responder.

Runs openvpn in static-key (p2p) mode.
Listens on UDP/<port>, accepts connection, records events.
Does NOT forward traffic — purely a measurement endpoint.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import tempfile
from pathlib import Path

from censprobe_core.link_utils import delete_iface
from censprobe_core.utils import write_secret

logger = logging.getLogger(__name__)


# Lower bound (inclusive) on UDP payload size for an inbound packet to
# count as "data-plane traffic" via the ``_DATA_INPUT_LENGTH_MIN`` rule.
# Empirically calibrated against censprobe's own openvpn probe on a
# clean GCP→DE path (2026-05-10): packet-size distribution on UDP/1194
# was {76 bytes: control/keepalive×11, 108 bytes: handshake×3,
# 140 bytes: ICMP-echo-through-tunnel×3 each direction}. AES-256-CBC
# block padding plus the HMAC-SHA1 footer pushes a 64-byte ICMP echo
# (8-byte ICMP header + 56-byte default payload) up to ~140 bytes on
# the wire; control / keepalive packets in static-key mode never
# exceed ~108 bytes. A 130-byte cut-off therefore separates ICMP
# echoes from any non-data flow, so the counter ticks once per real
# round-trip and stays at zero for handshake-only or idle sessions —
# even if the session is left open for hours of keepalive accumulation.
_DATA_INPUT_LENGTH_MIN = 130

# A handful of inbound data-plane packets is enough to declare the
# session "data flowed". Set to 1 because we're already filtering by
# size (only ICMP echoes / real bulk data qualify), so ``count >= 1``
# is unforgeable by keepalives or scanner traffic. Kept as a named
# constant to make the threshold semantics explicit at the call site.
_MIN_OVPN_DATA_PACKETS = 1

# Deterministic tun name so we can scrub a stale interface left behind by
# a SIGKILL — without this, a leftover tun keeps the 10.200.0.x peer route
# alive in host netns and silently blackholes the next session.
_OVPN_SRV_IFACE = "censovpn0"

# The ONLY OpenVPN status counter that proves a remote handshake (HMAC
# against our static-key PSK passed). Other counters (TCP/UDP read,
# TUN/TAP read, TCP/UDP write) all tick from scanner traffic or host-tun
# noise and would produce false-positive handshake verdicts. See
# ``OpenVPNResponder._read_status`` for the full counter taxonomy.
_AUTH_BYTES_LABEL = "Auth read bytes"


class OpenVPNResponder:
    """
    Wraps openvpn process in static-key p2p mode.
    Client connects, OpenVPN establishes tunnel, client can ping the server IP
    through the tunnel — kernel replies to ICMP on its own tun IP, which we
    observe as "TCP/UDP read bytes" > 0 in status file.
    """

    def __init__(self, psk_pem: str, port: int = 1194) -> None:
        self.psk_pem = psk_pem
        self.port = port
        self._proc: asyncio.subprocess.Process | None = None
        self._config_dir: tempfile.TemporaryDirectory[str] | None = None
        self._status_path: Path | None = None
        # Cached snapshot of connection/transfer state captured before teardown.
        self._final_handshake_count: int = 0
        self._final_bytes_received: int = 0
        self._final_data_packets: int = 0
        self._snapshot_taken: bool = False
        # Comment that identifies our iptables INPUT counter rule. Per-port
        # so multiple OpenVPN responders on the same host don't collide.
        self._counter_comment = f"censprobe-ovpn-data-{self.port}"

    async def start(self) -> None:
        """Write config files and launch openvpn subprocess."""
        self._config_dir = tempfile.TemporaryDirectory(prefix="censprobe_ovpn_")
        tmpdir = Path(self._config_dir.name)

        # Write PSK file in OpenVPN "Static key V1" PEM format. Create
        # with mode 0o600 atomically to close the TOCTOU window that
        # `write_text` + `chmod` would leave open.
        psk_path = tmpdir / "static.key"
        write_secret(psk_path, self.psk_pem)

        # Status/log files colocated with config (never shared across instances).
        self._status_path = tmpdir / "status.log"
        log_path = tmpdir / "openvpn.log"

        # Pre-clean any leftover tun device from a crashed previous run —
        # `dev <name>` makes OpenVPN refuse to start if the interface is
        # already present, so we must drop it first.
        await asyncio.get_running_loop().run_in_executor(None, delete_iface, _OVPN_SRV_IFACE)

        # AEAD ciphers (GCM / ChaCha20-Poly1305) require TLS mode; in
        # static-key / `secret` mode OpenVPN 2.4+ refuses them with
        # "AEAD cipher options --cipher is not allowed in --secret mode".
        # Use AES-256-CBC instead — the only realistic option for p2p PSK.
        config = f"""
proto udp
port {self.port}
dev {_OVPN_SRV_IFACE}
dev-type tun
secret {psk_path}
ifconfig 10.200.0.1 10.200.0.2
keepalive 10 60
cipher AES-256-CBC
persist-key
persist-tun
status {self._status_path} 5
log-append {log_path}
verb 1
"""
        conf_path = tmpdir / "server.conf"
        conf_path.write_text(config)

        # Async subprocess (S7487) — keeps the event loop responsive while
        # OpenVPN is starting and gives us awaitable wait()/returncode.
        self._proc = await asyncio.create_subprocess_exec(
            "openvpn",
            "--config",
            str(conf_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # Give it a moment to start
        await asyncio.sleep(1.0)
        if self._proc.returncode is not None:
            tail = log_path.read_text(errors="replace") if log_path.exists() else "<no log>"
            raise RuntimeError(f"OpenVPN failed to start:\n{tail[-2000:]}")
        logger.info("OpenVPN responder started on UDP/%d (iface: %s)", self.port, _OVPN_SRV_IFACE)
        await self._counter_install()

    def _read_status(self) -> tuple[int, int]:
        """Parse status file → (handshake_observed, tunnel_bytes).

        OpenVPN's P2P status file emits four byte counters; only ONE of
        them is a reliable handshake signal on a public-internet
        listener:

        * ``TCP/UDP read bytes``  — every UDP byte hit the listening
          socket, *including HMAC-failed garbage*. Increments on
          Shodan/Censys/DPI probes. Useless for handshake detection.
        * ``TUN/TAP read bytes``  — bytes the OpenVPN process read
          *from the tun device* (kernel → openvpn). On a host with
          ``network_mode: host`` and the tun's ptp peer-route up, the
          host kernel routinely shoves multicast/NDP/ICMP into the
          tun even with no peer connected. Observed in the wild as
          192 bytes of pure host noise after a 25-second idle session.
          This counter does NOT prove a remote client did anything.
        * ``TCP/UDP write bytes`` — bytes openvpn sent BACK to a peer.
          Only ticks after a peer is established, but counts our own
          retransmits/keepalives. Auth-gated transitively.
        * ``Auth read bytes``     — bytes that passed HMAC validation
          against the static-key PSK. THE ONLY counter a remote
          attacker without our PSK cannot move. This is the canonical
          and *exclusive* handshake signal.

        Returns ``(handshake_observed, tunnel_bytes)`` where both
        derive from ``Auth read bytes`` — the only counter immune to
        scanner noise (``TCP/UDP read``) and host-side tun noise
        (``TUN/TAP read``).
        """
        counters = self._parse_status_counters()
        if counters is None:
            return 0, 0

        auth_bytes = counters.get(_AUTH_BYTES_LABEL, 0)
        # Diagnostic only — surfaces *why* Auth was 0 on a session that
        # nominally "saw traffic". Logged at debug to keep stop-line
        # output clean during normal operation.
        if auth_bytes == 0 and any(
            counters.get(k, 0) > 0 for k in counters if k != _AUTH_BYTES_LABEL
        ):
            logger.debug(
                "openvpn idle session had non-auth counters: %s — host/scanner noise, not a peer",
                counters,
            )
        handshake = 1 if auth_bytes > 0 else 0
        return handshake, auth_bytes

    def _parse_status_counters(self) -> dict[str, int] | None:
        """Extract the four byte counters from the OpenVPN status file.

        Returns ``None`` when the file is unreadable (responder not yet
        started, status not yet written, transient I/O error). Returns
        a (possibly empty) dict mapping counter label → bytes otherwise.

        Split out from ``_read_status`` so the parsing loop and the
        verdict logic each stay below the cognitive-complexity ceiling.
        """
        if not self._status_path or not self._status_path.exists():
            return None
        try:
            content = self._status_path.read_text(errors="replace")
        except OSError:
            return None

        # Pull each counter independently. We track the noise-prone
        # counters too so they appear in the diagnostic logger when
        # operators investigate, but they NEVER affect the verdict.
        targets = (
            _AUTH_BYTES_LABEL,
            "TUN/TAP read bytes",
            "TCP/UDP read bytes",
            "TCP/UDP write bytes",
        )
        counters: dict[str, int] = {}
        for line in content.splitlines():
            for label in targets:
                if line.startswith(label + ","):
                    parts = line.split(",", 1)
                    if len(parts) == 2:
                        with contextlib.suppress(ValueError):
                            counters[label] = int(parts[1].strip())
                    break
        return counters

    async def stop(self) -> None:
        """Capture final state, then terminate openvpn and cleanup."""
        # Capture status BEFORE teardown so data_transfer_ok is observable.
        self._final_handshake_count, self._final_bytes_received = self._read_status()
        # Read the iptables data-packet counter while the rule is still
        # in place (``_counter_remove`` resets the counter to 0).
        self._final_data_packets = await self._counter_read()
        await self._counter_remove()
        self._snapshot_taken = True

        if self._proc:
            try:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.terminate()
                await asyncio.sleep(0.5)
                if self._proc.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        self._proc.kill()
                # Wait so the process is reaped — otherwise it lingers as a
                # zombie until our own exit. wait() can race with kill().
                with contextlib.suppress(Exception):
                    await self._proc.wait()
            except Exception as e:
                logger.warning("OpenVPN stop error: %s", e)
            self._proc = None

        # Belt-and-braces tun removal: openvpn normally cleans up its own
        # tun on graceful exit, but if we had to SIGKILL it the device
        # leaks and would block the next start().
        await asyncio.get_running_loop().run_in_executor(None, delete_iface, _OVPN_SRV_IFACE)

        if self._config_dir:
            # Tempdir cleanup races with the child holding files open
            # during a SIGKILL — OS will reap it on next reboot anyway.
            with contextlib.suppress(Exception):
                self._config_dir.cleanup()
            self._config_dir = None

        logger.info(
            "OpenVPN responder stopped (handshakes: %d, bytes: %d, data_pkts: %d)",
            self._final_handshake_count,
            self._final_bytes_received,
            self._final_data_packets,
        )

    @property
    def connection_count(self) -> int:
        """Handshake count snapshot (falls back to live read while running)."""
        if self._snapshot_taken:
            return self._final_handshake_count
        hs, _ = self._read_status()
        return hs

    async def _counter_install(self) -> None:
        """Install an INPUT rule that counts inbound UDP packets to
        ``self.port`` whose UDP datagram is at least
        ``_DATA_INPUT_LENGTH_MIN`` bytes — i.e. larger than any
        handshake control or keepalive packet observed in static-key
        mode (see calibration note on ``_DATA_INPUT_LENGTH_MIN``).

        The rule has no ``-j`` target; it only matches and ticks the
        counter, then falls through to subsequent INPUT rules. We
        deliberately avoid ``-j ACCEPT`` because that would short-
        circuit any user-installed firewall on the same port. If
        CAP_NET_ADMIN is missing or iptables is not on PATH, the
        whole helper short-circuits and ``data_transfer_ok`` falls
        back to the old auth-read-byte heuristic — see that property's
        docstring for why this regression-equivalent behaviour is
        acceptable.
        """
        if shutil.which("iptables") is None:
            return
        rule_args = self._counter_rule_args()
        check = await asyncio.create_subprocess_exec(
            "iptables",
            "-C",
            "INPUT",
            *rule_args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        if await check.wait() == 0:
            return
        add = await asyncio.create_subprocess_exec(
            "iptables",
            "-A",
            "INPUT",
            *rule_args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await add.wait()
        if rc != 0:
            logger.warning(
                "openvpn: iptables data-counter install failed (rc=%d) — "
                "data_transfer_ok will fall back to auth-read heuristic",
                rc,
            )

    async def _counter_read(self) -> int:
        if shutil.which("iptables") is None:
            return 0
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            "-L",
            "INPUT",
            "-v",
            "-n",
            "-x",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out_b, _ = await proc.communicate()
        for ln in out_b.decode(errors="replace").splitlines():
            if self._counter_comment not in ln:
                continue
            parts = ln.split()
            if not parts:
                continue
            try:
                return int(parts[0])
            except ValueError:
                return 0
        return 0

    async def _counter_remove(self) -> None:
        if shutil.which("iptables") is None:
            return
        rule_args = self._counter_rule_args()
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            "-D",
            "INPUT",
            *rule_args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()

    def _counter_rule_args(self) -> list[str]:
        # ``-m length`` matches against IP+TCP/UDP total length. Our
        # _DATA_INPUT_LENGTH_MIN is calibrated against the *UDP datagram*
        # length (header + payload, 8 + N), and the iptables ``length``
        # match operates on the same ip-pkt total — verified by inspection
        # of the actual rule (the post-install LIST shows the exact
        # numeric range), so the calibration constant maps 1:1.
        return [
            "-p",
            "udp",
            "--dport",
            str(self.port),
            "-m",
            "length",
            "--length",
            f"{_DATA_INPUT_LENGTH_MIN}:",
            "-m",
            "comment",
            "--comment",
            self._counter_comment,
        ]

    @property
    def data_transfer_ok(self) -> bool:
        """True when at least one large UDP packet (≥ ``_DATA_INPUT_LENGTH_MIN``)
        arrived from a client.

        Earlier iterations gated this on the ``Auth read bytes`` counter
        from openvpn's status file vs a static byte threshold. That
        counter conflates handshake control + keepalive overhead with
        real data plane and the only sound threshold (≥ 1500 bytes
        after a 3-min idle session) was too high to fire on the short
        (≤ 30 s) probe sessions censprobe actually generates — every
        run produced a HANDSHAKE_ONLY listener verdict in disagreement
        with the client's OK, even on an unobstructed path.

        The new mechanism is an INPUT iptables rule that counts only
        UDP packets the client sent that are *bigger* than any
        keepalive / handshake packet observed on UDP/1194 in static-
        key mode (≤ 108 B). Empirically calibrated against ICMP
        echoes through the tunnel (~140 B encrypted), so a single
        successful echo round-trip ticks the counter once and the
        property flips to True. Idle sessions with only keepalives
        and scanner noise stay at 0. CAP_NET_ADMIN is required to
        install the rule; on hosts without it the property reverts
        to its previous semantics, gating on the auth-read counter
        with the high threshold (kept exactly to avoid regressing
        the false-OK rejection on those hosts).
        """
        if self._snapshot_taken:
            if self._final_data_packets >= _MIN_OVPN_DATA_PACKETS:
                return True
            # Fallback path for hosts where iptables is unavailable
            # (alpine, macOS dev box, no CAP_NET_ADMIN). Apply the old
            # high-threshold check so we still flag long, data-rich
            # sessions even without the iptables counter.
            return self._final_bytes_received > 1500
        # Live-read path for diagnostic purposes (no snapshot yet); use
        # the auth-read fallback because we can't read iptables counters
        # without the comment match being installed.
        _, b = self._read_status()
        return b > 1500
