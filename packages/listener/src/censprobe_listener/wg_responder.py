"""
wg_responder.py — WireGuard / AmneziaWG test responders.

Use kernel WireGuard (via ip/wg) and amneziawg-go (via awg-quick).
Both set up a temporary interface, listen for handshake initiations,
record events, tear down interface on stop.

State snapshot is captured in stop() BEFORE teardown so
data_transfer_ok and handshake_count can be read after the interface
has been removed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import subprocess
import tempfile
from pathlib import Path

from censprobe_core.link_utils import delete_iface, rm_amneziawg_socket
from censprobe_core.models import LiveSnapshot
from censprobe_core.protocol_probes import AmneziaWGObfuscation
from censprobe_core.utils import write_secret

logger = logging.getLogger(__name__)


_WG_INTERFACE = "censwg0"


# Re-exported for back-compat with callers that imported the dataclass
# from this module before it was hoisted into probe-core. The canonical
# home is :mod:`censprobe_core.protocol_probes` so the listener responder
# and client probe share one shape.
__all__ = ["AmneziaWGObfuscation", "AmneziaWGResponder", "WireGuardResponder"]

# `wg show <iface> transfer` reports the kernel's `peer->rx_bytes` counter,
# which (linux drivers/net/wireguard/receive.c) is incremented only for
# *transport* messages (type 4). Handshake messages are accounted
# separately via `latest-handshakes` and DO NOT contribute to rx_bytes.
#
#   - empty keepalive  → message_data_len(0) = 32 bytes
#   - one IPv4 ping    → message_data_len(padded(84)) ≈ 128 bytes
#
# So the threshold must sit above a single keepalive (32) but below a
# single ping (~128) to register a single-shot `ping -c 1` probe as
# "data ok". 250 — the previous value — required ≥2 pings and caused
# false HANDSHAKE_ONLY verdicts on otherwise-working tunnels.
_MIN_ECHO_BYTES = 64


def _read_wg_transfer(interface: str, tool: str = "wg") -> tuple[int, int, int]:
    """
    Return (peer_count_with_handshake, rx_bytes, tx_bytes) from `<tool> show`.

    `<tool> show <iface> transfer`   → "<pubkey>\t<rx>\t<tx>"
    `<tool> show <iface> latest-handshakes` → "<pubkey>\t<unix_ts>"

    AmneziaWG interfaces live at /var/run/amneziawg/<iface>.sock — the
    vanilla `wg` utility only looks in /var/run/wireguard/ and will error
    out for those, silently returning zeros. Pass tool="awg" to query an
    AmneziaWG interface correctly.
    """
    try:
        out_tr = subprocess.check_output(
            [tool, "show", interface, "transfer"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        out_hs = subprocess.check_output(
            [tool, "show", interface, "latest-handshakes"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except Exception:
        return 0, 0, 0

    rx = tx = 0
    for line in out_tr.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                rx += int(parts[1])
                tx += int(parts[2])
            except ValueError:
                pass

    hs_peers = 0
    for line in out_hs.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] != "0":
            hs_peers += 1

    return hs_peers, rx, tx


class WireGuardResponder:
    """Temporary WireGuard interface for handshake + data-phase testing."""

    def __init__(
        self,
        server_private_key: str,
        client_public_key: str,
        preshared_key: str,
        port: int = 51820,
        interface: str = _WG_INTERFACE,
    ) -> None:
        self.server_private_key = server_private_key
        self.client_public_key = client_public_key
        self.preshared_key = preshared_key
        self.port = port
        self.interface = interface
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._final_hs_count: int = 0
        self._final_rx_bytes: int = 0
        self._snapshot_taken: bool = False

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_wg_")
        tmpdir = Path(self._tmpdir.name)

        # `0o600` on creation, not after — write_text(...)+chmod is a TOCTOU
        # window during which the privatekey is world-readable.
        pk_path = tmpdir / "privatekey"
        write_secret(pk_path, self.server_private_key)

        # The kernel `wg setconf` parser rejects `Address =` — that's a
        # wg-quick bash-wrapper directive, not a kernel-interface key. The
        # IP is assigned separately with `ip addr add` below.
        #
        # WG must NOT share its /24 with OpenVPN (which also runs on this
        # host in network_mode: host). Otherwise the kernel routes replies
        # for 10.200.0.2 onto OpenVPN's /32 tun peer route, producing a
        # silent blackhole for WG's own data phase.
        config = f"""[Interface]
ListenPort = {self.port}
PrivateKey = {self.server_private_key}

[Peer]
PublicKey = {self.client_public_key}
PresharedKey = {self.preshared_key}
AllowedIPs = 10.202.0.2/32
"""
        # Config has the server PrivateKey + PSK inline → must be 0o600
        # from the moment it touches disk.
        conf_path = tmpdir / f"{self.interface}.conf"
        write_secret(conf_path, config)

        loop = asyncio.get_running_loop()

        def _bring_up() -> None:
            # If a previous run crashed (OOM, SIGKILL, docker stop) the
            # interface may still exist in host netns (we run with
            # network_mode: host). Remove any stale iface before adding ours.
            delete_iface(self.interface)
            try:
                subprocess.run(
                    ["ip", "link", "add", self.interface, "type", "wireguard"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["wg", "setconf", self.interface, str(conf_path)],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["ip", "addr", "add", "10.202.0.1/24", "dev", self.interface],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(
                    ["ip", "link", "set", "up", self.interface],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"WireGuard setup failed: {e.stderr.decode(errors='replace')}"
                ) from e

        await loop.run_in_executor(None, _bring_up)
        logger.info("WireGuard responder started on UDP/%d (iface: %s)", self.port, self.interface)

    async def stop(self) -> None:
        # Snapshot peer stats BEFORE tearing the interface down.
        hs, rx, _ = _read_wg_transfer(self.interface, tool="wg")
        self._final_hs_count = hs
        self._final_rx_bytes = rx
        self._snapshot_taken = True

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, delete_iface, self.interface)

        if self._tmpdir:
            # Tempdir cleanup may race with the kernel holding the wg
            # config file open while tearing down the iface.
            with contextlib.suppress(Exception):
                self._tmpdir.cleanup()
            self._tmpdir = None

        logger.info(
            "WireGuard responder on UDP/%d stopped (handshakes=%d, rx=%d bytes)",
            self.port,
            self._final_hs_count,
            self._final_rx_bytes,
        )

    @property
    def connection_count(self) -> int:
        # After stop() the snapshot is canonical even when zero — falling
        # through to a live `wg show` of a torn-down interface returns 0
        # AND emits a noisy stderr error.
        if self._snapshot_taken:
            return self._final_hs_count
        hs, _, _ = _read_wg_transfer(self.interface, tool="wg")
        return hs

    @property
    def data_transfer_ok(self) -> bool:
        if self._snapshot_taken:
            return self._final_rx_bytes > _MIN_ECHO_BYTES
        _, rx, _ = _read_wg_transfer(self.interface, tool="wg")
        return rx > _MIN_ECHO_BYTES

    def live_snapshot(self) -> LiveSnapshot:
        """Live ``wg show`` read for the cred-server's /snapshot."""
        hs, rx, _ = _read_wg_transfer(self.interface, tool="wg")
        return LiveSnapshot(
            handshake_count=hs,
            data_transfer_ok=rx > _MIN_ECHO_BYTES,
            data_packets=None,  # WG doesn't expose a packet counter
            bytes_received=rx,
        )


class AmneziaWGResponder:
    """AmneziaWG responder using awg-quick. Identical structure, plus junk params."""

    def __init__(
        self,
        server_private_key: str,
        client_public_key: str,
        preshared_key: str,
        port: int = 51821,
        obfuscation: AmneziaWGObfuscation | None = None,
        interface: str = "censawg0",
    ) -> None:
        self.server_private_key = server_private_key
        self.client_public_key = client_public_key
        self.preshared_key = preshared_key
        self.port = port
        self.obfuscation = obfuscation if obfuscation is not None else AmneziaWGObfuscation()
        self.interface = interface
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._conf_path: Path | None = None
        self._final_hs_count: int = 0
        self._final_rx_bytes: int = 0
        self._snapshot_taken: bool = False

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_awg_")
        tmpdir = Path(self._tmpdir.name)

        o = self.obfuscation
        config = f"""[Interface]
ListenPort = {self.port}
PrivateKey = {self.server_private_key}
Address = 10.201.0.1/24
Jc = {o.jc}
Jmin = {o.jmin}
Jmax = {o.jmax}
S1 = {o.s1}
S2 = {o.s2}
H1 = {o.h1}
H2 = {o.h2}
H3 = {o.h3}
H4 = {o.h4}

[Peer]
PublicKey = {self.client_public_key}
PresharedKey = {self.preshared_key}
AllowedIPs = 10.201.0.2/32
"""
        # Inline server PrivateKey / PSK → write 0o600 from the start.
        self._conf_path = tmpdir / f"{self.interface}.conf"
        write_secret(self._conf_path, config)

        loop = asyncio.get_running_loop()

        def _start() -> None:
            # Clean up a stale interface AND its userspace control socket
            # from a previously-crashed run. awg-quick down needs the conf
            # file; ip link del works regardless. Removing the .sock file
            # is mandatory — amneziawg-go refuses to bind a fresh socket
            # when a leftover from a SIGKILLed daemon is still on disk.
            delete_iface(self.interface)
            rm_amneziawg_socket(self.interface)
            try:
                subprocess.run(
                    ["awg-quick", "up", str(self._conf_path)],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"AmneziaWG start failed: {e.stderr.decode(errors='replace')}"
                ) from e

        await loop.run_in_executor(None, _start)
        logger.info("AmneziaWG responder started on UDP/%d", self.port)

    async def stop(self) -> None:
        # Snapshot stats BEFORE teardown.
        hs, rx, _ = _read_wg_transfer(self.interface, tool="awg")
        self._final_hs_count = hs
        self._final_rx_bytes = rx
        self._snapshot_taken = True

        if self._tmpdir and self._conf_path:
            loop = asyncio.get_running_loop()

            def _stop() -> None:
                try:
                    subprocess.run(
                        ["awg-quick", "down", str(self._conf_path)],
                        capture_output=True,
                    )
                except Exception as e:
                    logger.warning("AmneziaWG stop error: %s", e)
                # Hard fallback in case awg-quick down failed (e.g. conf
                # file was never written or socket was already orphaned).
                delete_iface(self.interface)
                rm_amneziawg_socket(self.interface)

            await loop.run_in_executor(None, _stop)

            # Tempdir cleanup may race with awg-quick still holding files.
            with contextlib.suppress(Exception):
                self._tmpdir.cleanup()
            self._tmpdir = None

        logger.info(
            "AmneziaWG responder on UDP/%d stopped (handshakes=%d, rx=%d bytes)",
            self.port,
            self._final_hs_count,
            self._final_rx_bytes,
        )

    @property
    def connection_count(self) -> int:
        if self._snapshot_taken:
            return self._final_hs_count
        hs, _, _ = _read_wg_transfer(self.interface, tool="awg")
        return hs

    @property
    def data_transfer_ok(self) -> bool:
        if self._snapshot_taken:
            return self._final_rx_bytes > _MIN_ECHO_BYTES
        _, rx, _ = _read_wg_transfer(self.interface, tool="awg")
        return rx > _MIN_ECHO_BYTES

    def live_snapshot(self) -> LiveSnapshot:
        """Live ``awg show`` read for the cred-server's /snapshot.

        The Windows-Docker-Desktop false-OK regression is the whole
        reason this endpoint exists: the listener will report rx=0
        when the AWG packets never reach the host, while the client
        sees its userspace counter tick (occasionally even without
        real handshake completion). Surfacing the listener's rx_bytes
        via /snapshot lets the client-side cross-verifier turn
        client-OK + listener-rx=0 into the right verdict
        (DISPUTED/BLOCKED instead of OK).
        """
        hs, rx, _ = _read_wg_transfer(self.interface, tool="awg")
        return LiveSnapshot(
            handshake_count=hs,
            data_transfer_ok=rx > _MIN_ECHO_BYTES,
            data_packets=None,
            bytes_received=rx,
        )
