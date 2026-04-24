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
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_WG_INTERFACE = "censwg0"

# A pure WireGuard handshake (initiation 148 + response 92 bytes) already
# pushes rx well above any small constant. To distinguish "handshake only"
# from "handshake + real data", require rx to exceed the worst-case
# handshake-plus-keepalive budget (~148 + a few 32-byte keepalives).
_MIN_ECHO_BYTES = 250


def _read_wg_transfer(interface: str) -> tuple[int, int, int]:
    """
    Return (peer_count_with_handshake, rx_bytes, tx_bytes) from `wg show`.

    `wg show <iface> transfer`   → "<pubkey>\t<rx>\t<tx>"
    `wg show <iface> latest-handshakes` → "<pubkey>\t<unix_ts>"
    """
    try:
        out_tr = subprocess.check_output(
            ["wg", "show", interface, "transfer"], text=True, stderr=subprocess.DEVNULL
        )
        out_hs = subprocess.check_output(
            ["wg", "show", interface, "latest-handshakes"], text=True, stderr=subprocess.DEVNULL
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
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._final_hs_count: int = 0
        self._final_rx_bytes: int = 0

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_wg_")
        tmpdir = Path(self._tmpdir.name)

        pk_path = tmpdir / "privatekey"
        pk_path.write_text(self.server_private_key)
        pk_path.chmod(0o600)

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
        conf_path = tmpdir / f"{self.interface}.conf"
        conf_path.write_text(config)
        conf_path.chmod(0o600)

        loop = asyncio.get_running_loop()

        def _bring_up() -> None:
            # If a previous run crashed (OOM, SIGKILL, docker stop) the
            # interface may still exist in host netns (we run with
            # network_mode: host). Remove any stale iface before adding ours.
            subprocess.run(
                ["ip", "link", "del", self.interface],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=False,
            )
            try:
                subprocess.run(
                    ["ip", "link", "add", self.interface, "type", "wireguard"],
                    check=True, capture_output=True,
                )
                subprocess.run(
                    ["wg", "setconf", self.interface, str(conf_path)],
                    check=True, capture_output=True,
                )
                subprocess.run(
                    ["ip", "addr", "add", "10.202.0.1/24", "dev", self.interface],
                    check=False, capture_output=True,
                )
                subprocess.run(
                    ["ip", "link", "set", "up", self.interface],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"WireGuard setup failed: {e.stderr.decode(errors='replace')}"
                )

        await loop.run_in_executor(None, _bring_up)
        logger.info("WireGuard responder started on UDP/%d (iface: %s)", self.port, self.interface)

    async def stop(self) -> None:
        # Snapshot peer stats BEFORE tearing the interface down.
        hs, rx, _ = _read_wg_transfer(self.interface)
        self._final_hs_count = hs
        self._final_rx_bytes = rx

        loop = asyncio.get_running_loop()

        def _tear_down() -> None:
            try:
                subprocess.run(
                    ["ip", "link", "del", self.interface],
                    capture_output=True,
                )
            except Exception as e:
                logger.warning("WireGuard teardown error: %s", e)

        await loop.run_in_executor(None, _tear_down)

        if self._tmpdir:
            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

        logger.info(
            "WireGuard responder stopped (handshakes=%d, rx=%d bytes)",
            self._final_hs_count, self._final_rx_bytes,
        )

    @property
    def connection_count(self) -> int:
        if self._final_hs_count:
            return self._final_hs_count
        hs, _, _ = _read_wg_transfer(self.interface)
        return hs

    @property
    def data_transfer_ok(self) -> bool:
        if self._final_rx_bytes:
            return self._final_rx_bytes > _MIN_ECHO_BYTES
        _, rx, _ = _read_wg_transfer(self.interface)
        return rx > _MIN_ECHO_BYTES


class AmneziaWGResponder:
    """AmneziaWG responder using awg-quick. Identical structure, plus junk params."""

    def __init__(
        self,
        server_private_key: str,
        client_public_key: str,
        preshared_key: str,
        port: int = 51821,
        jc: int = 4,
        jmin: int = 40,
        jmax: int = 70,
        s1: int = 0,
        s2: int = 0,
        h1: int = 0,
        h2: int = 0,
        h3: int = 0,
        h4: int = 0,
        interface: str = "censawg0",
    ) -> None:
        self.server_private_key = server_private_key
        self.client_public_key = client_public_key
        self.preshared_key = preshared_key
        self.port = port
        self.jc, self.jmin, self.jmax = jc, jmin, jmax
        self.s1, self.s2 = s1, s2
        self.h1, self.h2, self.h3, self.h4 = h1, h2, h3, h4
        self.interface = interface
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._conf_path: Path | None = None
        self._final_hs_count: int = 0
        self._final_rx_bytes: int = 0

    async def start(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_awg_")
        tmpdir = Path(self._tmpdir.name)

        config = f"""[Interface]
ListenPort = {self.port}
PrivateKey = {self.server_private_key}
Address = 10.201.0.1/24
Jc = {self.jc}
Jmin = {self.jmin}
Jmax = {self.jmax}
S1 = {self.s1}
S2 = {self.s2}
H1 = {self.h1}
H2 = {self.h2}
H3 = {self.h3}
H4 = {self.h4}

[Peer]
PublicKey = {self.client_public_key}
PresharedKey = {self.preshared_key}
AllowedIPs = 10.201.0.2/32
"""
        self._conf_path = tmpdir / f"{self.interface}.conf"
        self._conf_path.write_text(config)
        self._conf_path.chmod(0o600)

        loop = asyncio.get_running_loop()

        def _start() -> None:
            # Clean up a stale interface from a previously-crashed run.
            # awg-quick down needs the conf file; ip link del works regardless.
            subprocess.run(
                ["ip", "link", "del", self.interface],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=False,
            )
            try:
                subprocess.run(
                    ["awg-quick", "up", str(self._conf_path)],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"AmneziaWG start failed: {e.stderr.decode(errors='replace')}"
                )

        await loop.run_in_executor(None, _start)
        logger.info("AmneziaWG responder started on UDP/%d", self.port)

    async def stop(self) -> None:
        # Snapshot stats BEFORE teardown.
        hs, rx, _ = _read_wg_transfer(self.interface)
        self._final_hs_count = hs
        self._final_rx_bytes = rx

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

            await loop.run_in_executor(None, _stop)

            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

        logger.info(
            "AmneziaWG responder stopped (handshakes=%d, rx=%d bytes)",
            self._final_hs_count, self._final_rx_bytes,
        )

    @property
    def connection_count(self) -> int:
        if self._final_hs_count:
            return self._final_hs_count
        hs, _, _ = _read_wg_transfer(self.interface)
        return hs

    @property
    def data_transfer_ok(self) -> bool:
        if self._final_rx_bytes:
            return self._final_rx_bytes > _MIN_ECHO_BYTES
        _, rx, _ = _read_wg_transfer(self.interface)
        return rx > _MIN_ECHO_BYTES
