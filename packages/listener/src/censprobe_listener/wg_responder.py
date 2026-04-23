"""
wg_responder.py — WireGuard test responder.

Uses wireguard-go (userspace WireGuard) or kernel WireGuard (via ip/wg).
Sets up a temporary WireGuard interface, listens for handshake initiations,
records events, tears down interface on stop.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_WG_INTERFACE = "censwg0"


class WireGuardResponder:
    """
    Brings up a temporary WireGuard interface for handshake testing.
    """

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

    async def start(self) -> None:
        """Configure and bring up WireGuard interface."""
        self._tmpdir = tempfile.TemporaryDirectory(prefix="censprobe_wg_")
        tmpdir = Path(self._tmpdir.name)

        # Write private key to file
        pk_path = tmpdir / "privatekey"
        pk_path.write_text(self.server_private_key)
        pk_path.chmod(0o600)

        # Write wg config
        config = f"""[Interface]
ListenPort = {self.port}
PrivateKey = {self.server_private_key}
Address = 10.200.0.1/24

[Peer]
PublicKey = {self.client_public_key}
PresharedKey = {self.preshared_key}
AllowedIPs = 0.0.0.0/0
"""
        conf_path = tmpdir / f"{self.interface}.conf"
        conf_path.write_text(config)
        conf_path.chmod(0o600)

        loop = asyncio.get_running_loop()

        def _bring_up():
            # Create interface using wg-quick or ip + wg setconf
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
                    ["ip", "link", "set", "up", self.interface],
                    check=True, capture_output=True,
                )
                subprocess.run(
                    ["ip", "addr", "add", "10.200.0.1/24", "dev", self.interface],
                    check=False, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"WireGuard setup failed: {e.stderr.decode(errors='replace')}"
                )

        await loop.run_in_executor(None, _bring_up)
        logger.info("WireGuard responder started on UDP/%d (iface: %s)", self.port, self.interface)

    async def stop(self) -> None:
        """Bring down WireGuard interface."""
        loop = asyncio.get_running_loop()

        def _tear_down():
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

        logger.info("WireGuard responder stopped")

    @property
    def connection_count(self) -> int:
        """Dynamically check wg show for handshakes."""
        try:
            out = subprocess.check_output(["wg", "show", self.interface, "latest-handshakes"], text=True)
            count = 0
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "0":
                    count += 1
            return count
        except Exception:
            return 0


class AmneziaWGResponder:
    """
    AmneziaWG responder using amneziawg-go binary.
    Identical structure to WireGuard but with junk packet parameters.
    """

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
        self.jc = jc
        self.jmin = jmin
        self.jmax = jmax
        self.s1 = s1
        self.s2 = s2
        self.h1 = h1
        self.h2 = h2
        self.h3 = h3
        self.h4 = h4
        self.interface = interface
        self._proc: subprocess.Popen | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None

    async def start(self) -> None:
        """Start amneziawg-go process."""
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
AllowedIPs = 0.0.0.0/0
"""
        conf_path = tmpdir / f"{self.interface}.conf"
        conf_path.write_text(config)
        conf_path.chmod(0o600)

        loop = asyncio.get_running_loop()

        def _start():
            try:
                subprocess.run(
                    ["awg-quick", "up", str(conf_path)],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                # Fallback: try wg-quick (some distributions bundle awg as wg)
                raise RuntimeError(
                    f"AmneziaWG start failed: {e.stderr.decode(errors='replace')}"
                )

        await loop.run_in_executor(None, _start)
        logger.info("AmneziaWG responder started on UDP/%d", self.port)

    async def stop(self) -> None:
        if self._tmpdir:
            tmpdir = Path(self._tmpdir.name)
            conf_path = tmpdir / f"{self.interface}.conf"
            loop = asyncio.get_running_loop()

            def _stop():
                try:
                    subprocess.run(["awg-quick", "down", str(conf_path)], capture_output=True)
                except Exception as e:
                    logger.warning("AmneziaWG stop error: %s", e)

            await loop.run_in_executor(None, _stop)

            try:
                self._tmpdir.cleanup()
            except Exception:
                pass
            self._tmpdir = None

        logger.info("AmneziaWG responder stopped")

    @property
    def connection_count(self) -> int:
        """Dynamically check wg show for handshakes."""
        try:
            out = subprocess.check_output(["wg", "show", self.interface, "latest-handshakes"], text=True)
            count = 0
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "0":
                    count += 1
            return count
        except Exception:
            return 0
