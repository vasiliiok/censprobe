"""
hysteria_wrapper.py — Hysteria 2 test responder.

Runs hysteria server with salamander obfuscation. No traffic forwarding to
the outside world — the only allowed destination is the local echo port
(127.0.0.1:ECHO_PORTS['hysteria2']). Non-authenticated traffic gets a small
static 404 response rather than being proxied externally.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from censprobe_listener._responder_base import SubprocessResponder

logger = logging.getLogger(__name__)


class HysteriaResponder(SubprocessResponder):
    proto_label = "hysteria2"
    tempdir_prefix = "censprobe_hy2_"
    log_prefix = "[hysteria]"
    # Hysteria 2 emits one "client connected" line per real session. Drop
    # the secondary "authenticated" matcher: hysteria also logs auth events
    # for sub-streams within an existing session, which double-counted the
    # same client and made the connection_count meaningless.
    handshake_log_pattern = "client connected"

    def __init__(
        self,
        auth_password: str,
        obfs_password: str,
        port: int = 443,
        echo_port: int | None = None,
    ) -> None:
        super().__init__(port=port, echo_port=echo_port)
        self.auth_password = auth_password
        self.obfs_password = obfs_password
        # Populated by pre_spawn_setup so config_dict() can reference them.
        self._cert_path: Path | None = None
        self._key_path: Path | None = None
        self._acl_path: Path | None = None

    async def pre_spawn_setup(self, tmpdir: Path) -> None:
        cert_path = tmpdir / "cert.pem"
        key_path = tmpdir / "key.pem"
        await self._generate_self_signed_cert(cert_path, key_path)

        # ACL: allow ONLY echo-port on loopback; reject everything else.
        # Hysteria 2 ACL expects `action(<cidr>, <proto>/<port>)` — a bare
        # port number is NOT valid grammar and the server will refuse to
        # start. Echo server is TCP-only, so scope the rule to tcp.
        acl_path = tmpdir / "acl.txt"
        acl_path.write_text(f"direct(127.0.0.1/32, tcp/{self.echo_port})\nreject(all)\n")

        self._cert_path = cert_path
        self._key_path = key_path
        self._acl_path = acl_path

    def binary_argv(self, config_path: Path) -> list[str]:
        return ["hysteria", "server", "--config", str(config_path)]

    def config_dict(self) -> dict[str, Any]:
        # pre_spawn_setup must have run by the time the base class calls
        # this. Production ``raise`` (not ``assert``, which python -O
        # strips) so a future re-ordering surfaces loudly rather than
        # writing a config with literal "None" paths.
        if self._cert_path is None or self._key_path is None or self._acl_path is None:
            raise RuntimeError(
                "HysteriaResponder.config_dict() called before pre_spawn_setup() — "
                "cert/key/acl paths are unset"
            )
        return {
            "listen": f":{self.port}",
            "tls": {"cert": str(self._cert_path), "key": str(self._key_path)},
            "obfs": {
                "type": "salamander",
                "salamander": {"password": self.obfs_password},
            },
            "auth": {"type": "password", "password": self.auth_password},
            # 404 for unauthenticated traffic — no outbound proxying.
            "masquerade": {
                "type": "string",
                "string": {
                    "content": "Not Found",
                    "headers": {"Content-Type": "text/plain"},
                    "statusCode": 404,
                },
            },
            "acl": {"file": str(self._acl_path)},
        }

    @staticmethod
    async def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
        loop = asyncio.get_running_loop()

        def _gen() -> None:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    "7",
                    "-nodes",
                    "-subj",
                    "/CN=censprobe-test",
                ],
                check=True,
                capture_output=True,
            )

        try:
            await loop.run_in_executor(None, _gen)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"openssl cert gen failed: {e.stderr.decode(errors='replace')}"
            ) from e
        # openssl honours the process umask (typically 0o022 → 0o644 file
        # perms). The key file is short-lived but still secret while in
        # use; tighten it explicitly. The cert is public so leave as-is.
        try:
            os.chmod(key_path, 0o600)
        except OSError as e:
            logger.debug("chmod on hysteria key failed: %s", e)
