"""
vless_reality_wrapper.py — VLESS+Reality test responder via xray-core.

Runs xray with VLESS inbound + Reality TLS. The only permitted outbound
destination is the local echo port (127.0.0.1:ECHO_PORTS['vless_reality']);
anything else is blackholed. This lets us measure both handshake success
(xray log) and data-phase success (echo server counter).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from censprobe_listener._responder_base import SubprocessResponder


class VlessRealityResponder(SubprocessResponder):
    proto_label = "vless_reality"
    tempdir_prefix = "censprobe_xray_"
    log_prefix = "[xray]"
    # xray-core logs successful inbound accepts as `accepted tcp:<host>:<port>`.
    # Bare "accepted" matched too broadly — every routing decision and
    # outbound selection contains the word — and inflated the counter to
    # 2-3× the real connection count.
    handshake_log_pattern = "accepted tcp:"

    def __init__(
        self,
        uuid: str,
        private_key: str,
        public_key: str,
        short_id: str,
        server_name: str = "apimaps.yandex.ru",
        port: int = 443,
        echo_port: int | None = None,
    ) -> None:
        super().__init__(port=port, echo_port=echo_port)
        self.uuid = uuid
        self.private_key = private_key
        self.public_key = public_key
        self.short_id = short_id
        self.server_name = server_name

    def binary_argv(self, config_path: Path) -> list[str]:
        return ["xray", "run", "-c", str(config_path)]

    def config_dict(self) -> dict[str, Any]:
        return {
            "log": {"loglevel": "info"},
            "inbounds": [
                {
                    "tag": "censprobe-vless",
                    "port": self.port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": self.uuid,
                                "flow": "xtls-rprx-vision",
                            }
                        ],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": f"{self.server_name}:443",
                            "xver": 0,
                            "serverNames": [self.server_name],
                            "privateKey": self.private_key,
                            "shortIds": [self.short_id],
                        },
                    },
                    "sniffing": {"enabled": False},
                }
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "ip": ["127.0.0.1/32"],
                        "port": str(self.echo_port),
                        "outboundTag": "direct",
                    },
                    {
                        "type": "field",
                        "inboundTag": ["censprobe-vless"],
                        "outboundTag": "block",
                    },
                ]
            },
        }
