"""
ss_responder.py — Shadowsocks 2022 test responder via sing-box.

Runs sing-box with a Shadowsocks inbound (2022-blake3-aes-256-gcm).
The only allowed outbound is a local echo port (127.0.0.1:ECHO_PORTS['shadowsocks']);
any other traffic is blocked. Connection/handshake counts come from sing-box
stdout, data-phase success from the echo server's byte counter.
"""
from __future__ import annotations

from pathlib import Path

from censprobe_listener._responder_base import SubprocessResponder


class ShadowsocksResponder(SubprocessResponder):
    proto_label = "shadowsocks"
    tempdir_prefix = "censprobe_ss_"
    log_prefix = "[sing-box]"
    # sing-box settles its inbound binds quickly; the heavier xray/hysteria
    # boxes need the default 1.0 s. SS gets the shorter window so a healthy
    # listener boots faster.
    startup_settle_sec = 0.5
    # Strict matchers: a bare "accepted" substring fires on cert refresh /
    # route-decision logs and inflates the counter. sing-box logs real
    # inbound accepts as `inbound connection from <addr>` or
    # `[ss-in] inbound/shadowsocks: accepted ...`.
    handshake_log_pattern = ("inbound connection from", "accepted tcp:")

    def __init__(
        self,
        password_b64: str,
        port: int = 8388,
        method: str = "2022-blake3-aes-256-gcm",
        echo_port: int | None = None,
    ) -> None:
        super().__init__(port=port, echo_port=echo_port)
        self.password_b64 = password_b64
        self.method = method

    def binary_argv(self, config_path: Path) -> list[str]:
        return ["sing-box", "run", "-c", str(config_path)]

    def config_dict(self) -> dict:
        return {
            "log": {"level": "info", "output": "stdout", "timestamp": True},
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "censprobe-ss",
                    "listen": "::",
                    "listen_port": self.port,
                    "method": self.method,
                    "password": self.password_b64,
                    "multiplex": {"enabled": False},
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "route": {
                "final": "block",
                "rules": [
                    {
                        "ip_cidr": ["127.0.0.1/32"],
                        "port": [self.echo_port],
                        "outbound": "direct",
                    }
                ],
            },
        }
