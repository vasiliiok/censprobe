"""
credentials_reader.py — Read protocols.yaml into a simple namespace.

Used by client container to load listener-generated credentials
without depending on censprobe_listener package.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ProtocolCredentials:
    """Loaded credentials from protocols.yaml."""
    openvpn_psk_b64: str = ""
    openvpn_port: int = 1194

    wg_server_public: str = ""
    wg_client_private: str = ""
    wg_client_public: str = ""
    wg_preshared_key: str = ""
    wg_port: int = 51820

    awg_server_public: str = ""
    awg_client_private: str = ""
    awg_client_public: str = ""
    awg_preshared_key: str = ""
    awg_port: int = 51821
    awg_jc: int = 4
    awg_jmin: int = 40
    awg_jmax: int = 70
    awg_s1: int = 0
    awg_s2: int = 0
    awg_h1: int = 0
    awg_h2: int = 0
    awg_h3: int = 0
    awg_h4: int = 0

    ss_port: int = 8388
    ss_method: str = "2022-blake3-aes-256-gcm"
    ss_password_b64: str = ""

    vless_port: int = 443
    vless_uuid: str = ""
    vless_pbk: str = ""
    vless_short_id: str = ""
    vless_server_name: str = "apimaps.yandex.ru"

    hy2_port: int = 443
    hy2_auth: str = ""
    hy2_obfs_password: str = ""


def load_protocols_yaml(path: Path) -> ProtocolCredentials:
    """Load credentials from a protocols.yaml file."""
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    c = ProtocolCredentials()

    ovpn = raw.get("openvpn", {})
    c.openvpn_psk_b64 = ovpn.get("psk_b64", "")
    c.openvpn_port = ovpn.get("port", 1194)

    wg = raw.get("wireguard", {})
    c.wg_server_public = wg.get("server_public_key", "")
    c.wg_client_private = wg.get("client_private_key", "")
    c.wg_client_public = wg.get("client_public_key", "")
    c.wg_preshared_key = wg.get("preshared_key", "")
    c.wg_port = wg.get("port", 51820)

    awg = raw.get("amneziawg", {})
    c.awg_server_public = awg.get("server_public_key", "")
    c.awg_client_private = awg.get("client_private_key", "")
    c.awg_client_public = awg.get("client_public_key", "")
    c.awg_preshared_key = awg.get("preshared_key", "")
    c.awg_port = awg.get("port", 51821)
    c.awg_jc = awg.get("jc", 4)
    c.awg_jmin = awg.get("jmin", 40)
    c.awg_jmax = awg.get("jmax", 70)
    c.awg_s1 = awg.get("s1", 0)
    c.awg_s2 = awg.get("s2", 0)
    c.awg_h1 = awg.get("h1", 0)
    c.awg_h2 = awg.get("h2", 0)
    c.awg_h3 = awg.get("h3", 0)
    c.awg_h4 = awg.get("h4", 0)

    ss = raw.get("shadowsocks", {})
    c.ss_port = ss.get("port", 8388)
    c.ss_method = ss.get("method", "2022-blake3-aes-256-gcm")
    c.ss_password_b64 = ss.get("password_b64", "")

    vless = raw.get("vless_reality", {})
    c.vless_port = vless.get("port", 443)
    c.vless_uuid = vless.get("uuid", "")
    c.vless_pbk = vless.get("public_key", "")
    c.vless_short_id = vless.get("short_id", "")
    c.vless_server_name = vless.get("server_name", "apimaps.yandex.ru")

    hy2 = raw.get("hysteria2", {})
    c.hy2_port = hy2.get("port", 443)
    c.hy2_auth = hy2.get("auth", "")
    c.hy2_obfs_password = hy2.get("obfs_password", "")

    return c
