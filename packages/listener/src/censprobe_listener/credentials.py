"""
credentials.py — Generate per-test-session VPN credentials.

Generates one-time credentials for all 6 VPN protocols and writes
them to reports/<test_id>/protocols.yaml so the client container
can read them via git pull.

Credentials are single-use test keys — not production VPN credentials.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import secrets
import string
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ProtocolCredentials:
    """All credentials needed for one test session."""
    # OpenVPN: static-key PSK
    openvpn_psk_b64: str = ""
    openvpn_port: int = 1194

    # WireGuard: server keypair + client pubkey
    wg_server_private: str = ""
    wg_server_public: str = ""
    wg_client_private: str = ""
    wg_client_public: str = ""
    wg_preshared_key: str = ""
    wg_port: int = 51820

    # AmneziaWG: WG keypair + junk params
    awg_server_private: str = ""
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

    # Shadowsocks 2022
    ss_port: int = 8388
    ss_method: str = "2022-blake3-aes-256-gcm"
    ss_password_b64: str = ""

    # VLESS + Reality
    vless_port: int = 443
    vless_uuid: str = ""
    vless_pbk: str = ""           # Reality public key
    vless_pvk: str = ""           # Reality private key (server only)
    vless_short_id: str = ""      # Reality short ID
    vless_server_name: str = "apimaps.yandex.ru"   # Reality SNI

    # Hysteria 2
    hy2_port: int = 443
    hy2_auth: str = ""
    hy2_obfs_password: str = ""


def generate_credentials() -> ProtocolCredentials:
    """Generate fresh one-time credentials for all protocols."""
    creds = ProtocolCredentials()

    # OpenVPN PSK: 256 random bytes, base64 encoded
    creds.openvpn_psk_b64 = base64.b64encode(os.urandom(256)).decode()

    # WireGuard: use wg genkey/pubkey
    creds.wg_server_private, creds.wg_server_public = _wg_keypair()
    creds.wg_client_private, creds.wg_client_public = _wg_keypair()
    creds.wg_preshared_key = _wg_preshared_key()

    # AmneziaWG: same structure as WG + junk params
    creds.awg_server_private, creds.awg_server_public = _wg_keypair()
    creds.awg_client_private, creds.awg_client_public = _wg_keypair()
    creds.awg_preshared_key = _wg_preshared_key()
    # Random junk header values (32-bit)
    creds.awg_h1 = secrets.randbits(32)
    creds.awg_h2 = secrets.randbits(32)
    creds.awg_h3 = secrets.randbits(32)
    creds.awg_h4 = secrets.randbits(32)
    creds.awg_jc = secrets.randbelow(5) + 3   # 3-7 junk packets
    creds.awg_jmin = secrets.randbelow(20) + 40   # 40-59
    creds.awg_jmax = secrets.randbelow(30) + 70   # 70-99
    
    # AmneziaWG padding sizes: Randomize S1 and S2, ensure S1+56 != S2
    creds.awg_s1 = secrets.randbelow(135) + 15
    creds.awg_s2 = secrets.randbelow(135) + 15
    while creds.awg_s1 + 56 == creds.awg_s2:
        creds.awg_s2 = secrets.randbelow(135) + 15

    # Shadowsocks 2022: 32-byte password
    creds.ss_password_b64 = base64.b64encode(os.urandom(32)).decode()

    # VLESS + Reality: UUID + reality keys
    creds.vless_uuid = _generate_uuid()
    creds.vless_pvk, creds.vless_pbk = _reality_keypair()
    creds.vless_short_id = secrets.token_hex(4)  # 4 bytes = 8 hex chars

    # Hysteria 2: random auth + obfs password
    creds.hy2_auth = secrets.token_urlsafe(24)
    creds.hy2_obfs_password = secrets.token_urlsafe(20)

    return creds


def save_protocols_yaml(creds: ProtocolCredentials, path: Path) -> None:
    """Write credentials to reports/<test_id>/protocols.yaml."""
    data: dict[str, Any] = {
        "_note": "One-time test credentials. Do not use for production VPN.",
        "openvpn": {
            "port": creds.openvpn_port,
            "protocol": "udp",
            "psk_b64": creds.openvpn_psk_b64,
        },
        "wireguard": {
            "port": creds.wg_port,
            "server_public_key": creds.wg_server_public,
            "client_private_key": creds.wg_client_private,
            "client_public_key": creds.wg_client_public,
            "preshared_key": creds.wg_preshared_key,
        },
        "amneziawg": {
            "port": creds.awg_port,
            "server_public_key": creds.awg_server_public,
            "client_private_key": creds.awg_client_private,
            "client_public_key": creds.awg_client_public,
            "preshared_key": creds.awg_preshared_key,
            "jc": creds.awg_jc,
            "jmin": creds.awg_jmin,
            "jmax": creds.awg_jmax,
            "s1": creds.awg_s1,
            "s2": creds.awg_s2,
            "h1": creds.awg_h1,
            "h2": creds.awg_h2,
            "h3": creds.awg_h3,
            "h4": creds.awg_h4,
        },
        "shadowsocks": {
            "port": creds.ss_port,
            "method": creds.ss_method,
            "password_b64": creds.ss_password_b64,
        },
        "vless_reality": {
            "port": creds.vless_port,
            "uuid": creds.vless_uuid,
            "public_key": creds.vless_pbk,
            "short_id": creds.vless_short_id,
            "server_name": creds.vless_server_name,
        },
        "hysteria2": {
            "port": creds.hy2_port,
            "auth": creds.hy2_auth,
            "obfs_password": creds.hy2_obfs_password,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    logger.info("Protocols written to %s", path)


def load_protocols_yaml(path: Path) -> ProtocolCredentials:
    """Load credentials from an existing protocols.yaml."""
    raw = yaml.safe_load(path.read_text())
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
    c.awg_port = awg.get("port", 51821)
    c.awg_client_private = awg.get("client_private_key", "")
    c.awg_client_public = awg.get("client_public_key", "")
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


# ─────────────────────────────────────────────────────────────────────────────
# Key generation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _wg_keypair() -> tuple[str, str]:
    """Generate a WireGuard keypair using wg tool. Falls back to random bytes."""
    try:
        private = subprocess.check_output(["wg", "genkey"]).decode().strip()
        public = subprocess.check_output(
            ["wg", "pubkey"], input=private.encode()
        ).decode().strip()
        return private, public
    except Exception:
        # Fallback: base64-encoded random bytes (not cryptographically WG-correct, but usable for tests)
        private = base64.b64encode(os.urandom(32)).decode()
        public = base64.b64encode(os.urandom(32)).decode()
        return private, public


def _wg_preshared_key() -> str:
    """Generate a WireGuard preshared key."""
    try:
        return subprocess.check_output(["wg", "genpsk"]).decode().strip()
    except Exception:
        return base64.b64encode(os.urandom(32)).decode()


def _generate_uuid() -> str:
    """Generate a RFC 4122 UUID v4."""
    import uuid
    return str(uuid.uuid4())


def _reality_keypair() -> tuple[str, str]:
    """
    Generate an x25519 keypair for VLESS+Reality using xray x25519.
    Returns (private_key_b64, public_key_b64).
    Falls back to raw random bytes if xray not available.
    """
    try:
        out = subprocess.check_output(
            ["xray", "x25519"], stderr=subprocess.DEVNULL
        ).decode()
        # Output format:
        # Private key: <b64>
        # Public key:  <b64>
        lines = out.strip().splitlines()
        private = lines[0].split(": ", 1)[1].strip()
        public = lines[1].split(": ", 1)[1].strip()
        return private, public
    except Exception:
        # Fallback using cryptography library
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            key = X25519PrivateKey.generate()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
            private_bytes = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            public_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()
        except Exception:
            return base64.b64encode(os.urandom(32)).decode(), base64.b64encode(os.urandom(32)).decode()
