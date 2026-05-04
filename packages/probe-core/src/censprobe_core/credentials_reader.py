"""
credentials_reader.py — Parse protocols YAML into a simple namespace.

Used by the client container to load listener-generated credentials
fetched over the one-shot HTTPS endpoint, without depending on the
censprobe_listener package.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml


@dataclass
class ProtocolCredentials:
    """Parsed credentials YAML received from the listener cred-server.

    Port fields default to 0 (sentinel for "not set in inbound YAML"); a
    real value is always populated by :func:`parse_protocols_yaml` from
    the YAML body the listener serves, which itself reflects the
    listener's ``censprobe.yaml::protocols.ports``. A missing port in
    the inbound YAML raises a parse error rather than falling back to a
    historical default — the client and listener must agree on every
    bind port for the probe to hit the right responder.
    """

    # ``_protocols_enabled`` mirrors the listener's
    # ``censprobe.yaml::protocols.enabled`` list — the client uses it to
    # avoid probing a protocol the listener didn't bring up. ``None``
    # means the listener didn't advertise the field → the client falls
    # back to whichever protocol sections were present in the YAML.
    _protocols_enabled: list[str] | None = None

    openvpn_psk_pem: str = ""
    openvpn_port: int = 0

    wg_server_public: str = ""
    wg_client_private: str = ""
    wg_client_public: str = ""
    wg_preshared_key: str = ""
    wg_port: int = 0

    awg_server_public: str = ""
    awg_client_private: str = ""
    awg_client_public: str = ""
    awg_preshared_key: str = ""
    awg_port: int = 0
    awg_jc: int = 4
    awg_jmin: int = 40
    awg_jmax: int = 70
    awg_s1: int = 0
    awg_s2: int = 0
    awg_h1: int = 0
    awg_h2: int = 0
    awg_h3: int = 0
    awg_h4: int = 0

    ss_port: int = 0
    ss_method: str = "2022-blake3-aes-256-gcm"
    ss_password_b64: str = ""

    vless_port: int = 0
    vless_uuid: str = ""
    vless_pbk: str = ""
    vless_short_id: str = ""
    vless_server_name: str = "apimaps.yandex.ru"

    hy2_port: int = 0
    hy2_auth: str = ""
    hy2_obfs_password: str = ""

    mtproxy_secret: str = ""
    mtproxy_port: int = 0



def _required_port(section: dict[str, Any], proto: str) -> int:
    """Extract ``port`` from a credentials-YAML protocol section.

    A missing or non-int port is a hard error: the listener and client
    must agree on every bind port for the probe to land on the right
    responder. There are no fallback defaults — a stale or partial YAML
    body from the cred-server is a bug worth surfacing immediately.
    """
    if "port" not in section:
        raise ValueError(
            f"credentials YAML missing {proto}.port — listener and client "
            f"versions disagree on the credentials schema"
        )
    port = section["port"]
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(
            f"credentials YAML has invalid {proto}.port: {port!r}"
        )
    return port


def parse_protocols_yaml(text: str) -> ProtocolCredentials:
    """Parse the credentials YAML body served by the listener cred-server.

    A protocol section that is PRESENT in the YAML must carry a valid
    ``port`` — otherwise the listener and client disagree on the schema
    and we want that to fail loud. A protocol section that is ABSENT is
    treated as "this listener didn't bring up that protocol" — its port
    fields stay at the dataclass default of ``0`` and the client uses
    ``_protocols_enabled`` (or the explicit absence of the section) to
    skip the corresponding probe. That way an operator who sets
    ``protocols.enabled`` to a strict subset of the registry doesn't
    break credential parsing.
    """
    parsed = yaml.safe_load(text)
    raw: dict[str, Any] = parsed if isinstance(parsed, dict) else {}
    c = ProtocolCredentials()

    # Listener-advertised enabled-protocols list. Permissive parsing —
    # missing key, ``null``, non-list value → leave as None and let the
    # client fall back to "every registered protocol".
    enabled = raw.get("_protocols_enabled")
    if isinstance(enabled, list):
        c._protocols_enabled = [str(x) for x in enabled if isinstance(x, str)]

    if "openvpn" in raw:
        ovpn = raw["openvpn"] or {}
        c.openvpn_psk_pem = ovpn.get("psk_pem", "")
        c.openvpn_port = _required_port(ovpn, "openvpn")

    if "wireguard" in raw:
        wg = raw["wireguard"] or {}
        c.wg_server_public = wg.get("server_public_key", "")
        c.wg_client_private = wg.get("client_private_key", "")
        c.wg_client_public = wg.get("client_public_key", "")
        c.wg_preshared_key = wg.get("preshared_key", "")
        c.wg_port = _required_port(wg, "wireguard")

    if "amneziawg" in raw:
        awg = raw["amneziawg"] or {}
        c.awg_server_public = awg.get("server_public_key", "")
        c.awg_client_private = awg.get("client_private_key", "")
        c.awg_client_public = awg.get("client_public_key", "")
        c.awg_preshared_key = awg.get("preshared_key", "")
        c.awg_port = _required_port(awg, "amneziawg")
        c.awg_jc = awg.get("jc", 4)
        c.awg_jmin = awg.get("jmin", 40)
        c.awg_jmax = awg.get("jmax", 70)
        c.awg_s1 = awg.get("s1", 0)
        c.awg_s2 = awg.get("s2", 0)
        c.awg_h1 = awg.get("h1", 0)
        c.awg_h2 = awg.get("h2", 0)
        c.awg_h3 = awg.get("h3", 0)
        c.awg_h4 = awg.get("h4", 0)

    if "shadowsocks" in raw:
        ss = raw["shadowsocks"] or {}
        c.ss_port = _required_port(ss, "shadowsocks")
        c.ss_method = ss.get("method", "2022-blake3-aes-256-gcm")
        c.ss_password_b64 = ss.get("password_b64", "")

    if "vless_reality" in raw:
        vless = raw["vless_reality"] or {}
        c.vless_port = _required_port(vless, "vless_reality")
        c.vless_uuid = vless.get("uuid", "")
        c.vless_pbk = vless.get("public_key", "")
        c.vless_short_id = vless.get("short_id", "")
        c.vless_server_name = vless.get("server_name", "apimaps.yandex.ru")

    if "hysteria2" in raw:
        hy2 = raw["hysteria2"] or {}
        c.hy2_port = _required_port(hy2, "hysteria2")
        c.hy2_auth = hy2.get("auth", "")
        c.hy2_obfs_password = hy2.get("obfs_password", "")

    if "mtproto_proxy" in raw:
        mtp = raw["mtproto_proxy"] or {}
        c.mtproxy_secret = mtp.get("secret", "")
        c.mtproxy_port = _required_port(mtp, "mtproto_proxy")

    return c
