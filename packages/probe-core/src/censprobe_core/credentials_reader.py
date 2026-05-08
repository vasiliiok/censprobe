"""
credentials_reader.py — Parse protocols YAML into a simple namespace.

Used by the client container to load listener-generated credentials
fetched over the one-shot HTTPS endpoint, without depending on the
censprobe_listener package.

Contract: a protocol section that is PRESENT in the YAML must carry
every operational field (port, keys, method, headers, etc.). A
protocol section that is ABSENT means "this listener didn't bring up
that protocol" — its dataclass fields stay at their zero defaults and
the client uses ``_protocols_enabled`` to skip the corresponding
probe. Silent fallbacks for missing-but-significant fields are
deliberately rejected: the listener and client deploy in lockstep
from the same compose image, so any divergence is a bug worth failing
loud at parse time rather than masking with a hardcoded default.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class ProtocolCredentials:
    """Parsed credentials YAML received from the listener cred-server.

    Every field defaults to a zero/empty sentinel ("not set in inbound
    YAML"); a real value is populated by :func:`parse_protocols_yaml`
    only for the protocol sections that were present. A section that
    IS present must carry every operational field — partial sections
    raise ``ValueError`` rather than producing a half-configured
    credential set.
    """

    # Mirrors the listener's ``censprobe.yaml::protocols.enabled`` list.
    # The client iterates this exact set so it never probes a protocol
    # the listener didn't bring up. Required in the YAML body — see
    # ``parse_protocols_yaml``. The dataclass default is an empty list
    # for the unusual case of constructing without going through the
    # parser; in production every instance comes from the YAML.
    _protocols_enabled: list[str] = field(default_factory=list)

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
    awg_jc: int = 0
    awg_jmin: int = 0
    awg_jmax: int = 0
    awg_s1: int = 0
    awg_s2: int = 0
    awg_h1: int = 0
    awg_h2: int = 0
    awg_h3: int = 0
    awg_h4: int = 0

    ss_port: int = 0
    ss_method: str = ""
    ss_password_b64: str = ""

    vless_port: int = 0
    vless_uuid: str = ""
    vless_pbk: str = ""
    vless_short_id: str = ""
    vless_server_name: str = ""

    hy2_port: int = 0
    hy2_auth: str = ""
    hy2_obfs_password: str = ""

    mtproxy_secret: str = ""
    mtproxy_port: int = 0

    mtproxy_alt_secret: str = ""
    mtproxy_alt_port: int = 0


def _required(section: dict[str, Any], proto: str, key: str) -> Any:
    """Fetch a required key from a credentials-YAML protocol section.

    Raises ``ValueError`` if the key is missing or its value is
    ``None``. The listener and client must agree on every field for
    the probe to land on the right responder with the right material;
    a stale or partial YAML body is a bug worth surfacing here rather
    than papering over with a hardcoded default that quietly misaligns
    with the responder.
    """
    if key not in section or section[key] is None:
        raise ValueError(
            f"credentials YAML missing {proto}.{key} — listener and client "
            f"versions disagree on the credentials schema"
        )
    return section[key]


def _required_str(section: dict[str, Any], proto: str, key: str) -> str:
    v = _required(section, proto, key)
    if not isinstance(v, str) or not v:
        raise ValueError(f"credentials YAML has invalid {proto}.{key}: {v!r}")
    return v


def _required_int(section: dict[str, Any], proto: str, key: str) -> int:
    v = _required(section, proto, key)
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"credentials YAML has invalid {proto}.{key}: {v!r}")
    return v


def _required_port(section: dict[str, Any], proto: str) -> int:
    port = _required_int(section, proto, "port")
    if not (1 <= port <= 65535):
        raise ValueError(f"credentials YAML has invalid {proto}.port: {port!r}")
    return port


def _parse_wireguard(c: ProtocolCredentials, wg: dict[str, Any]) -> None:
    c.wg_port = _required_port(wg, "wireguard")
    c.wg_server_public = _required_str(wg, "wireguard", "server_public_key")
    c.wg_client_private = _required_str(wg, "wireguard", "client_private_key")
    c.wg_client_public = _required_str(wg, "wireguard", "client_public_key")
    c.wg_preshared_key = _required_str(wg, "wireguard", "preshared_key")


def _parse_shadowsocks(c: ProtocolCredentials, ss: dict[str, Any]) -> None:
    c.ss_port = _required_port(ss, "shadowsocks")
    c.ss_method = _required_str(ss, "shadowsocks", "method")
    c.ss_password_b64 = _required_str(ss, "shadowsocks", "password_b64")


def _parse_vless_reality(c: ProtocolCredentials, vless: dict[str, Any]) -> None:
    c.vless_port = _required_port(vless, "vless_reality")
    c.vless_uuid = _required_str(vless, "vless_reality", "uuid")
    c.vless_pbk = _required_str(vless, "vless_reality", "public_key")
    c.vless_short_id = _required_str(vless, "vless_reality", "short_id")
    c.vless_server_name = _required_str(vless, "vless_reality", "server_name")


def _parse_hysteria2(c: ProtocolCredentials, hy2: dict[str, Any]) -> None:
    c.hy2_port = _required_port(hy2, "hysteria2")
    c.hy2_auth = _required_str(hy2, "hysteria2", "auth")
    c.hy2_obfs_password = _required_str(hy2, "hysteria2", "obfs_password")


def _parse_openvpn(c: ProtocolCredentials, ovpn: dict[str, Any]) -> None:
    c.openvpn_port = _required_port(ovpn, "openvpn")
    c.openvpn_psk_pem = _required_str(ovpn, "openvpn", "psk_pem")


def _parse_mtproto_proxy(c: ProtocolCredentials, mtp: dict[str, Any]) -> None:
    c.mtproxy_port = _required_port(mtp, "mtproto_proxy")
    c.mtproxy_secret = _required_str(mtp, "mtproto_proxy", "secret")


def _parse_mtproto_proxy_alt(c: ProtocolCredentials, mtp: dict[str, Any]) -> None:
    c.mtproxy_alt_port = _required_port(mtp, "mtproto_proxy_alt")
    c.mtproxy_alt_secret = _required_str(mtp, "mtproto_proxy_alt", "secret")


def _parse_amneziawg(c: ProtocolCredentials, awg: dict[str, Any]) -> None:
    """Populate AmneziaWG fields from the YAML section.

    Every AWG obfuscation parameter is required: H1..H4 must match the
    responder's magic-header set or the demuxer drops half the
    handshake; jc/jmin/jmax/s1/s2 govern junk-packet shape and length
    constraints (``s1+56 != s2``). A silent default here would line
    up with the responder only by accident.
    """
    c.awg_port = _required_port(awg, "amneziawg")
    c.awg_server_public = _required_str(awg, "amneziawg", "server_public_key")
    c.awg_client_private = _required_str(awg, "amneziawg", "client_private_key")
    c.awg_client_public = _required_str(awg, "amneziawg", "client_public_key")
    c.awg_preshared_key = _required_str(awg, "amneziawg", "preshared_key")
    c.awg_jc = _required_int(awg, "amneziawg", "jc")
    c.awg_jmin = _required_int(awg, "amneziawg", "jmin")
    c.awg_jmax = _required_int(awg, "amneziawg", "jmax")
    c.awg_s1 = _required_int(awg, "amneziawg", "s1")
    c.awg_s2 = _required_int(awg, "amneziawg", "s2")
    c.awg_h1 = _required_int(awg, "amneziawg", "h1")
    c.awg_h2 = _required_int(awg, "amneziawg", "h2")
    c.awg_h3 = _required_int(awg, "amneziawg", "h3")
    c.awg_h4 = _required_int(awg, "amneziawg", "h4")


def parse_protocols_yaml(text: str) -> ProtocolCredentials:
    """Parse the credentials YAML body served by the listener cred-server.

    ``_protocols_enabled`` is required: it tells the client which
    subset of probes the listener actually started. A protocol section
    listed in ``_protocols_enabled`` MUST be present in the YAML and
    carry every operational field; a section that is absent from
    ``_protocols_enabled`` may be omitted from the YAML entirely.
    """
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise ValueError("credentials YAML must be a top-level mapping")
    raw: dict[str, Any] = parsed
    c = ProtocolCredentials()

    enabled = raw.get("_protocols_enabled")
    if not isinstance(enabled, list) or not all(isinstance(x, str) for x in enabled):
        raise ValueError(
            "credentials YAML missing or malformed _protocols_enabled — listener "
            "and client versions disagree on the credentials schema"
        )
    c._protocols_enabled = list(enabled)

    parsers: list[tuple[str, Callable[[ProtocolCredentials, dict[str, Any]], None]]] = [
        ("openvpn", _parse_openvpn),
        ("wireguard", _parse_wireguard),
        ("amneziawg", _parse_amneziawg),
        ("shadowsocks", _parse_shadowsocks),
        ("vless_reality", _parse_vless_reality),
        ("hysteria2", _parse_hysteria2),
        ("mtproto_proxy", _parse_mtproto_proxy),
        ("mtproto_proxy_alt", _parse_mtproto_proxy_alt),
    ]
    for key, fn in parsers:
        if key in raw:
            section = raw[key]
            if not isinstance(section, dict):
                raise ValueError(
                    f"credentials YAML section {key!r} must be a mapping, "
                    f"got {type(section).__name__}"
                )
            fn(c, section)

    return c
