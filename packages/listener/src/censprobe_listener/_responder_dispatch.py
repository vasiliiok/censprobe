"""
_responder_dispatch.py — Listener-side mapping name → responder factory.

Sits next to the responders so the protocol registry in probe-core
stays free of listener imports (which would create a cycle —
``censprobe_listener`` already depends on probe-core).

Each factory receives the freshly-generated
:class:`ProtocolCredentials` plus the optional shared
:class:`EchoServer` and returns a started-but-not-yet-running responder
instance. The listener main loop calls ``responder.start()``.

Adding a new protocol:
    1. Implement the responder class.
    2. Register a factory here keyed by the protocol's canonical name
       (the same name used in :data:`censprobe_core.protocol_registry.PROTOCOLS`).
    3. Extend :class:`censprobe_listener.credentials.ProtocolCredentials`
       to carry the new fields.
    4. Done — the listener loop picks the new entry up automatically.
"""
from __future__ import annotations

from typing import Callable

from censprobe_listener.credentials import ProtocolCredentials
from censprobe_listener.echo_server import EchoServer
from censprobe_listener.hysteria_wrapper import HysteriaResponder
from censprobe_listener.openvpn_responder import OpenVPNResponder
from censprobe_listener.ss_responder import ShadowsocksResponder
from censprobe_listener.vless_reality_wrapper import VlessRealityResponder
from censprobe_listener.wg_responder import AmneziaWGResponder, WireGuardResponder


# Each factory takes (creds, echo_server) and returns a fresh, unstarted
# responder. ``echo_server`` is None for protocols that don't use the
# loopback echo path (OpenVPN/WG/AWG); the factory ignores the argument
# in that case.
ResponderFactory = Callable[[ProtocolCredentials, EchoServer | None], object]


def _factory_openvpn(creds: ProtocolCredentials, _echo: EchoServer | None) -> object:
    return OpenVPNResponder(creds.openvpn_psk_pem, creds.openvpn_port)


def _factory_wireguard(creds: ProtocolCredentials, _echo: EchoServer | None) -> object:
    return WireGuardResponder(
        creds.wg_server_private,
        creds.wg_client_public,
        creds.wg_preshared_key,
        creds.wg_port,
    )


def _factory_amneziawg(creds: ProtocolCredentials, _echo: EchoServer | None) -> object:
    return AmneziaWGResponder(
        creds.awg_server_private,
        creds.awg_client_public,
        creds.awg_preshared_key,
        creds.awg_port,
        creds.awg_jc, creds.awg_jmin, creds.awg_jmax,
        creds.awg_s1, creds.awg_s2,
        creds.awg_h1, creds.awg_h2, creds.awg_h3, creds.awg_h4,
    )


def _factory_shadowsocks(creds: ProtocolCredentials, echo: EchoServer | None) -> object:
    r = ShadowsocksResponder(creds.ss_password_b64, creds.ss_port, creds.ss_method)
    r.echo_server = echo
    return r


def _factory_vless_reality(creds: ProtocolCredentials, echo: EchoServer | None) -> object:
    r = VlessRealityResponder(
        creds.vless_uuid, creds.vless_pvk, creds.vless_pbk,
        creds.vless_short_id, creds.vless_server_name, creds.vless_port,
    )
    r.echo_server = echo
    return r


def _factory_hysteria2(creds: ProtocolCredentials, echo: EchoServer | None) -> object:
    r = HysteriaResponder(creds.hy2_auth, creds.hy2_obfs_password, creds.hy2_port)
    r.echo_server = echo
    return r


# Mapping is keyed by the same canonical name as
# :data:`censprobe_core.protocol_registry.PROTOCOLS`. Missing entries
# (a name in the protocol registry without a factory here) raise a
# clear KeyError at startup so a half-implemented protocol fails loud.
LISTENER_RESPONDERS: dict[str, ResponderFactory] = {
    "openvpn": _factory_openvpn,
    "wireguard": _factory_wireguard,
    "amneziawg": _factory_amneziawg,
    "shadowsocks": _factory_shadowsocks,
    "vless_reality": _factory_vless_reality,
    "hysteria2": _factory_hysteria2,
}
