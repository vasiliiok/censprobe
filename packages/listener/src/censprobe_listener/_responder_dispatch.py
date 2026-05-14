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

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from censprobe_core.models import LiveSnapshot

from censprobe_listener.credentials import ProtocolCredentials
from censprobe_listener.echo_server import EchoServer
from censprobe_listener.hysteria_wrapper import HysteriaResponder
from censprobe_listener.mtproto_orig_responder import MTProxyOrigResponder
from censprobe_listener.mtproxy_responder import MTProxyResponder
from censprobe_listener.openvpn_responder import OpenVPNResponder
from censprobe_listener.ss_responder import ShadowsocksResponder
from censprobe_listener.vless_reality_wrapper import VlessRealityResponder
from censprobe_listener.wg_responder import (
    AmneziaWGObfuscation,
    AmneziaWGResponder,
    WireGuardResponder,
)


class Responder(Protocol):
    """Duck-typed surface every responder exposes to the listener loop.

    The concrete responder classes (one per foreign tool — OpenVPN,
    WireGuard, AmneziaWG, MTProxy mtg, MTProxy original C, sing-box,
    xray, hysteria) don't share a base class because each wraps a very
    different binary, and ``SubprocessResponder`` only fits the
    sing-box / xray / hysteria family. ``MTProxyResponder`` (mtg, Go,
    fakeTLS) is reused for both ``mtproto_proxy`` and
    ``mtproto_proxy_alt`` (same wire protocol, different bind port);
    ``MTProxyOrigResponder`` (TelegramMessenger/MTProxy, C,
    obfuscated2) backs ``mtproto_orig`` separately because the binary,
    argv shape, and stdout schema all differ from mtg. Net result:
    9 protocols across 8 responder classes (the count of *responder
    classes* lags by one because of the mtg primary/alt sharing).
    This Protocol captures the read-side contract
    ``listener/main.py`` relies on so the helpers there can be typed
    without leaking ``Any``.
    """

    # @property here (instead of `connection_count: int`) so the Protocol
    # accepts both classes that store it as a regular attribute and those
    # that expose it as a read-only @property — without the decorator,
    # mypy treats the contract as "settable" and rejects the latter.
    @property
    def connection_count(self) -> int: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    # Sync (no-event-loop) snapshot for the cred-server's /snapshot
    # endpoint. Each responder reads its own live counters and
    # returns the same shape, so the cross-thread HTTP handler can
    # build a uniform JSON without dispatching by class.
    def live_snapshot(self) -> LiveSnapshot: ...


@runtime_checkable
class SelfTestCapable(Protocol):
    """Subset of the Responder contract carrying a startup self-test.

    Only :class:`MTProxyOrigResponder` implements this today (its C
    MTProxy daemon can prune all upstreams and skip subprocess launch
    at preflight, which is positive evidence of network-level Telegram
    blocking). Captured as a Protocol so the listener-main code path
    that dispatches on these fields stops using ``getattr(...)`` duck-
    typing — mypy now flags any drift between the responder
    implementation and the consumer.

    Protocol is ``runtime_checkable`` so per-protocol main-loop branches
    can do ``isinstance(responder, SelfTestCapable)`` instead of
    string-comparing protocol names.
    """

    @property
    def unavailable(self) -> bool: ...

    @property
    def upstream_alive_count(self) -> int: ...

    @property
    def upstream_total_count(self) -> int: ...


# Each factory takes (creds, echo_server) and returns a fresh, unstarted
# responder. All three VPN responders (OpenVPN/WG/AWG) now also accept
# the echo_server so they can register a tun-bound /throughput endpoint
# after their tun device is up — see EchoServer.add_tun_bind.
ResponderFactory = Callable[[ProtocolCredentials, EchoServer | None], Responder]


def _factory_openvpn(creds: ProtocolCredentials, echo: EchoServer | None) -> Responder:
    r = OpenVPNResponder(creds.openvpn_psk_pem, creds.openvpn_port)
    r.echo_server = echo
    return r


def _factory_wireguard(creds: ProtocolCredentials, echo: EchoServer | None) -> Responder:
    r = WireGuardResponder(
        creds.wg_server_private,
        creds.wg_client_public,
        creds.wg_preshared_key,
        creds.wg_port,
    )
    r.echo_server = echo
    return r


def _factory_amneziawg(creds: ProtocolCredentials, echo: EchoServer | None) -> Responder:
    r = AmneziaWGResponder(
        creds.awg_server_private,
        creds.awg_client_public,
        creds.awg_preshared_key,
        creds.awg_port,
        AmneziaWGObfuscation(
            jc=creds.awg_jc,
            jmin=creds.awg_jmin,
            jmax=creds.awg_jmax,
            s1=creds.awg_s1,
            s2=creds.awg_s2,
            h1=creds.awg_h1,
            h2=creds.awg_h2,
            h3=creds.awg_h3,
            h4=creds.awg_h4,
        ),
    )
    r.echo_server = echo
    return r


def _factory_shadowsocks(creds: ProtocolCredentials, echo: EchoServer | None) -> Responder:
    r = ShadowsocksResponder(creds.ss_password_b64, creds.ss_port, creds.ss_method)
    r.echo_server = echo
    return r


def _factory_vless_reality(creds: ProtocolCredentials, echo: EchoServer | None) -> Responder:
    r = VlessRealityResponder(
        creds.vless_uuid,
        creds.vless_pvk,
        creds.vless_pbk,
        creds.vless_short_id,
        creds.vless_server_name,
        creds.vless_port,
    )
    r.echo_server = echo
    return r


def _factory_hysteria2(creds: ProtocolCredentials, echo: EchoServer | None) -> Responder:
    r = HysteriaResponder(creds.hy2_auth, creds.hy2_obfs_password, creds.hy2_port)
    r.echo_server = echo
    return r


def _factory_mtproto_proxy(creds: ProtocolCredentials, _echo: EchoServer | None) -> Responder:
    return MTProxyResponder(creds.mtproxy_port, creds.mtproxy_secret)


def _factory_mtproto_proxy_alt(creds: ProtocolCredentials, _echo: EchoServer | None) -> Responder:
    # Same responder class as mtproto_proxy — a second mtg instance on an
    # alternate port with an independent ee-secret. Two ProtocolResult
    # rows let the dashboard compare port-443 vs alt-port verdicts and
    # tell port-keyed DPI from L7-keyed DPI apart.
    return MTProxyResponder(creds.mtproxy_alt_port, creds.mtproxy_alt_secret)


def _factory_mtproto_orig(creds: ProtocolCredentials, _echo: EchoServer | None) -> Responder:
    # The original Telegram MTProxy (C). Different binary, different argv,
    # different on-the-wire format from mtg — see mtproto_orig_responder.py.
    return MTProxyOrigResponder(creds.mtproxy_orig_port, creds.mtproxy_orig_secret)


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
    "mtproto_proxy": _factory_mtproto_proxy,
    "mtproto_proxy_alt": _factory_mtproto_proxy_alt,
    "mtproto_orig": _factory_mtproto_orig,
}
