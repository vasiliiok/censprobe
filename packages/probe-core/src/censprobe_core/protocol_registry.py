"""
protocol_registry.py — Single source of truth for the VPN protocols.

Six protocols are tested today (OpenVPN, WireGuard, AmneziaWG,
Shadowsocks, VLESS+Reality, Hysteria 2). Before this module they were
hard-coded in five places (listener factory list, client probe list,
echo-port table, scoring priority, recommendation order). This file
collapses the metadata into a single list — listener and client
register their own factory dispatch maps that key off the names here.

Adding a new protocol (e.g. MTProto-proxy, TUIC):
    1. Add a :class:`ProtocolSpec` entry below.
    2. In ``censprobe_listener``: add a responder class, register it in
       ``LISTENER_RESPONDERS`` (see _responder_dispatch.py).
    3. In ``censprobe_core.protocol_probes``: add a probe coroutine,
       register it in ``CLIENT_PROBES``.
    4. Extend ``censprobe_listener.credentials`` to populate the new
       fields in :class:`ProtocolCredentials`.
    5. Extend ``censprobe_core.credentials_reader`` so the client can
       parse them.
    Done — runner / scoring / dashboards pick the protocol up
    automatically.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolSpec:
    """Static metadata about a single VPN protocol.

    No callables here — keeps probe-core decoupled from
    ``censprobe_listener`` (which can't be imported here without a
    cycle). Concrete factories live in dispatch tables on each side.
    """

    name: str
    """Canonical identifier — flows into echo_ports, ListenerReport,
    ProtocolResult.protocol, dashboards. Lowercase, ASCII, snake_case."""

    label: str
    """Human-readable name for CLI / dashboards."""

    transport: str
    """``tcp`` or ``udp`` — used in CLI port displays."""

    default_port: int
    """Listener-side port the responder binds by default. Overridable
    via the per-test credentials object (e.g. ProtocolCredentials.ss_port).
    """

    uses_socks_echo: bool
    """True if the client probe routes data through a SOCKS proxy and
    the listener-side echo server (loopback ``echo_ports.ECHO_PORTS``).
    False for protocols that establish a tun device and verify the data
    plane via ICMP ping (OpenVPN/WG/AWG)."""


PROTOCOLS: tuple[ProtocolSpec, ...] = (
    ProtocolSpec(
        name="openvpn",
        label="OpenVPN",
        transport="udp",
        default_port=1194,
        uses_socks_echo=False,
    ),
    ProtocolSpec(
        name="wireguard",
        label="WireGuard",
        transport="udp",
        default_port=51820,
        uses_socks_echo=False,
    ),
    ProtocolSpec(
        name="amneziawg",
        label="AmneziaWG",
        transport="udp",
        default_port=51821,
        uses_socks_echo=False,
    ),
    ProtocolSpec(
        name="shadowsocks",
        label="Shadowsocks 2022",
        transport="tcp",
        default_port=8388,
        uses_socks_echo=True,
    ),
    ProtocolSpec(
        name="vless_reality",
        label="VLESS+Reality",
        transport="tcp",
        default_port=443,
        uses_socks_echo=True,
    ),
    ProtocolSpec(
        name="hysteria2",
        label="Hysteria 2",
        transport="udp",
        default_port=443,
        uses_socks_echo=True,
    ),
    ProtocolSpec(
        name="mtproto_proxy",
        label="MTProto Proxy",
        transport="tcp",
        # 9443: kept off 443 (squatted by vless_reality + hysteria2) AND
        # off 8443 (the listener's creds-server). Must match
        # ``ProtocolCredentials.mtproxy_port`` so the responder-status
        # table prints what the responder actually binds.
        default_port=9443,
        uses_socks_echo=False,
    ),
)


_BY_NAME: dict[str, ProtocolSpec] = {p.name: p for p in PROTOCOLS}


def all_protocols() -> tuple[ProtocolSpec, ...]:
    """Return every registered protocol in declaration order."""
    return PROTOCOLS


def get_protocol(name: str) -> ProtocolSpec | None:
    """Look up a protocol by canonical name, or None if unknown."""
    return _BY_NAME.get(name)


def enabled_protocols(enabled_names: list[str]) -> list[ProtocolSpec]:
    """Resolve a list of names against the registry.

    Unknown names are dropped (the caller is expected to log a warning
    — at this layer we don't know whether a missing name is a typo or
    deliberate). The returned list preserves the order of
    ``enabled_names`` so the operator can express "VLESS first" via the
    YAML order alone.
    """
    out: list[ProtocolSpec] = []
    for name in enabled_names:
        spec = _BY_NAME.get(name)
        if spec is not None:
            out.append(spec)
    return out


def known_names() -> list[str]:
    """Names of all protocols, in declaration order — for diagnostics."""
    return [p.name for p in PROTOCOLS]
