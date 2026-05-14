"""
protocol_registry.py — Single source of truth for the VPN protocols.

Today's lineup is OpenVPN, WireGuard, AmneziaWG, Shadowsocks 2022,
VLESS+Reality, Hysteria 2, MTProto-proxy on its primary port and an
``mtproto_proxy_alt`` sibling on a non-443 port (port-keyed-vs-L7-keyed
DPI A/B; see ``censprobe.yaml`` for the rationale). Before this module
the same names were hard-coded in five places (listener factory list,
client probe list, echo-port table, scoring priority, recommendation
order). The registry collapses that metadata into one list — listener
and client register their own factory dispatch maps that key off the
names here.

Adding a new protocol (e.g. TUIC):
    1. Add a :class:`ProtocolSpec` entry below.
    2. In ``censprobe_listener``: add a responder class, register it in
       ``LISTENER_RESPONDERS`` (see _responder_dispatch.py).
    3. In ``censprobe_core.protocol_probes``: add a probe coroutine,
       register it in ``CLIENT_PROBES``.
    4. Extend ``censprobe_listener.credentials`` to populate the new
       fields in :class:`ProtocolCredentials`.
    Done — runner / scoring / dashboards pick the protocol up
    automatically. Operator MUST also add the protocol to
    ``protocols.enabled`` + ``protocols.ports`` in censprobe.yaml; the
    config validator rejects missing entries at startup.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ProtocolSpec:
    """Static metadata about a single VPN protocol.

    No callables here — keeps probe-core decoupled from
    ``censprobe_listener`` (which can't be imported here without a
    cycle). Concrete factories live in dispatch tables on each side.

    No bind port here either: the operator's censprobe.yaml is the
    single source of truth for ports, and the config validator
    (:meth:`ProtocolsConfig._check_ports_cover_enabled`) refuses to
    start without a port for every enabled protocol. Previously this
    spec carried a ``default_port`` that was used as a fallback in
    one place (the listener's pre-flight UDP NOTRACK helper) and
    documented as a fallback in two more — meaning a registry-default
    drift from yaml (mtproto_proxy went 9443 → 443 in yaml; the
    registry default never moved) created a silent mismatch. The
    field was removed in the 2026-05-14 audit.
    """

    name: str
    """Canonical identifier — flows into echo_ports, ListenerReport,
    ProtocolResult.protocol, dashboards. Lowercase, ASCII, snake_case."""

    label: str
    """Human-readable name for CLI / dashboards."""

    transport: Literal["tcp", "udp"]
    """``tcp`` or ``udp`` — used in CLI port displays. Typed as Literal
    so a typo (``"upd"``) fails type-check rather than silently being
    accepted as a free-form string."""

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
        uses_socks_echo=False,
    ),
    ProtocolSpec(
        name="wireguard",
        label="WireGuard",
        transport="udp",
        uses_socks_echo=False,
    ),
    ProtocolSpec(
        name="amneziawg",
        label="AmneziaWG",
        transport="udp",
        uses_socks_echo=False,
    ),
    ProtocolSpec(
        name="shadowsocks",
        label="Shadowsocks 2022",
        transport="tcp",
        uses_socks_echo=True,
    ),
    ProtocolSpec(
        name="vless_reality",
        label="VLESS+Reality",
        transport="tcp",
        uses_socks_echo=True,
    ),
    ProtocolSpec(
        name="hysteria2",
        label="Hysteria 2",
        transport="udp",
        uses_socks_echo=True,
    ),
    ProtocolSpec(
        name="mtproto_proxy",
        label="MTProto Proxy",
        transport="tcp",
        uses_socks_echo=False,
    ),
    # Sibling of mtproto_proxy on a non-443 port. Same protocol/responder,
    # different bind. Lets a single test distinguish port-keyed DPI ("TSPU
    # only inspects fakeTLS on TCP/443") from L7-keyed DPI ("TSPU drops
    # fakeTLS on any TCP"). 8888 is a common port for public Telegram
    # MTProto proxies — chosen for realism, not arbitrarily.
    ProtocolSpec(
        name="mtproto_proxy_alt",
        label="MTProto Proxy (alt port)",
        transport="tcp",
        uses_socks_echo=False,
    ),
    # Original Telegram MTProxy (TelegramMessenger/MTProxy, written in C).
    # Speaks legacy obfuscated2 — no fakeTLS camouflage. Co-runs with the
    # mtg fakeTLS siblings above to give a fakeTLS-vs-obfuscated2 A/B in
    # one session: if mtg variants get BLOCKED while this one passes,
    # the censor's DPI is fakeTLS-fingerprint-keyed (mtg-specific) rather
    # than keyed on the underlying MTProto pattern.
    ProtocolSpec(
        name="mtproto_orig",
        label="MTProto Proxy (original C)",
        transport="tcp",
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

    Names not in the registry are dropped silently here — the config
    validator (:meth:`ProtocolsConfig._check_ports_cover_enabled`)
    already raises on unknown names at startup, so by the time this
    function runs every name in ``enabled_names`` is guaranteed to
    resolve. The defensive filter remains for non-config callers
    (ad-hoc test fixtures, future tooling). The returned list
    preserves the order of ``enabled_names`` so the operator's yaml
    order is honoured.
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
