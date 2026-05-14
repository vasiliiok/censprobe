"""
echo_ports.py — Single source of truth for the listener-side echo ports.

The contract is shared between two unrelated consumers:

  * the listener's :mod:`censprobe_listener.echo_server`, which binds the
    TCP echo endpoints, and the per-protocol responder modules that
    route the only allowed outbound at one of these ports;
  * :mod:`censprobe_core.protocol_probes`, used by the client to drive a
    curl through either a local SOCKS proxy (SOCKS-routed protocols) or
    directly through the brought-up tun device (VPN protocols).

Keeping the dicts in probe-core (a dependency of both sides) closes the
silent-drift hole that an earlier two-copy layout had.
"""

from __future__ import annotations

# SOCKS-routed protocols: shadowsocks / vless_reality / hysteria2. The
# listener-side responder narrows its proxy ACL to exactly the protocol's
# echo port, so a probe that escapes the intended path is rejected at the
# tunnel rather than reaching anything resembling an open proxy. Client
# probes hit these via ``socks5h://127.0.0.1:<proxy_port>`` →
# ``http://127.0.0.1:<echo_port>/...``.
SOCKS_ECHO_PORTS: dict[str, int] = {
    "shadowsocks": 9991,
    "vless_reality": 9992,
    "hysteria2": 9993,
}

# Point-to-point VPN protocols: openvpn / wireguard / amneziawg. After
# the responder brings up its TUN device, the listener-side echo server
# additionally binds the corresponding port on the listener-side tun IP
# (see :data:`VPN_TUN_LISTENER_IPS`). The bind is gated on tun-up so the
# port never appears on a public interface — only packets routed through
# the tun reach it. Client probes hit these via a plain
# ``http://<listener_tun_ip>:<echo_port>/...`` after the tun is established.
TUN_ECHO_PORTS: dict[str, int] = {
    "openvpn": 9994,
    "wireguard": 9995,
    "amneziawg": 9996,
}

# Listener-side tun IPs the VPN responders assign to themselves. Mirrored
# in the responder modules:
#   * openvpn_responder.py:   ``ifconfig 10.200.0.1 10.200.0.2``
#   * wg_responder.py:        ``ip addr add 10.202.0.1/24 dev <iface>``
#   * wg_responder.py:        AmneziaWG ``Address = 10.201.0.1/24``
# Pinned here so the client throughput probe can target them without
# parsing responder credentials.
VPN_TUN_LISTENER_IPS: dict[str, str] = {
    "openvpn": "10.200.0.1",
    "wireguard": "10.202.0.1",
    "amneziawg": "10.201.0.1",
}

# Combined view used by consumers that don't care about the split (e.g.
# operator-facing summaries, schema generators). New code should prefer
# the split dicts to make the routing model explicit.
ECHO_PORTS: dict[str, int] = {**SOCKS_ECHO_PORTS, **TUN_ECHO_PORTS}
