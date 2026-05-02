"""
echo_ports.py — Single source of truth for the listener-side echo ports.

The contract is shared between two unrelated consumers:

  * the listener's :mod:`censprobe_listener.echo_server`, which binds the
    TCP echo endpoints, and the SS / VLESS / Hysteria responders that
    route the only allowed direct outbound at one of these ports;
  * :mod:`censprobe_core.protocol_probes`, used by the client to drive
    a curl through a local SOCKS proxy at ``http://127.0.0.1:<port>/ping``.

Keeping the dict in probe-core (a dependency of both sides) closes the
silent-drift hole that an earlier two-copy layout had.
"""
from __future__ import annotations


# Loopback-only TCP ports the echo server listens on. The listener-side
# protocol responders narrow their ACL to exactly the protocol's port,
# so a probe that escapes the intended path is rejected at the tunnel
# rather than reaching anything resembling an open proxy.
ECHO_PORTS: dict[str, int] = {
    "shadowsocks": 9991,
    "vless_reality": 9992,
    "hysteria2": 9993,
}
