"""
_probe_dispatch.py — Client-side mapping name → probe coroutine factory.

Mirror of :mod:`censprobe_listener._responder_dispatch` for the client
side. Each entry takes ``(server_host, ProtocolCredentials)`` and
returns the coroutine that runs one probe against the listener.

Adding a new protocol:
    1. Implement an async ``probe_X`` in
       :mod:`censprobe_core.protocol_probes`.
    2. Register a factory here keyed by the same canonical name as
       :data:`censprobe_core.protocol_registry.PROTOCOLS`.
    3. Done — client picks it up automatically.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from censprobe_core.credentials_reader import ProtocolCredentials
from censprobe_core.protocol_probes import (
    AmneziaWGObfuscation,
    ProbeResult,
    probe_amneziawg,
    probe_hysteria2,
    probe_mtproto_orig,
    probe_mtproto_proxy,
    probe_openvpn,
    probe_shadowsocks,
    probe_vless_reality,
    probe_wireguard,
)

# Each factory closes over the credential subset it needs. Returning a
# coroutine — not invoking it — lets the client jitter / shuffle the
# probe order without committing to one execution sequence.
ProbeFactory = Callable[[str, ProtocolCredentials], Awaitable[ProbeResult]]


def _probe_openvpn(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_openvpn(host, creds.openvpn_port, creds.openvpn_psk_pem)


def _probe_wireguard(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_wireguard(
        host,
        creds.wg_port,
        creds.wg_server_public,
        creds.wg_preshared_key,
        creds.wg_client_private,
    )


def _probe_amneziawg(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_amneziawg(
        host,
        creds.awg_port,
        creds.awg_server_public,
        creds.awg_preshared_key,
        creds.awg_client_private,
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


def _probe_shadowsocks(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_shadowsocks(host, creds.ss_port, creds.ss_method, creds.ss_password_b64)


def _probe_vless_reality(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_vless_reality(
        host,
        creds.vless_port,
        creds.vless_uuid,
        creds.vless_pbk,
        creds.vless_short_id,
        creds.vless_server_name,
    )


def _probe_hysteria2(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_hysteria2(
        host,
        creds.hy2_port,
        creds.hy2_auth,
        creds.hy2_obfs_password,
    )


def _probe_mtproto_proxy(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_mtproto_proxy(host, creds.mtproxy_port, creds.mtproxy_secret)


def _probe_mtproto_proxy_alt(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_mtproto_proxy(host, creds.mtproxy_alt_port, creds.mtproxy_alt_secret)


def _probe_mtproto_orig(host: str, creds: ProtocolCredentials) -> Awaitable[ProbeResult]:
    return probe_mtproto_orig(host, creds.mtproxy_orig_port, creds.mtproxy_orig_secret)


CLIENT_PROBES: dict[str, ProbeFactory] = {
    "openvpn": _probe_openvpn,
    "wireguard": _probe_wireguard,
    "amneziawg": _probe_amneziawg,
    "shadowsocks": _probe_shadowsocks,
    "vless_reality": _probe_vless_reality,
    "hysteria2": _probe_hysteria2,
    "mtproto_proxy": _probe_mtproto_proxy,
    "mtproto_proxy_alt": _probe_mtproto_proxy_alt,
    "mtproto_orig": _probe_mtproto_orig,
}
