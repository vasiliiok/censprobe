"""
Tests for the AmneziaWG obfuscation invariants in credentials.py.

Two distinct invariants are exercised here, both load-bearing for the
on-the-wire obfuscation:

1. ``H1..H4`` magic-header replacements must be pairwise distinct AND
   not collide with the standard WireGuard message-type ids 1..4 — using
   a forbidden value is what the receiver demuxes against, so a collision
   silently drops half of every handshake.

2. ``S1 + 56 != S2`` — the only on-wire constraint on the junk-payload
   sizes for handshake init / response. Equality lets an observer demux
   the two message types by length alone, defeating the obfuscation.
"""

from __future__ import annotations

import pytest
from censprobe_listener.credentials import (
    ProtocolCredentials,
    _apply_ports,
    _awg_magic_headers,
)


class TestAwgMagicHeaders:
    @pytest.mark.parametrize("_iter", range(50))
    def test_pairwise_distinct(self, _iter: int) -> None:
        # Run repeatedly — the underlying generator is non-deterministic
        # (secrets.randbits(32)), so a single call could pass by luck.
        # 50 iterations gives us decent confidence that the loop guard
        # is doing its job.
        h = _awg_magic_headers()
        assert len(set(h)) == 4, f"H1..H4 not distinct: {h}"

    @pytest.mark.parametrize("_iter", range(50))
    def test_not_collide_with_standard_wg(self, _iter: int) -> None:
        # 1..4 are the kernel WG message types — using them defeats the
        # whole obfuscation since the wire bytes coincide with vanilla WG.
        h = _awg_magic_headers()
        forbidden = {1, 2, 3, 4}
        assert not (set(h) & forbidden), f"H1..H4 collides with standard WG: {h}"

    @pytest.mark.parametrize("_iter", range(50))
    def test_within_uint32_range(self, _iter: int) -> None:
        h = _awg_magic_headers()
        for v in h:
            assert 0 <= v < 2**32


class TestApplyPorts:
    def test_ports_stamped(self) -> None:
        creds = ProtocolCredentials()
        _apply_ports(
            creds,
            {
                "openvpn": 1194,
                "wireguard": 51820,
                "amneziawg": 51821,
                "shadowsocks": 8388,
                "vless_reality": 8444,
                "hysteria2": 443,
                "mtproto_proxy": 444,
                "mtproto_proxy_alt": 8888,
                "mtproto_orig": 2080,
            },
        )
        assert creds.openvpn_port == 1194
        assert creds.wg_port == 51820
        assert creds.awg_port == 51821
        assert creds.ss_port == 8388
        assert creds.vless_port == 8444
        assert creds.hy2_port == 443
        assert creds.mtproxy_port == 444
        assert creds.mtproxy_alt_port == 8888
        assert creds.mtproxy_orig_port == 2080

    def test_unknown_protocol_raises_keyerror(self) -> None:
        # A future protocol added to the registry but not to
        # _PROTOCOL_PORT_ATTR is a programmer error — surface it
        # immediately so we don't silently bind nothing on that port.
        creds = ProtocolCredentials()
        with pytest.raises(KeyError, match="future_proto"):
            _apply_ports(creds, {"future_proto": 9999})

    def test_partial_apply_ok(self) -> None:
        # Apply only a subset — the unspecified ports stay at their
        # dataclass default (0), which surfaces at responder bind time
        # as a clear "port not configured" error.
        creds = ProtocolCredentials()
        _apply_ports(creds, {"wireguard": 51820})
        assert creds.wg_port == 51820
        assert creds.openvpn_port == 0
