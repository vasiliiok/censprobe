"""
Byte-shape tests for QUIC and WireGuard probe-packet builders in
``modules.cloudflare``.

Wire-shape correctness is what makes the packets *get through* the
classifying middleboxes that drop random UDP bytes. Any drift in the
fixed bytes (Long Header bit, GREASE version literal, length varint,
WG message type) silently changes verdicts to BLOCKED on every probe
run while still passing every other unit test in the module — so we
pin every fixed byte explicitly.
"""

from __future__ import annotations

from censprobe_core.modules.cloudflare import (
    _QUIC_INITIAL_MIN_SIZE,
    _build_masque_probe_packet,
    _build_quic_vn_trigger,
    _build_wg_handshake_init,
)


class TestQuicVnTrigger:
    def test_total_size_is_initial_min(self) -> None:
        # RFC 9000 §14.1 floor — Cloudflare drops shorter datagrams.
        pkt = _build_quic_vn_trigger()
        assert len(pkt) == _QUIC_INITIAL_MIN_SIZE == 1200

    def test_first_byte_is_long_header_plus_fixed_bit(self) -> None:
        # 0xc0 == 0b11000000: Long Header (bit 7) + Fixed Bit (bit 6).
        pkt = _build_quic_vn_trigger()
        assert pkt[0] == 0xC0

    def test_grease_version_at_fixed_offset(self) -> None:
        # Bytes 1..5 are the version field. The whitepaper's GREASE
        # version is the literal 0x0a0a0a0a — easy to match on a wire,
        # which is exactly what we want for a triggering Long Header.
        pkt = _build_quic_vn_trigger()
        assert pkt[1:5] == b"\x0a\x0a\x0a\x0a"

    def test_dcid_length_byte(self) -> None:
        # Byte 5 is DCID length (we use 8 bytes of randomness).
        pkt = _build_quic_vn_trigger()
        assert pkt[5] == 8

    def test_scid_length_byte_after_dcid(self) -> None:
        # Byte (5+1+8)=14 is SCID length (4 bytes of randomness).
        pkt = _build_quic_vn_trigger()
        assert pkt[14] == 4

    def test_token_length_zero(self) -> None:
        # Byte after SCID is the Initial Token Length (varint, value 0).
        pkt = _build_quic_vn_trigger()
        assert pkt[5 + 1 + 8 + 1 + 4] == 0  # one byte after SCID block

    def test_padding_to_min_size_is_zeros(self) -> None:
        # The trailing PADDING frames are all zero bytes.
        pkt = _build_quic_vn_trigger()
        # First fixed-shape header is 22 bytes; everything after must be 0x00.
        assert pkt[22:] == b"\x00" * (_QUIC_INITIAL_MIN_SIZE - 22)


class TestMasqueProbePacket:
    def test_is_alias_for_quic_vn_trigger(self) -> None:
        # The MASQUE probe reuses the QUIC VN trigger — same wire shape.
        # Both are 1200 bytes with the GREASE-version Long Header.
        m = _build_masque_probe_packet()
        q = _build_quic_vn_trigger()
        # Random fields differ between calls; assert structural parity.
        assert len(m) == len(q) == _QUIC_INITIAL_MIN_SIZE
        assert m[0] == q[0] == 0xC0
        assert m[1:5] == q[1:5] == b"\x0a\x0a\x0a\x0a"


class TestWgHandshakeInit:
    def test_total_size_is_148(self) -> None:
        # WireGuard handshake-init packet — the canonical 148-byte size
        # from the WG whitepaper §5.4.2. Different size = wrong shape =
        # immediate drop by Cloudflare WARP.
        pkt = _build_wg_handshake_init()
        assert len(pkt) == 148

    def test_message_type_byte(self) -> None:
        # Byte 0: message_type = 1 (handshake init).
        pkt = _build_wg_handshake_init()
        assert pkt[0] == 0x01

    def test_reserved_bytes_are_zero(self) -> None:
        # Bytes 1..4 — reserved, must be 0x00 per the WG whitepaper.
        pkt = _build_wg_handshake_init()
        assert pkt[1:4] == b"\x00\x00\x00"

    def test_mac2_is_zeroed(self) -> None:
        # The trailing 16 bytes are mac2; we don't supply a cookie, so
        # they must be zeros (per the WG whitepaper, mac2 is zeroed when
        # the responder hasn't sent a cookie).
        pkt = _build_wg_handshake_init()
        assert pkt[-16:] == b"\x00" * 16
