"""
Tests for two cross-protocol helpers in
``censprobe_core.protocol_probes`` whose verdicts the listener
dashboard consumes verbatim:

1. ``_classify_proxy_outcome`` — turns proxy_echo's terse
   (status, log_text) into the (handshake_ok, is_real_handshake_only)
   pair the SOCKS-routed probes (Shadowsocks, VLESS+Reality, Hysteria
   2) feed into ``Verdict``. The bug being regressed here: when curl
   through the SOCKS hop returned ``status="blocked"``, every such
   case was downgraded to BLOCKED — even when the tunnel binary's own
   stdout proved the upstream handshake completed. That conflicted
   with the listener's ``handshake_count > 0 and not data_transfer_ok
   ⇒ HANDSHAKE_ONLY`` aggregation and produced split verdicts on the
   per-session reachability matrix.

2. ``_wg_peer_rx_bytes`` — parses the ``<tool> show <iface> transfer``
   output (vanilla ``wg`` and amneziawg-go's ``awg``). The number is
   gated as a second OK signal in the WG/AWG probes specifically to
   block the Windows Docker Desktop ``network_mode: host`` quirk
   where ICMP echoes get spoofed by the host network stack and
   ``ping_echo`` returns True even though the listener never observed
   any handshake bytes.
"""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock

import pytest
from censprobe_core import protocol_probes
from censprobe_core.models import Verdict
from censprobe_core.protocol_probes import (
    ProbeResult,
    _build_obfuscated2_init,
    _classify_proxy_outcome,
    _parse_mtproxy_orig_secret,
    _validate_resPQ,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class TestClassifyProxyOutcomeOk:
    def test_ok_status_short_circuits_without_log_inspection(self) -> None:
        # status="ok" must always return (True, False) regardless of
        # whatever the tunnel log says — curl already proved the data
        # plane works end-to-end.
        assert _classify_proxy_outcome("ok", "") == (True, False)
        assert _classify_proxy_outcome("ok", "handshake failed everywhere") == (True, False)


class TestClassifyProxyOutcomeBlocked:
    """Regression: status='blocked' + success token in log → HANDSHAKE_ONLY.

    Previously this short-circuited to (False, False) → BLOCKED, even
    when the sing-box / xray / hysteria stdout clearly showed the
    upstream tunnel was up. That made the client report BLOCKED while
    the listener (which does see the responder's handshake counter
    advance) reported HANDSHAKE_ONLY.
    """

    def test_blocked_with_success_token_promotes_to_handshake_only(self) -> None:
        log = "12:00:00 inbound connection accepted from 1.2.3.4"
        assert _classify_proxy_outcome("blocked", log) == (True, True)

    def test_blocked_with_no_tokens_stays_blocked(self) -> None:
        # Truly blocked: tunnel never came up, no markers either way.
        assert _classify_proxy_outcome("blocked", "") == (False, False)
        assert _classify_proxy_outcome(
            "blocked",
            "config loaded\nstarted listen :8080\n",  # 'started listen' is a success token
        ) == (True, True)

    def test_blocked_with_success_AND_failure_tokens_stays_blocked(self) -> None:
        # If both a success and a failure marker show up, fail closed —
        # we cannot prove the upstream handshake actually finished.
        log = "tunnel established\nlater: handshake failed: peer refused"
        assert _classify_proxy_outcome("blocked", log) == (False, False)

    def test_blocked_case_insensitive(self) -> None:
        # Token lookup lowercases the log; sing-box logs in mixed case.
        log = "Tunnel ESTABLISHED\nproxy ready"
        assert _classify_proxy_outcome("blocked", log) == (True, True)


class TestClassifyProxyOutcomeInconclusive:
    """Same log-inspection rules apply to status='inconclusive'."""

    def test_inconclusive_with_success_only_is_handshake_only(self) -> None:
        log = "reality: client connected\n"
        assert _classify_proxy_outcome("inconclusive", log) == (True, True)

    def test_inconclusive_with_no_tokens_blocked(self) -> None:
        assert _classify_proxy_outcome("inconclusive", "") == (False, False)

    def test_legacy_handshake_only_alias_tolerated(self) -> None:
        # Some older callers passed "handshake_only" — fall through to
        # the same log-inspection branch as inconclusive.
        log = "client connected"
        assert _classify_proxy_outcome("handshake_only", log) == (True, True)


class TestWgPeerRxBytesParsing:
    """``_wg_peer_rx_bytes`` runs ``<tool> show <iface> transfer`` and
    returns the highest rx_bytes counter across peers. Anything that
    can't be parsed must collapse to 0 so the WG/AWG probe stays in
    HANDSHAKE_ONLY rather than promoting to OK on bad evidence.
    """

    @pytest.fixture
    def patch_run_cmd(self, monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
        # Patch the bound ``run_cmd`` on the module so the helper sees
        # our fake output without spawning the wg/awg binary.
        mock = AsyncMock()
        monkeypatch.setattr(protocol_probes, "run_cmd", mock)
        return mock

    async def test_single_peer_with_rx(self, patch_run_cmd: AsyncMock) -> None:
        patch_run_cmd.return_value = (0, "PEER_PUBKEY_BASE64\t12345\t6789", "")
        rx = await protocol_probes._wg_peer_rx_bytes("wg", "censwg0")
        assert rx == 12345

    async def test_multiple_peers_returns_max_rx(self, patch_run_cmd: AsyncMock) -> None:
        patch_run_cmd.return_value = (
            0,
            "PEERA\t100\t200\nPEERB\t9999\t10\nPEERC\t50\t50",
            "",
        )
        rx = await protocol_probes._wg_peer_rx_bytes("wg", "censwg0")
        assert rx == 9999

    async def test_zero_rx_means_no_peer_bytes(self, patch_run_cmd: AsyncMock) -> None:
        # Fresh interface, peer never replied: rx_bytes=0. Helper must
        # return 0 (NOT None / NOT raise) so caller's `rx > 0` check
        # cleanly short-circuits to HANDSHAKE_ONLY.
        patch_run_cmd.return_value = (0, "PEERA\t0\t0", "")
        rx = await protocol_probes._wg_peer_rx_bytes("wg", "censwg0")
        assert rx == 0

    async def test_tool_failure_returns_zero(self, patch_run_cmd: AsyncMock) -> None:
        # Non-zero exit (binary missing, iface gone) ⇒ 0, never raise.
        # Probe loop must keep running and report HANDSHAKE_ONLY rather
        # than crash on an opaque CalledProcessError.
        patch_run_cmd.return_value = (1, "", "No such device")
        rx = await protocol_probes._wg_peer_rx_bytes("wg", "censwg0")
        assert rx == 0

    async def test_garbled_output_returns_zero(self, patch_run_cmd: AsyncMock) -> None:
        # Future tool version, partial line, etc. — tolerate by
        # falling through to 0 rather than asserting line shape.
        patch_run_cmd.return_value = (0, "what is this format", "")
        rx = await protocol_probes._wg_peer_rx_bytes("wg", "censwg0")
        assert rx == 0

    async def test_space_separated_output_also_parsed(self, patch_run_cmd: AsyncMock) -> None:
        # Some builds emit space-separated rather than tab-separated
        # transfer lines. ``str.split()`` handles both, so we should
        # parse either shape correctly without a special case.
        patch_run_cmd.return_value = (0, "PEERA 7777 1111", "")
        rx = await protocol_probes._wg_peer_rx_bytes("wg", "censwg0")
        assert rx == 7777


# ─────────────────────────────────────────────────────────────────────────────
# Original MTProxy (obfuscated2) probe helpers
# ─────────────────────────────────────────────────────────────────────────────


class TestParseMtproxyOrigSecret:
    """``_parse_mtproxy_orig_secret`` accepts both 'dd<32-hex>' and bare
    32-hex; everything else fails fast with a typed ProbeResult so the
    upstream caller can attribute the error.
    """

    def test_dd_prefix_stripped(self) -> None:
        sec = "dd" + "ab" * 16  # 34 chars, dd-prefixed
        result = _parse_mtproxy_orig_secret(sec)
        assert isinstance(result, bytes)
        assert len(result) == 16
        assert result == bytes.fromhex("ab" * 16)

    def test_bare_32_hex_accepted(self) -> None:
        sec = "1234567890abcdef" * 2  # 32 hex chars
        result = _parse_mtproxy_orig_secret(sec)
        assert isinstance(result, bytes)
        assert len(result) == 16

    def test_uppercase_dd_prefix_accepted(self) -> None:
        # Operator-typed secrets sometimes capitalise hex; helper must
        # canonicalise before comparing.
        sec = "DD" + "AB" * 16
        result = _parse_mtproxy_orig_secret(sec)
        assert isinstance(result, bytes)

    def test_non_hex_rejected(self) -> None:
        result = _parse_mtproxy_orig_secret("dd" + "zz" * 16)
        assert isinstance(result, ProbeResult)
        assert result.error == "orig_secret_not_hex"
        assert result.verdict == Verdict.ERROR

    def test_wrong_length_rejected(self) -> None:
        # 30 hex chars = 15 bytes — too short.
        result = _parse_mtproxy_orig_secret("ab" * 15)
        assert isinstance(result, ProbeResult)
        assert "orig_secret_bad_len" in (result.error or "")


class TestBuildObfuscated2Init:
    """``_build_obfuscated2_init`` produces a 64-byte init plus a CTR
    cipher pair that the proxy will be able to decrypt symmetrically.
    Verified directly: derive keys with the same algorithm and confirm
    bytes [56:60] decrypt to ``0xdddddddd`` (padded-intermediate tag).
    """

    def test_init_is_64_bytes(self) -> None:
        secret = b"\x42" * 16
        init_bytes, _, _ = _build_obfuscated2_init(secret)
        assert len(init_bytes) == 64

    def test_first_byte_not_0xef(self) -> None:
        # Tag byte 0xef would self-collide with abridged-transport.
        # Loop should keep regenerating until the constraint holds.
        for _ in range(20):
            secret = b"\x00" * 16
            init_bytes, _, _ = _build_obfuscated2_init(secret)
            assert init_bytes[0] != 0xEF

    def test_second_int32_nonzero(self) -> None:
        for _ in range(20):
            secret = b"\x00" * 16
            init_bytes, _, _ = _build_obfuscated2_init(secret)
            assert int.from_bytes(init_bytes[4:8], "little") != 0

    def test_first_int32_not_in_forbidden_set(self) -> None:
        forbidden = {
            0x44414548,
            0x54534F50,
            0x20544547,
            0x4954504F,
            0xEEEEEEEE,
            0xDDDDDDDD,
            0x02010316,
        }
        for _ in range(20):
            secret = b"\x00" * 16
            init_bytes, _, _ = _build_obfuscated2_init(secret)
            assert int.from_bytes(init_bytes[0:4], "little") not in forbidden

    def test_decrypted_tag_is_padded_intermediate(self) -> None:
        # Full handshake-side check: rebuild server's recv keystream and
        # XOR against init[56:60] — must yield 0xdddddddd (4 × 0xdd).
        secret = b"\x99" * 16
        init_bytes, _, _ = _build_obfuscated2_init(secret)

        # Server's recv key derivation = client's send keys (mirror).
        key_part = init_bytes[8:56]
        send_key_raw, send_iv = key_part[:32], key_part[32:48]
        send_key = hashlib.sha256(send_key_raw + secret).digest()

        srv_cipher = Cipher(algorithms.AES(send_key), modes.CTR(send_iv)).encryptor()
        keystream = srv_cipher.update(b"\x00" * 64)

        decrypted_tag = bytes(init_bytes[56 + i] ^ keystream[56 + i] for i in range(4))
        assert decrypted_tag == b"\xdd\xdd\xdd\xdd"


class TestValidateResPQ:
    """``_validate_resPQ`` accepts a structurally valid resPQ frame with
    matching nonce; everything else returns BLOCKED + a typed error tag.
    The decrypted body layout we validate is:

        auth_key_id(8) || msg_id(8) || msg_len(4) || msg_body(msg_len) || pad

    where msg_body[0:4] is TL ID 0x05162463 and msg_body[4:20] is the
    server-echoed nonce.
    """

    @staticmethod
    def _build_valid_body(nonce: bytes, *, tl_id: int = 0x05162463) -> bytes:
        # Minimal resPQ-shaped body. Real resPQ is bigger but probe
        # validation only inspects auth_key_id, msg_len, TL ID, nonce.
        msg_body = tl_id.to_bytes(4, "little") + nonce + b"\x00" * 64  # 84 bytes
        msg_len = len(msg_body)
        return (
            b"\x00" * 8  # auth_key_id
            + b"\x11" * 8  # msg_id (any)
            + msg_len.to_bytes(4, "little")
            + msg_body
        )

    def test_valid_resPQ_accepted(self) -> None:
        nonce = b"n" * 16
        body = self._build_valid_body(nonce)
        assert _validate_resPQ(body, nonce) is None

    def test_truncated_body_rejected(self) -> None:
        result = _validate_resPQ(b"\x00" * 10, b"n" * 16)
        assert isinstance(result, ProbeResult)
        assert result.verdict == Verdict.BLOCKED
        assert "truncated" in (result.error or "")

    def test_nonzero_auth_key_id_rejected(self) -> None:
        nonce = b"n" * 16
        body = bytearray(self._build_valid_body(nonce))
        body[0] = 0xFF  # non-zero auth_key_id → not unencrypted MTProto
        result = _validate_resPQ(bytes(body), nonce)
        assert isinstance(result, ProbeResult)
        assert result.error == "orig_resPQ_bad_auth_key_id"

    def test_wrong_tl_id_rejected(self) -> None:
        # Body says it's some other constructor — not resPQ.
        nonce = b"n" * 16
        body = self._build_valid_body(nonce, tl_id=0xDEADBEEF)
        result = _validate_resPQ(body, nonce)
        assert isinstance(result, ProbeResult)
        assert "orig_resPQ_bad_tl_id" in (result.error or "")

    def test_nonce_mismatch_rejected(self) -> None:
        # resPQ structurally OK but server echoed a different nonce —
        # signals proxy is wrong instance / cross-session collision.
        body = self._build_valid_body(b"n" * 16)
        result = _validate_resPQ(body, b"X" * 16)
        assert isinstance(result, ProbeResult)
        assert result.error == "orig_resPQ_nonce_mismatch"
