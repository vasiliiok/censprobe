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
    _validate_res_pq,
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

    def test_blocked_with_only_listener_startup_log_stays_blocked(self) -> None:
        # Local SOCKS listener startup ("started listen", "listening on…")
        # is NOT evidence of an upstream handshake — the local proxy
        # binary spinning up its own port doesn't say anything about
        # whether the remote peer ever replied. Promoting BLOCKED here
        # would violate the project invariant "BLOCKED == confirmed
        # block": fixed 2026-05.
        log = "config loaded\nstarted listen :8080\n"
        assert _classify_proxy_outcome("blocked", log) == (False, False)

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
        log = "accepted tcp:127.0.0.1:443 -> upstream\n"
        assert _classify_proxy_outcome("inconclusive", log) == (True, True)

    def test_inconclusive_with_no_tokens_blocked(self) -> None:
        assert _classify_proxy_outcome("inconclusive", "") == (False, False)

    def test_legacy_handshake_only_alias_tolerated(self) -> None:
        # Some older callers passed "handshake_only" — fall through to
        # the same log-inspection branch as inconclusive.
        log = "client connected"
        assert _classify_proxy_outcome("handshake_only", log) == (True, True)


class TestHandshakeTokenSetSnapshot:
    """Pin the exact token sets so accidental token additions/removals
    fail loudly in review.

    These tokens decide whether BLOCKED gets promoted to HANDSHAKE_ONLY.
    A typo or overly-broad addition (e.g. "started listen", which we
    removed in 2026-05) silently changes the verdict for every probe
    that uses _classify_proxy_outcome. A snapshot test forces any
    future change to be a *deliberate* one — touch this list, the
    review reads exactly what shifted.
    """

    def test_success_tokens_pinned(self) -> None:
        # Each entry MUST be evidence of upstream-peer activity, not
        # local listener bring-up. If you add a token that fires on
        # binary startup alone (e.g. "listening on", "started listen",
        # "ready"), you violate the BLOCKED invariant — see
        # _HS_SUCCESS_TOKENS docstring.
        expected = (
            "inbound connection",
            "connection established",
            "handshake complete",
            "tunnel established",
            "authenticated",
            "accepted tcp:",
            "client connected",
            "server connected",
            "new connection:",
        )
        assert protocol_probes._HS_SUCCESS_TOKENS == expected

    def test_failure_tokens_pinned(self) -> None:
        # Failure markers gate the success-token promotion: if any of
        # these appear, BLOCKED stays BLOCKED even with a success
        # marker present. See test_blocked_with_success_AND_failure_…
        expected = (
            "handshake failed",
            "connection refused",
            "no route to host",
            "i/o timeout",
            "context deadline exceeded",
            "tls: ",
            "reality verify failed",
            "auth failed",
            "authentication failed",
            "dial tcp",
            "dial udp",
        )
        assert protocol_probes._HS_FAILURE_TOKENS == expected

    def test_no_token_overlap(self) -> None:
        # Sanity: a string can't be both a success and failure marker
        # — that would make _classify_proxy_outcome ambiguous.
        success = set(protocol_probes._HS_SUCCESS_TOKENS)
        failure = set(protocol_probes._HS_FAILURE_TOKENS)
        assert success.isdisjoint(failure), f"tokens in both sets: {success & failure}"

    def test_no_token_is_substring_of_another(self) -> None:
        # Defensive: if "tcp" were in success and "dial tcp" in
        # failure, every "dial tcp" line would match BOTH and the
        # outcome would depend on iteration order. Substring checks
        # short-circuit cleanly only when no token shadows another.
        all_tokens = list(protocol_probes._HS_SUCCESS_TOKENS) + list(
            protocol_probes._HS_FAILURE_TOKENS
        )
        for i, a in enumerate(all_tokens):
            for j, b in enumerate(all_tokens):
                if i != j:
                    assert a not in b or a == b, (
                        f"token {a!r} is a substring of {b!r} — will produce ambiguous matches"
                    )


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
    """``_validate_res_pq`` accepts a structurally valid resPQ frame with
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
        assert _validate_res_pq(body, nonce) is None

    def test_truncated_body_rejected(self) -> None:
        result = _validate_res_pq(b"\x00" * 10, b"n" * 16)
        assert isinstance(result, ProbeResult)
        assert result.verdict == Verdict.BLOCKED
        assert "truncated" in (result.error or "")

    def test_nonzero_auth_key_id_rejected(self) -> None:
        nonce = b"n" * 16
        body = bytearray(self._build_valid_body(nonce))
        body[0] = 0xFF  # non-zero auth_key_id → not unencrypted MTProto
        result = _validate_res_pq(bytes(body), nonce)
        assert isinstance(result, ProbeResult)
        assert result.error == "orig_resPQ_bad_auth_key_id"

    def test_wrong_tl_id_rejected(self) -> None:
        # Body says it's some other constructor — not resPQ.
        nonce = b"n" * 16
        body = self._build_valid_body(nonce, tl_id=0xDEADBEEF)
        result = _validate_res_pq(body, nonce)
        assert isinstance(result, ProbeResult)
        assert "orig_resPQ_bad_tl_id" in (result.error or "")

    def test_nonce_mismatch_rejected(self) -> None:
        # resPQ structurally OK but server echoed a different nonce —
        # signals proxy is wrong instance / cross-session collision.
        body = self._build_valid_body(b"n" * 16)
        result = _validate_res_pq(body, b"X" * 16)
        assert isinstance(result, ProbeResult)
        assert result.error == "orig_resPQ_nonce_mismatch"


class TestExchangeObfuscated2RespQTimeout:
    """Regression: ``len_timeout_post_init`` (TCP held open + init bytes
    accepted but no L7 resPQ ever surfaces) MUST verdict as ``BLOCKED``,
    not ``HANDSHAKE_ONLY``.

    Why: preflight already verified DC reach from the listener host, so
    a silent stall here is the canonical DPI signature — a third party
    fingerprinted the obfuscated2 envelope and dropped the data path.
    The protocol is functionally unusable, which is a confirmed L7
    block. Treating it as HANDSHAKE_ONLY misled operators into reading
    \"protocol reachable\" when the protocol could not move data.

    Covers BOTH transport variants:
      * raw obfuscated2 (``probe_mtproto_orig`` — wrap_inner=False)
      * faketls-wrapped (``probe_mtproto_proxy``/``_alt`` —
        wrap_inner=True): timeout while reading the TLS record header
        for the encrypted-length prefix.
    """

    @staticmethod
    def _make_blocking_reader_writer() -> tuple[
        protocol_probes.asyncio.StreamReader, protocol_probes.asyncio.StreamWriter
    ]:
        # A real ``StreamReader`` that never gets data fed into it —
        # ``readexactly`` will raise ``TimeoutError`` under
        # ``asyncio.wait_for``. The writer is a stub: ``write`` is a
        # no-op, ``drain`` returns immediately. We don't need a real
        # transport; the probe never reads back from the writer.
        reader = protocol_probes.asyncio.StreamReader()
        writer = AsyncMock()
        writer.write = lambda _b: None
        return reader, writer

    @pytest.mark.asyncio
    async def test_raw_path_len_timeout_is_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Squeeze the probe timeout so the test finishes in well under
        # a second instead of waiting the production 15s constant.
        monkeypatch.setattr(protocol_probes, "PROBE_TIMEOUT", 0.05)
        reader, writer = self._make_blocking_reader_writer()
        result = await protocol_probes._exchange_obfuscated2_respq(
            reader, writer, secret_key=b"\x00" * 16, wrap_inner_in_tls_record=False
        )
        assert isinstance(result, ProbeResult)
        assert result.verdict == Verdict.BLOCKED
        assert result.error == "orig_resPQ_len_timeout_post_init"

    @pytest.mark.asyncio
    async def test_faketls_path_len_timeout_is_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(protocol_probes, "PROBE_TIMEOUT", 0.05)
        reader, writer = self._make_blocking_reader_writer()
        result = await protocol_probes._exchange_obfuscated2_respq(
            reader, writer, secret_key=b"\x00" * 16, wrap_inner_in_tls_record=True
        )
        assert isinstance(result, ProbeResult)
        assert result.verdict == Verdict.BLOCKED
        assert result.error == "orig_resPQ_len_timeout_post_init"


class TestPingEchoReturnShape:
    """``ping_echo`` returns ``(data_plane_ok, avg_rtt_ms)`` so WG/AWG
    probes can surface a real round-trip number instead of the legacy
    polling-resolution artifact (1 ms when the handshake completed
    during ``wg-quick up``, 505 ms when the next poll tick was 0.5 s
    later). Tests the parser branches without spawning a real ping.
    """

    @staticmethod
    def _ping_output(received: int, *, avg_rtt: float | None) -> str:
        # Emulate iputils-ping's textual summary: a "packets transmitted /
        # received" header and an optional "rtt min/avg/max/mdev" line.
        # avg_rtt=None drops the rtt line entirely (the case where every
        # ping timed out and ping prints no rtt summary).
        lines = [
            "PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.",
            f"3 packets transmitted, {received} received, 0% packet loss, time 600ms",
        ]
        if avg_rtt is not None:
            # min/avg/max/mdev — we only parse avg, but real ping always
            # includes all four when ANY reply is received.
            lines.append(
                f"rtt min/avg/max/mdev = "
                f"{max(0.0, avg_rtt - 0.1):.3f}/{avg_rtt:.3f}/{avg_rtt + 0.1:.3f}/0.024 ms"
            )
        return "\n".join(lines)

    @pytest.mark.asyncio
    async def test_full_success_returns_ok_and_rtt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _fake(*_a: object, **_kw: object) -> tuple[int, str, str]:
            return 0, self._ping_output(3, avg_rtt=12.5), ""

        monkeypatch.setattr(protocol_probes, "run_cmd", _fake)
        ok, rtt = await protocol_probes.ping_echo("10.0.0.1")
        assert ok is True
        assert rtt == 12.5

    @pytest.mark.asyncio
    async def test_partial_success_above_threshold(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # min_received default is 2; 2/3 received still passes.
        async def _fake(*_a: object, **_kw: object) -> tuple[int, str, str]:
            return 0, self._ping_output(2, avg_rtt=8.7), ""

        monkeypatch.setattr(protocol_probes, "run_cmd", _fake)
        ok, rtt = await protocol_probes.ping_echo("10.0.0.1")
        assert ok is True
        assert rtt == 8.7

    @pytest.mark.asyncio
    async def test_below_threshold_returns_false_with_rtt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 1/3 received: a single echo could be the Windows-Docker-Desktop
        # spoof. ping_echo flags this as not-OK even though the rtt line
        # is still parseable from the lone reply we did get.
        async def _fake(*_a: object, **_kw: object) -> tuple[int, str, str]:
            return 0, self._ping_output(1, avg_rtt=1.2), ""

        monkeypatch.setattr(protocol_probes, "run_cmd", _fake)
        ok, rtt = await protocol_probes.ping_echo("10.0.0.1")
        assert ok is False
        # Legitimate to surface the rtt anyway — the caller decides
        # whether a sub-threshold echo's RTT is meaningful.
        assert rtt == 1.2

    @pytest.mark.asyncio
    async def test_total_failure_returns_false_and_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # rc=1 from ping → no echoes received at all → no rtt line
        # in stdout → (False, None).
        async def _fake(*_a: object, **_kw: object) -> tuple[int, str, str]:
            return 1, "", ""

        monkeypatch.setattr(protocol_probes, "run_cmd", _fake)
        ok, rtt = await protocol_probes.ping_echo("10.0.0.1")
        assert ok is False
        assert rtt is None

    @pytest.mark.asyncio
    async def test_zero_received_with_rc0_no_rtt_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Edge case: rc=0 (ping itself didn't crash) but iputils omitted
        # the rtt summary because no replies came back.
        async def _fake(*_a: object, **_kw: object) -> tuple[int, str, str]:
            return 0, self._ping_output(0, avg_rtt=None), ""

        monkeypatch.setattr(protocol_probes, "run_cmd", _fake)
        ok, rtt = await protocol_probes.ping_echo("10.0.0.1")
        assert ok is False
        assert rtt is None
