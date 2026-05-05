"""
Byte-exact verification of the MTProto abridged-transport frame written
by ``_test_dc_port``.

The wire bytes are split across three lines in telegram.py:

    mtproto = struct.pack("<qqi", 0, msg_id, 4) + b"\\xf1\\x8e\\x7e\\xbe"
    assert len(mtproto) == 24 and (len(mtproto) % 4) == 0
    writer.write(b"\\xef" + bytes([len(mtproto) // 4]) + mtproto)

A single off-by-one in any of those three lines (wrong struct format,
wrong abridged-transport magic, missing length byte) would silently
break wire compat without tripping any unit-level assertion in the
broader probe — it would just always time out, which the verdict logic
treats as expected on clean networks. So we capture the bytes from a
mocked socket and validate every documented invariant explicitly.
"""

from __future__ import annotations

import struct
from typing import Any

import pytest
from censprobe_core.modules import telegram


class _FakeWriter:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _FakeReader:
    async def read(self, n: int) -> bytes:
        # Force the MTProto-response wait to time out (the documented
        # expected case on clean networks). _test_dc_port treats that
        # as Verdict.OK based on TCP connect success.
        raise TimeoutError


@pytest.mark.asyncio
async def test_mtproto_frame_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    writer = _FakeWriter()
    reader = _FakeReader()

    async def _fake_open_connection(*args: Any, **kwargs: Any) -> Any:
        return reader, writer

    monkeypatch.setattr(telegram.asyncio, "open_connection", _fake_open_connection)

    # Pin time so msg_id is deterministic. The frame logic uses
    # int(time.time() * 2**32) & (1<<63)-1 for msg_id.
    monkeypatch.setattr(telegram.time, "time", lambda: 1_700_000_000.0)
    expected_msg_id = int(1_700_000_000.0 * (2**32)) & ((1 << 63) - 1)

    await telegram._test_dc_port(dc_id=1, ip_ver="ipv4", ip="1.2.3.4", port=443)

    payload = bytes(writer.buf)

    # ── Frame length and structure ──────────────────────────────────────────
    # 1 byte abridged-transport magic + 1 byte length + 24 byte mtproto body.
    assert len(payload) == 26, f"frame total length {len(payload)} != 26"

    # ── Abridged transport magic (\xef) ────────────────────────────────────
    assert payload[0] == 0xEF, f"abridged-transport magic byte != 0xef: {payload[0]:#x}"

    # ── Length byte: number of 4-byte words in the body ────────────────────
    # Body is 24 bytes → 24/4 == 6.
    assert payload[1] == 6, f"length byte != 6: {payload[1]}"

    # ── struct.pack("<qqi", 0, msg_id, 4) — first 20 bytes of the body ─────
    auth_key_id, msg_id, msg_len = struct.unpack("<qqi", payload[2:22])
    assert auth_key_id == 0, f"auth_key_id must be 0 (unauth client): {auth_key_id}"
    assert msg_id == expected_msg_id, "msg_id != int(time.time()*2**32) & (2**63 - 1)"
    assert msg_len == 4, f"msg_len in struct must be 4: {msg_len}"

    # ── ReqPqMulti TL constructor — last 4 bytes ──────────────────────────
    # Telegram's TL ID for req_pq_multi#be7e8ef1 — note the little-endian
    # byte order on the wire. The literal in telegram.py is the LE form:
    #   b"\xf1\x8e\x7e\xbe"
    assert payload[22:26] == b"\xf1\x8e\x7e\xbe", (
        f"req_pq_multi constructor bytes wrong: {payload[22:26].hex()}"
    )
