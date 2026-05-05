"""
Byte-signature snapshots for the on-wire packet builders.

These complement ``test_cloudflare_packets.py`` (which pins each fixed
field by structural assertion). Here we capture the COMPLETE bytes of
each builder under deterministic input and snapshot them with
pytest-regressions. Any unintended byte-level drift fails CI; an
intentional change re-records the snapshot in the diff for human
review.

We seed ``os.urandom`` with a fixed PRNG so the random portions of the
packet are reproducible. The fixed bytes (Long-Header bit, GREASE
version, WG message-type byte, etc.) are then visible in the snapshot
hex dump and a future contributor can spot a one-byte change at a
glance.
"""

from __future__ import annotations

import hashlib
import os
import random
from collections.abc import Iterator
from typing import Any

import pytest


@pytest.fixture
def deterministic_urandom(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Replace ``os.urandom`` with a seeded PRNG so snapshots are stable."""
    rng = random.Random(0xCAFEBABE)

    def _fake(n: int) -> bytes:
        return bytes(rng.randint(0, 255) for _ in range(n))

    monkeypatch.setattr(os, "urandom", _fake)
    yield


def _hexdump(data: bytes) -> dict[str, Any]:
    """Stable, diff-friendly representation: length, sha256, hex string."""
    return {
        "len": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        # 16-byte rows make scanning a hex dump for byte-level changes easy.
        "hex_rows": [data[i : i + 16].hex() for i in range(0, len(data), 16)],
    }


def test_quic_vn_trigger_bytes(
    deterministic_urandom: None,
    data_regression: Any,
) -> None:
    from censprobe_core.modules.cloudflare import _build_quic_vn_trigger

    pkt = _build_quic_vn_trigger()
    data_regression.check(_hexdump(pkt))


def test_masque_probe_packet_bytes(
    deterministic_urandom: None,
    data_regression: Any,
) -> None:
    from censprobe_core.modules.cloudflare import _build_masque_probe_packet

    pkt = _build_masque_probe_packet()
    data_regression.check(_hexdump(pkt))


def test_wg_handshake_init_bytes(
    deterministic_urandom: None,
    data_regression: Any,
) -> None:
    from censprobe_core.modules.cloudflare import _build_wg_handshake_init

    pkt = _build_wg_handshake_init()
    data_regression.check(_hexdump(pkt))
