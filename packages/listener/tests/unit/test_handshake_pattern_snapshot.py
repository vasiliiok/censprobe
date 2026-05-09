"""Pin the lowercase substrings each responder uses to count completed
handshakes from its child binary's stdout.

If xray / sing-box / hysteria / mtg / mtproto-proxy ever changes its log
format in a binary upgrade, ``_responder_base._monitor_output`` will
silently stop incrementing ``connection_count`` and the listener-side
verdict will be permanently HANDSHAKE_ONLY → BLOCKED on every probe,
with no other surface signal. These tests freeze the contract so a
future binary bump that drifts a marker fails CI loudly, instead of
silently corrupting verdicts in production.
"""

from __future__ import annotations

import pytest
from censprobe_listener._responder_base import SubprocessResponder
from censprobe_listener.hysteria_wrapper import HysteriaResponder
from censprobe_listener.mtproto_orig_responder import MTProxyOrigResponder
from censprobe_listener.mtproxy_responder import MTProxyResponder
from censprobe_listener.ss_responder import ShadowsocksResponder
from censprobe_listener.vless_reality_wrapper import VlessRealityResponder


def _patterns(cls: type[SubprocessResponder]) -> tuple[str, ...]:
    """Class attribute can be either a str or a tuple — normalise to tuple."""
    raw = cls.handshake_log_pattern
    return (raw,) if isinstance(raw, str) else tuple(raw)


@pytest.mark.parametrize(
    ("cls", "expected"),
    [
        (VlessRealityResponder, ("accepted tcp:",)),
        (HysteriaResponder, ("client connected",)),
        (ShadowsocksResponder, ("inbound connection from", "accepted tcp:")),
    ],
)
def test_log_monitored_responder_handshake_patterns(
    cls: type[SubprocessResponder], expected: tuple[str, ...]
) -> None:
    """Pin each responder's marker so a binary upgrade that drifts it
    breaks the test instead of silently zeroing handshake_count.
    """
    actual = _patterns(cls)
    assert actual == expected, (
        f"{cls.__name__}.handshake_log_pattern drifted from {expected} to "
        f"{actual}. Likely cause: child binary changed its log format. "
        f"Re-derive the new substring against the current binary's stdout, "
        f"verify it fires once per real handshake, and update both the "
        f"responder and this test."
    )


def test_mtg_responder_handshake_marker() -> None:
    """``MTProxyResponder`` (mtg) doesn't use the base class' attribute —
    it parses its own stdout in a custom monitor (see
    ``_monitor_output_mtproto`` in mtproxy_responder.py). The marker is
    'stream has been started' — pin it so a mtg upgrade is caught.
    """
    import inspect

    src = inspect.getsource(MTProxyResponder)
    assert "stream has been started" in src, (
        "MTProxyResponder no longer references its handshake marker. mtg "
        "upgrades have historically renamed this string — verify against "
        "the new mtg version's stdout and re-pin."
    )


def test_mtproto_orig_responder_handshake_markers() -> None:
    """``MTProxyOrigResponder`` (TelegramMessenger/MTProxy) similarly
    parses stdout in a custom path. Verify both markers it counts.
    """
    import inspect

    src = inspect.getsource(MTProxyOrigResponder)
    for marker in ("new connection from", "query from"):
        assert marker in src, (
            f"MTProxyOrigResponder lost handshake marker {marker!r}. The "
            f"original mtproto-proxy is rarely updated, but if its log "
            f"format ever drifts, re-derive markers from a fresh build."
        )
