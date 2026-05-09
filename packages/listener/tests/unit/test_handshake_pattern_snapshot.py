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
    it parses its own stdout in a custom monitor. Pin BOTH the
    success marker (``stream has been started``, increments) and the
    handshake-failure markers (decrement, so scanner traffic doesn't
    inflate the counter — see _monitor_output docstring).
    """
    import inspect

    src = inspect.getsource(MTProxyResponder)

    assert "stream has been started" in src, (
        "MTProxyResponder lost the handshake-success marker. mtg upgrades "
        "have historically renamed this string — re-derive against the "
        "new mtg version's stdout and update."
    )

    # Failure markers used to subtract scanner / failed-handshake
    # streams from the connection counter. If mtg renames any of
    # these, the counter will be inflated and start producing
    # false-OK at the listener side.
    expected_failure_markers = (
        "cannot parse client hello",
        "cannot read client hello",
        "cannot send welcome packet",
        "obfuscated handshake is failed",
        "cannot wrap into doppelganger connection",
    )
    for marker in expected_failure_markers:
        assert marker in src, (
            f"MTProxyResponder lost the failure marker {marker!r}. "
            f"This marker decrements the handshake counter — without "
            f"it, scanner traffic on the public-facing port inflates "
            f"connection_count and listener verdicts become false-OK."
        )

    # Pin -d (debug) flag presence — without it, mtg's default zerolog
    # WarnLevel suppresses the Info-level handshake events entirely
    # and the counter is permanently zero. Verified critical 2026-05.
    assert '"-d"' in src or "'-d'" in src, (
        "MTProxyResponder no longer passes -d/--debug to mtg. Without "
        "this flag mtg silences all handshake events (default zerolog "
        "level is Warn, our markers are Info), and connection_count "
        "stays at 0 forever → every probe reports listener-side BLOCKED."
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
