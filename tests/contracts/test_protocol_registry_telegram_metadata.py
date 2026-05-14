"""Contract: ProtocolSpec.is_mtg_protocol / requires_telegram_dc are
correctly populated for the Telegram-flavoured protocols.

Why this exists: the listener-side ``_finalize_protocol_result``, the
``commit_final_snapshots`` dc_reach_ok injection, and the client-side
``_agreed_verdict`` note rewrite all consult these two metadata fields
to decide which protocols get the DC-reach gate. A typo or missed
flag silently breaks dual-RU vantage attribution (the very bug that
spawned this metadata in the first place — see commit 408ed61 and
the 2026-05-14 ya-b run analysis). The contract test makes the
configuration explicit so a future protocol addition fails loudly
when the operator forgets the flags.
"""

from __future__ import annotations

from censprobe_core.protocol_registry import (
    PROTOCOLS,
    is_mtg_protocol,
    requires_telegram_dc,
)

# Canonical set of Telegram-flavoured protocols. If you add a new
# Telegram protocol (e.g., an mtg sibling on yet another port, or a
# different MTProxy implementation), update BOTH this set AND the
# matching ProtocolSpec flags below — the test enforces sync.
_EXPECTED_MTG_PROTOCOLS = {"mtproto_proxy", "mtproto_proxy_alt"}
_EXPECTED_TELEGRAM_DC_PROTOCOLS = {
    "mtproto_proxy",
    "mtproto_proxy_alt",
    "mtproto_orig",
}


def test_is_mtg_protocol_matches_expected_set() -> None:
    actual_mtg = {p.name for p in PROTOCOLS if p.is_mtg_protocol}
    assert actual_mtg == _EXPECTED_MTG_PROTOCOLS, (
        f"is_mtg_protocol drift: expected {_EXPECTED_MTG_PROTOCOLS}, "
        f"got {actual_mtg}. Adding a new mtg sibling? Update both the "
        f"ProtocolSpec flag and this contract's expected set."
    )


def test_requires_telegram_dc_matches_expected_set() -> None:
    actual_dc = {p.name for p in PROTOCOLS if p.requires_telegram_dc}
    assert actual_dc == _EXPECTED_TELEGRAM_DC_PROTOCOLS, (
        f"requires_telegram_dc drift: expected "
        f"{_EXPECTED_TELEGRAM_DC_PROTOCOLS}, got {actual_dc}. "
        f"All Telegram-flavoured protocols must set this flag so the "
        f"listener's snapshot-injection logic picks them up."
    )


def test_mtg_protocols_also_require_telegram_dc() -> None:
    # Every mtg protocol is by definition a Telegram protocol — it
    # routes traffic to/from the DC fleet. The inverse is not true
    # (mtproto_orig requires DC but isn't mtg).
    for spec in PROTOCOLS:
        if spec.is_mtg_protocol:
            assert spec.requires_telegram_dc, (
                f"{spec.name} is_mtg_protocol=True but "
                f"requires_telegram_dc=False — mtg responders MUST "
                f"relay to a Telegram DC, so the flags are inconsistent."
            )


def test_helper_functions_agree_with_specs() -> None:
    # The convenience helpers must agree with the underlying ProtocolSpec
    # for every registered protocol — otherwise callers using helpers
    # see a different set than callers iterating PROTOCOLS directly.
    for spec in PROTOCOLS:
        assert is_mtg_protocol(spec.name) is spec.is_mtg_protocol
        assert requires_telegram_dc(spec.name) is spec.requires_telegram_dc


def test_helper_functions_default_false_for_unknown() -> None:
    # Unknown protocol names should never raise; they're "obviously not"
    # mtg / Telegram-flavoured. Caller pre-validates against
    # known_names() at config time, so unknown is a programming error
    # — but defensive False keeps the helpers from crashing the run.
    assert is_mtg_protocol("unknown_protocol") is False
    assert is_mtg_protocol("") is False
    assert requires_telegram_dc("unknown_protocol") is False
    assert requires_telegram_dc("") is False


def test_non_telegram_protocols_have_both_flags_false() -> None:
    # OpenVPN / WG / AmneziaWG / SS / VLESS-Reality / Hysteria2 have
    # nothing to do with Telegram DCs. If a flag accidentally lights
    # up for one of these (typo, copy/paste error), the listener's
    # snapshot injection would spuriously add dc_reach_ok to e.g.
    # shadowsocks snapshots — wasted bytes and confusing semantics.
    non_telegram = {
        spec.name for spec in PROTOCOLS if spec.name not in _EXPECTED_TELEGRAM_DC_PROTOCOLS
    }
    for name in non_telegram:
        assert not is_mtg_protocol(name), f"{name}: spurious is_mtg flag"
        assert not requires_telegram_dc(name), f"{name}: spurious requires_telegram_dc flag"
