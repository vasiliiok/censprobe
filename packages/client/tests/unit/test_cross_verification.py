"""Tests for the client-side cross-verification helpers.

The client fetches a per-protocol snapshot from the listener's
``/snapshot`` endpoint and combines it with its own probe verdicts.
The pure helpers ``_listener_verdict`` and ``_agreed_verdict`` decide:

  1. What the listener's verdict would be from its current counters
     (same predicates as ``ProtocolResult.finalize``).
  2. The "final" verdict surfaced to the operator: listener-authoritative
     with a comment when client and listener disagree.

We exercise the disagreement matrix because that's the only path
where the table tells the operator something they couldn't see in
the client-side table — most importantly the Windows-Docker-Desktop
``client=OK + listener=BLOCKED`` case the snapshot was added to catch.
"""

from __future__ import annotations

from censprobe_client.main import _agreed_verdict, _listener_verdict
from censprobe_core.models import LiveSnapshot, Verdict


class TestListenerVerdict:
    """``_listener_verdict`` mirrors ``ProtocolResult.finalize``."""

    def test_handshake_with_data_is_ok(self) -> None:
        snap = LiveSnapshot(handshake_count=1, data_transfer_ok=True)
        assert _listener_verdict(snap) == Verdict.OK

    def test_handshake_without_data_is_handshake_only(self) -> None:
        snap = LiveSnapshot(handshake_count=1, data_transfer_ok=False)
        assert _listener_verdict(snap) == Verdict.HANDSHAKE_ONLY

    def test_zero_handshake_is_blocked(self) -> None:
        snap = LiveSnapshot(handshake_count=0, data_transfer_ok=False)
        assert _listener_verdict(snap) == Verdict.BLOCKED

    def test_zero_handshake_with_data_pkts_still_blocked(self) -> None:
        # Defence in depth against the openvpn scanner pattern: even
        # if data_transfer_ok somehow flipped True without a handshake
        # (which the listener-side AND-gate prevents in the first
        # place), the listener verdict still requires handshake_count > 0.
        snap = LiveSnapshot(handshake_count=0, data_transfer_ok=True, data_packets=8)
        assert _listener_verdict(snap) == Verdict.BLOCKED


class TestAgreedVerdict:
    """``_agreed_verdict`` returns (final_verdict, note) — listener wins."""

    def test_both_ok_no_note(self) -> None:
        final, note = _agreed_verdict(Verdict.OK, Verdict.OK)
        assert final == Verdict.OK
        assert note == ""

    def test_both_blocked_no_note(self) -> None:
        final, note = _agreed_verdict(Verdict.BLOCKED, Verdict.BLOCKED)
        assert final == Verdict.BLOCKED
        assert note == ""

    def test_client_overconfident_listener_wins_with_note(self) -> None:
        # The Windows Docker Desktop / amneziawg-go scenario from the
        # 2026-05-10 RU runs: client reports OK off spoofed local
        # responses, listener saw zero bytes — listener wins.
        final, note = _agreed_verdict(Verdict.OK, Verdict.BLOCKED)
        assert final == Verdict.BLOCKED
        assert "client overread" in note.lower()

    def test_client_overconfident_handshake_only_listener_wins(self) -> None:
        final, note = _agreed_verdict(Verdict.OK, Verdict.HANDSHAKE_ONLY)
        assert final == Verdict.HANDSHAKE_ONLY
        assert "client overread" in note.lower()

    def test_listener_saw_data_client_missed(self) -> None:
        # Inverse: listener has hard kernel evidence of data (iptables
        # counter ticked, auth-validated bytes), but the client probe
        # gave up early or took an error path. Listener wins, note
        # surfaces the asymmetry.
        final, note = _agreed_verdict(Verdict.HANDSHAKE_ONLY, Verdict.OK)
        assert final == Verdict.OK
        assert "listener saw data" in note.lower()

    def test_other_disagreements_show_client_in_note(self) -> None:
        # E.g. client says ERROR (probe binary blew up), listener says
        # BLOCKED (no traffic ever reached). Final is listener's, note
        # surfaces the client side so the operator sees the divergence.
        final, note = _agreed_verdict(Verdict.ERROR, Verdict.BLOCKED)
        assert final == Verdict.BLOCKED
        assert "client=ERROR" in note
