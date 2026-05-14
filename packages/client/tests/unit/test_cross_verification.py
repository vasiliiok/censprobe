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

    def test_data_transfer_ok_overrides_zero_handshake(self) -> None:
        # ``data_transfer_ok=True`` is the cryptographic / kernel ground
        # truth — bytes don't arrive at the echo server, the WG rx_bytes
        # counter, or the OpenVPN/mtg iptables PSH+ACK counter without a
        # successful handshake. ``handshake_count`` for SOCKS-routed
        # responders and mtproto_proxy comes from substring-matching the
        # foreign binary's stdout, which silently drifts with xray /
        # sing-box / hysteria / mtg releases. If the log parser missed
        # the marker but data actually flowed, the verdict must follow
        # the data signal — the old "still BLOCKED" branch turned every
        # log-format drift into a false negative on the listener side.
        # OpenVPN-side scanner-resistance is enforced upstream by an
        # AND-gate on ``data_transfer_ok`` itself (see openvpn_responder
        # ``data_transfer_ok`` docstring), so the responders that need
        # the strict gate already provide it.
        snap = LiveSnapshot(handshake_count=0, data_transfer_ok=True, data_packets=8)
        assert _listener_verdict(snap) == Verdict.OK


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


class TestAsymmetricDpiDetection:
    """``_agreed_verdict`` downgrades listener=OK/HANDSHAKE_ONLY +
    client=BLOCKED to HANDSHAKE_ONLY when client error matches a
    read-timeout-after-handshake marker. Two distinct shapes verified
    in production pcaps:

      * MTS RU 2026-05-13: listener sent the mtg faketls SERVER_HELLO
        (iptables PSH-ACK counter ticked), but the client never
        received it — TSPU dropped the server→client leg.
      * Selectel→Vultr 2026-05-13: L4 handshake both directions,
        ClientHello PSH-ACK retransmits never arrived at the listener
        — c→s payload dropped, server never responded.

    The listener cannot distinguish the two from its counters alone,
    so the attribution note stays direction-agnostic. Either way the
    protocol is NOT usable, and masking it as OK based purely on the
    listener counter would be wrong."""

    def test_listener_ok_client_blocked_with_welcome_timeout_is_handshake_only(
        self,
    ) -> None:
        final, note = _agreed_verdict(
            Verdict.BLOCKED,
            Verdict.OK,
            client_error="welcome_read_timeout_record0",
        )
        assert final == Verdict.HANDSHAKE_ONLY
        assert "asymmetric" in note.lower()
        assert "data plane filtered" in note.lower()

    def test_listener_ok_client_blocked_with_orig_respq_timeout_is_handshake_only(
        self,
    ) -> None:
        # mtproto_orig (C MTProxy obfuscated2 path) version of the
        # same read-timeout-after-handshake signature.
        final, note = _agreed_verdict(
            Verdict.BLOCKED,
            Verdict.OK,
            client_error="orig_resPQ_len_timeout_post_init",
        )
        assert final == Verdict.HANDSHAKE_ONLY
        assert "asymmetric" in note.lower()

    def test_listener_ok_client_blocked_with_other_error_stays_ok(self) -> None:
        # ``connection_refused`` does NOT indicate a server reply was
        # dropped — it indicates the client never reached the server
        # at all (Docker loopback artefact, host-firewall, etc.). In
        # that state the listener's OK reading is still authoritative.
        final, note = _agreed_verdict(
            Verdict.BLOCKED,
            Verdict.OK,
            client_error="connection_refused",
        )
        assert final == Verdict.OK
        assert "listener saw data" in note.lower()

    def test_listener_ok_client_blocked_with_no_error_stays_ok(self) -> None:
        # Backward compatibility with callers that don't pass
        # ``client_error``. Should never apply the downgrade.
        final, note = _agreed_verdict(Verdict.BLOCKED, Verdict.OK)
        assert final == Verdict.OK
        assert "listener saw data" in note.lower()

    def test_listener_handshake_only_client_blocked_with_timeout_fires_asymmetric_note(
        self,
    ) -> None:
        # Two pcap-verified shapes both land here:
        #   * MTS RU 2026-05-13: client@google-cloud probing
        #     listener@MTS — iptables OUTPUT counter ticked once
        #     (SERVER_HELLO), no return traffic; listener.finalize()
        #     landed HANDSHAKE_ONLY (handshake_count=1,
        #     data_transfer_ok=False). Client got
        #     ``welcome_read_timeout_record0`` (s→c leg dropped).
        #   * Selectel→Vultr 2026-05-13: mtg saw the L4 accept()
        #     (stream-has-started → handshake_count=1) but ClientHello
        #     PSH-ACK retransmits never arrived; mtg never sent
        #     SERVER_HELLO. Client got the same timeout marker
        #     (c→s payload dropped). Listener cannot tell the two
        #     shapes apart from its counters alone.
        # Final verdict stays HANDSHAKE_ONLY; the note surfaces the
        # direction-agnostic asymmetric-DPI attribution instead of the
        # generic ``client=BLOCKED`` fall-through, otherwise the
        # operator cannot distinguish this from a regular
        # HANDSHAKE_ONLY-with-client-error shape.
        final, note = _agreed_verdict(
            Verdict.BLOCKED,
            Verdict.HANDSHAKE_ONLY,
            client_error="welcome_read_timeout_record0",
        )
        assert final == Verdict.HANDSHAKE_ONLY
        assert "asymmetric" in note.lower()
        assert "data plane filtered" in note.lower()

    def test_listener_handshake_only_client_blocked_no_timeout_falls_through(
        self,
    ) -> None:
        # Without an asymmetric-DPI marker, the listener-HANDSHAKE_ONLY +
        # client-BLOCKED disagreement must keep the legacy ``client=X``
        # fall-through note — the asymmetric branch must not over-
        # claim attribution when the client never even reached the
        # listener's bind port.
        final, note = _agreed_verdict(
            Verdict.BLOCKED,
            Verdict.HANDSHAKE_ONLY,
            client_error="connection_refused",
        )
        assert final == Verdict.HANDSHAKE_ONLY
        assert "client=BLOCKED" in note
