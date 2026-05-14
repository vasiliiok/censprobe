"""Shared diagnostic-note strings used by both listener and client.

These strings end up in two places:
  * ``ProtocolResult.note`` in the listener-side JSON report (and
    therefore the dashboard).
  * The "Note" column of the client-side cross-verify table.

Keeping them in one module guarantees the listener-written note and
the client cross-verifier's note for the SAME bug-shape are identical
— previously the two sides each had their own string literal and a
typo in either drifted the operator-visible wording.

When you add a new diagnostic shape:
  1. Add a constant here with a descriptive name.
  2. Reference the constant from both producer sites.
  3. The cross-verifier test (test_cross_verification.py) checks
     against the constants so a rename surfaces immediately.
"""

from __future__ import annotations

# Asymmetric DPI: client BLOCKED with read-timeout-after-handshake, but
# the listener saw the L4 handshake. Two pcap-confirmed shapes both
# land here — see _agreed_verdict docstring. Same attribution applies
# regardless of which direction the data plane filter sits in.
NOTE_ASYMMETRIC_DPI = "asymmetric DPI: handshake passed, data plane filtered"

# Dual-vantage Telegram-DC unreachable: listener egress can't reach the
# Telegram DC fleet (preflight ``telegram-dc-reach`` failed 0/N), so the
# inner Telegram session can never complete regardless of the client's
# data plane. Shorter form used in the cross-verify table column.
NOTE_LISTENER_DC_UNREACHABLE_SHORT = (
    "listener egress to Telegram DCs blocked — no DC relay possible"
)

# Longer form used in the listener-side ProtocolResult.note (which
# ends up verbatim in the JSON report and Grafana cell). Spells out
# the WelcomePacket mechanism that misleads the OK reading, so an
# operator reading the report doesn't need to dig into the source
# to understand why mtg counters ticked but the session didn't work.
NOTE_LISTENER_DC_UNREACHABLE_LONG = (
    "listener egress to Telegram DCs blocked at preflight "
    "(telegram-dc-reach 0/N) — mtg accepted the FakeTLS "
    "handshake locally but cannot relay to a real DC, so "
    "client-side resPQ never arrives. The end-to-end protocol "
    "is unusable from this listener vantage, independent of "
    "any client-side DPI."
)

# Client said OK, listener saw less (BLOCKED / HANDSHAKE_ONLY). Common
# on Docker Desktop where the host netstack spoofs ICMP/UDP locally,
# and on amneziawg-go's loopback quirk.
NOTE_CLIENT_OVERREAD = "client overread (listener saw less)"

# Listener has hard kernel evidence (iptables counter ticked, auth-
# validated bytes) but the client probe gave up early or took an error
# path. Listener wins; note surfaces the asymmetry so an operator can
# investigate why the client probe didn't see what the wire did.
NOTE_LISTENER_SAW_DATA = "listener saw data the client missed"
