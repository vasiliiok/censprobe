"""Tests for ``_parse_ping_received`` and ``_parse_ping_avg_rtt``.

Extracted from ``ping_echo`` in 2026-05-14 to reduce cognitive
complexity (Sonar S3776 was reporting CC=21). The helpers themselves
have no side-effects — these tests pin the iputils stdout shapes we
parse and the failure modes we tolerate (missing line, malformed
field, unparseable number) so a future iputils release that nudges
the output format gets caught at unit-test time rather than producing
silent zero-RTT readings in the dashboard.
"""

from __future__ import annotations

from censprobe_core.protocol_probes import _parse_ping_avg_rtt, _parse_ping_received


class TestParsePingReceived:
    def test_canonical_summary_line(self) -> None:
        out = (
            "PING 1.2.3.4 (1.2.3.4) 56(84) bytes of data.\n"
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.123 ms\n"
            "\n"
            "--- 1.2.3.4 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
            "rtt min/avg/max/mdev = 0.067/0.094/0.123/0.024 ms\n"
        )
        assert _parse_ping_received(out) == 3

    def test_partial_packet_loss(self) -> None:
        # 1/3 received — the value we care about for min_received gating.
        out = "3 packets transmitted, 1 received, 66% packet loss, time 2003ms\n"
        assert _parse_ping_received(out) == 1

    def test_zero_received(self) -> None:
        out = "3 packets transmitted, 0 received, 100% packet loss, time 2003ms\n"
        assert _parse_ping_received(out) == 0

    def test_missing_summary_returns_zero(self) -> None:
        # If iputils didn't even emit a summary (totally broken output,
        # truncated stderr-as-stdout), default to zero — caller's
        # min_received gate will treat that the same as a failure.
        out = "Total nonsense\nno summary line here\n"
        assert _parse_ping_received(out) == 0

    def test_malformed_summary_returns_zero(self) -> None:
        # Summary line exists but the "X received" token isn't a number.
        # Defensive parse should NOT raise; returns 0 so caller fails
        # the data-plane gate (correct conservative behaviour).
        out = "3 packets transmitted, ??? received, x% packet loss\n"
        assert _parse_ping_received(out) == 0

    def test_empty_output(self) -> None:
        assert _parse_ping_received("") == 0


class TestParsePingAvgRtt:
    def test_canonical_rtt_line(self) -> None:
        out = "rtt min/avg/max/mdev = 0.067/0.094/0.123/0.024 ms\n"
        assert _parse_ping_avg_rtt(out) == 0.094

    def test_full_ping_output(self) -> None:
        out = (
            "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n"
            "64 bytes from 8.8.8.8: icmp_seq=1 ttl=119 time=5.42 ms\n"
            "--- 8.8.8.8 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 2004ms\n"
            "rtt min/avg/max/mdev = 5.421/5.789/6.111/0.282 ms\n"
        )
        assert _parse_ping_avg_rtt(out) == 5.789

    def test_no_rtt_line_returns_none(self) -> None:
        # 0% reply case: ping prints no RTT summary at all.
        out = "3 packets transmitted, 0 received, 100% packet loss\n"
        assert _parse_ping_avg_rtt(out) is None

    def test_malformed_rtt_line_returns_none(self) -> None:
        # The "= " separator is there but the value side is garbage.
        out = "rtt min/avg/max/mdev = lol/wat/ok/no ms\n"
        assert _parse_ping_avg_rtt(out) is None

    def test_rtt_line_without_equals_returns_none(self) -> None:
        # Starts with "rtt " and contains "/" but no `=` — possible in
        # locale-translated busybox builds. Don't crash; return None.
        out = "rtt info: 1.5/2.3/4.1/0.5 ms\n"
        assert _parse_ping_avg_rtt(out) is None

    def test_empty_output(self) -> None:
        assert _parse_ping_avg_rtt("") is None
