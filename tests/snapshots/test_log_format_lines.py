"""Snapshot tests for INFO-log format strings.

These tests pin the EXACT wording of the three log-line shapes emitted
by listener and client (preflight / probe / cross-verify) so an
accidental whitespace or punctuation change is caught at test time
rather than breaking grep patterns operators have built up.

If you intentionally change a format here, update the expected strings
below in the same commit so the contract is explicit. The tests are
golden-string comparisons — no fuzzy matching, no regex — to keep
"what does this line look like" one Read away.
"""

from __future__ import annotations

from censprobe_core._log_format import (
    format_cross_verify_line,
    format_preflight_line,
    format_probe_line,
)
from censprobe_core.models import Verdict


class TestPreflightLine:
    def test_ok_status(self) -> None:
        line = format_preflight_line("conntrack", "ok", "65k entries free")
        assert line == "preflight[ok] conntrack: 65k entries free"

    def test_warn_status(self) -> None:
        line = format_preflight_line(
            "telegram-dc-reach",
            "warn",
            "0/3 Telegram DCs reachable from listener egress",
        )
        assert line == (
            "preflight[warn] telegram-dc-reach: 0/3 Telegram DCs reachable from listener egress"
        )

    def test_skip_status(self) -> None:
        line = format_preflight_line("dmesg-recent-drops", "skip", "no dmesg access")
        assert line == "preflight[skip] dmesg-recent-drops: no dmesg access"


class TestProbeLine:
    def test_full_signals(self) -> None:
        line = format_probe_line(
            name="shadowsocks",
            verdict=Verdict.OK,
            elapsed_ms=12663.4,
            rtt_ms=364.2,
            throughput_mbps=5.7,
            error=None,
        )
        assert line == (
            "probe[shadowsocks] verdict=OK elapsed=12663ms rtt=364ms throughput=5.70Mbps error=none"
        )

    def test_blocked_with_error(self) -> None:
        line = format_probe_line(
            name="mtproto_orig",
            verdict=Verdict.BLOCKED,
            elapsed_ms=3176.0,
            rtt_ms=None,
            throughput_mbps=None,
            error="connection_refused",
        )
        assert line == (
            "probe[mtproto_orig] verdict=BLOCKED elapsed=3176ms "
            "rtt=n/a throughput=n/a error=connection_refused"
        )

    def test_missing_elapsed_renders_zero(self) -> None:
        # elapsed_ms=None happens on the rare error-path before the
        # _stamp_elapsed decorator fires. Render as "0" rather than
        # "None" so the line stays parseable.
        line = format_probe_line(
            name="hysteria2",
            verdict=Verdict.ERROR,
            elapsed_ms=None,
            rtt_ms=None,
            throughput_mbps=None,
            error="ssl: bad cert",
        )
        assert line == (
            "probe[hysteria2] verdict=ERROR elapsed=0ms rtt=n/a throughput=n/a error=ssl: bad cert"
        )


class TestCrossVerifyLine:
    def test_agree_no_note(self) -> None:
        line = format_cross_verify_line(
            name="wireguard",
            client=Verdict.OK,
            listener=Verdict.OK,
            dc_reach_ok=None,
            client_error=None,
            final="OK",
            note="",
        )
        assert line == (
            "cross-verify[wireguard] client=OK listener=OK dc_reach_ok=None "
            "client_error=none → final=OK note=agree"
        )

    def test_dc_unreachable_note(self) -> None:
        line = format_cross_verify_line(
            name="mtproto_proxy",
            client=Verdict.BLOCKED,
            listener=Verdict.OK,
            dc_reach_ok=False,
            client_error="orig_resPQ_len_timeout_post_init",
            final="HANDSHAKE_ONLY",
            note="listener egress to Telegram DCs blocked — no DC relay possible",
        )
        assert line == (
            "cross-verify[mtproto_proxy] "
            "client=BLOCKED listener=OK dc_reach_ok=False "
            "client_error=orig_resPQ_len_timeout_post_init "
            "→ final=HANDSHAKE_ONLY "
            "note=listener egress to Telegram DCs blocked — no DC relay possible"
        )

    def test_asymmetric_dpi_note(self) -> None:
        line = format_cross_verify_line(
            name="mtproto_proxy",
            client=Verdict.BLOCKED,
            listener=Verdict.OK,
            dc_reach_ok=True,
            client_error="welcome_read_timeout_record0",
            final="HANDSHAKE_ONLY",
            note="asymmetric DPI: handshake passed, data plane filtered",
        )
        assert line == (
            "cross-verify[mtproto_proxy] "
            "client=BLOCKED listener=OK dc_reach_ok=True "
            "client_error=welcome_read_timeout_record0 "
            "→ final=HANDSHAKE_ONLY "
            "note=asymmetric DPI: handshake passed, data plane filtered"
        )
