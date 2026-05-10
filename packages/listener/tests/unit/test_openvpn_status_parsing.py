"""Regression tests for :meth:`OpenVPNResponder._read_status`.

Two false-positive sources had to be eliminated:

1. ``TCP/UDP read bytes`` counts *every* UDP byte hit on the listening
   socket including HMAC-failed scanner traffic — on a public IP this
   turned ZMap/Shodan/DPI probes into phantom handshakes.
2. ``TUN/TAP read bytes`` counts bytes the OpenVPN process reads *from
   the tun device* (host kernel → openvpn), which on a host-mode
   container ticks from local multicast/NDP/ICMP even when no peer ever
   connected. Observed in the wild: 192 bytes of pure host noise on a
   25-second idle session.

The only counter immune to both is ``Auth read bytes`` (HMAC-gated
against the static-key PSK). The implementation now uses ``Auth read
bytes`` as the *exclusive* signal for both handshake count and data
transfer; the other counters survive only as diagnostic context.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from censprobe_listener.openvpn_responder import OpenVPNResponder


def _make_responder(tmp_path: Path, status_text: str) -> OpenVPNResponder:
    status = tmp_path / "status.log"
    status.write_text(status_text)
    r = OpenVPNResponder(psk_pem="", port=1194)
    r._status_path = status
    return r


_SCANNER_NOISE_ONLY = """\
OpenVPN STATISTICS
Updated,Sat May  9 13:36:08 2026
TUN/TAP read bytes,0
TUN/TAP write bytes,0
TCP/UDP read bytes,144
TCP/UDP write bytes,0
Auth read bytes,0
END
"""

# Real-world capture from production: idle 25 s session, no client ever
# reached the host. Host kernel pushed multicast/NDP/ICMP into the tun
# (TUN/TAP read = 192 B), but no UDP packets arrived (TCP/UDP read = 0)
# and nothing passed HMAC (Auth read = 0).
_HOST_KERNEL_TUN_NOISE = """\
OpenVPN STATISTICS
Updated,2026-05-09 14:30:00
TUN/TAP read bytes,192
TUN/TAP write bytes,0
TCP/UDP read bytes,0
TCP/UDP write bytes,0
Auth read bytes,0
END
"""

_REAL_HANDSHAKE_NO_DATA = """\
OpenVPN STATISTICS
Updated,Sat May  9 13:36:08 2026
TUN/TAP read bytes,0
TUN/TAP write bytes,0
TCP/UDP read bytes,512
TCP/UDP write bytes,256
Auth read bytes,256
END
"""

_REAL_HANDSHAKE_WITH_DATA = """\
OpenVPN STATISTICS
Updated,Sat May  9 13:36:08 2026
TUN/TAP read bytes,4096
TUN/TAP write bytes,4096
TCP/UDP read bytes,8192
TCP/UDP write bytes,8192
Auth read bytes,8192
END
"""

# Truncated / version-skewed status file: only TCP/UDP reported, no Auth label.
_DEGRADED_TCP_UDP_ONLY = """\
OpenVPN STATISTICS
Updated,Sat May  9 13:36:08 2026
TCP/UDP read bytes,144
END
"""


def test_scanner_noise_does_not_count_as_handshake(tmp_path: Path) -> None:
    """144 bytes of TCP/UDP read + Auth=0 must NOT be a handshake.

    This is the original production false positive: public-IP listener
    with no real client, only scanner traffic, was reporting a phantom
    OpenVPN handshake. Auth=0 is the kill signal.
    """
    r = _make_responder(tmp_path, _SCANNER_NOISE_ONLY)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 0
    assert tunnel_bytes == 0


def test_host_kernel_tun_noise_does_not_count_as_handshake(tmp_path: Path) -> None:
    """192 B of TUN/TAP read + Auth=0 must NOT be a handshake.

    Real production capture: an idle listener on a host-mode container
    saw 192 B of TUN/TAP read bytes from local multicast / NDP / ICMP
    routed into the censovpn0 ptp peer route. No remote client ever
    sent a packet (TCP/UDP read = 0). Auth=0 proves nothing
    HMAC-validated, so the verdict must be 'no peer connected'. An
    earlier fix that included TUN/TAP read in the verdict would have
    produced a phantom CONNECTED here.
    """
    r = _make_responder(tmp_path, _HOST_KERNEL_TUN_NOISE)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 0
    assert tunnel_bytes == 0


def test_real_handshake_without_data(tmp_path: Path) -> None:
    """Auth>0 → handshake yes; tunnel_bytes equals Auth read bytes."""
    r = _make_responder(tmp_path, _REAL_HANDSHAKE_NO_DATA)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 1
    assert tunnel_bytes == 256


def test_real_handshake_with_full_tunnel(tmp_path: Path) -> None:
    r = _make_responder(tmp_path, _REAL_HANDSHAKE_WITH_DATA)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 1
    assert tunnel_bytes == 8192


def test_degraded_status_without_auth_label_does_not_false_positive(tmp_path: Path) -> None:
    """When the Auth label is missing entirely, refuse to call raw
    TCP/UDP or TUN/TAP traffic a handshake. Better to under-report than
    to paint host/scanner noise as a successful connection."""
    r = _make_responder(tmp_path, _DEGRADED_TCP_UDP_ONLY)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 0
    assert tunnel_bytes == 0


def test_missing_status_file(tmp_path: Path) -> None:
    r = OpenVPNResponder(psk_pem="", port=1194)
    r._status_path = tmp_path / "nonexistent.log"
    assert r._read_status() == (0, 0)


@pytest.mark.parametrize("garbage", ["", "junk", "TUN/TAP read bytes\n"])
def test_malformed_status_does_not_raise(tmp_path: Path, garbage: str) -> None:
    r = _make_responder(tmp_path, garbage)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 0
    assert tunnel_bytes == 0


# Reproduction from a real production probe (RU mobile, 2026-05-09):
# the listener reported data_transfer_ok=true with only 337 Auth-read
# bytes, even though the client never managed a successful ping. Those
# 337 bytes were entirely handshake control + a couple of keepalives,
# NOT data plane. With ``keepalive 10 60`` configured, every 10 s adds
# ~80 B of HMAC'd control traffic; over a 3-min idle session this can
# accumulate well past the historical 64-byte threshold.
_PRODUCTION_HANDSHAKE_PLUS_KEEPALIVE_NO_DATA = """\
OpenVPN STATISTICS
Updated,Sat May  9 21:26:28 2026
TUN/TAP read bytes,0
TUN/TAP write bytes,0
TCP/UDP read bytes,400
TCP/UDP write bytes,400
Auth read bytes,337
END
"""


def test_handshake_only_session_does_not_falsely_report_data_transfer(
    tmp_path: Path,
) -> None:
    """Handshake completed + keepalive ticking ≠ data transfer.

    Reproduces the false-OK observed on RU mobile 2026-05: 337 B of
    Auth-read after a 3-minute session where no client ping ever
    completed. The threshold has to clear handshake-control + a few
    keepalive intervals, otherwise an idle session that merely
    finished its TLS-static-key handshake gets reported as OK.
    """
    r = _make_responder(tmp_path, _PRODUCTION_HANDSHAKE_PLUS_KEEPALIVE_NO_DATA)
    r._final_handshake_count, r._final_bytes_received = r._read_status()
    r._snapshot_taken = True
    assert r.connection_count == 1, "handshake itself definitely happened"
    assert r.data_transfer_ok is False, (
        "337 B is handshake + keepalive only; it must NOT be classified "
        "as data transfer or the listener will report OK while the "
        "client correctly reports HANDSHAKE_ONLY (no ping completed)"
    )


def test_data_transfer_ok_true_when_real_data_flowed(tmp_path: Path) -> None:
    """Sanity: a session with substantial Auth-read bytes (well past
    handshake+keepalive accumulation) DOES still report data_ok=True.
    """
    r = _make_responder(tmp_path, _REAL_HANDSHAKE_WITH_DATA)  # Auth=8192
    r._final_handshake_count, r._final_bytes_received = r._read_status()
    r._snapshot_taken = True
    assert r.connection_count == 1
    assert r.data_transfer_ok is True


def test_data_transfer_ok_when_iptables_counter_saw_data_packets(tmp_path: Path) -> None:
    """The iptables INPUT counter is the canonical signal for short
    probe sessions where Auth-read alone never crosses the legacy
    1500-byte threshold.

    Reproduces the GCP→DE clean-path observation on 2026-05-10:
    Auth-read=337 (handshake control + a few keepalives) is below the
    fallback threshold, but ping_echo's 3 ICMP echo requests show up
    as ≥130-byte UDP packets in INPUT. The 2-packet floor (bumped
    from 1 on 2026-05-10 to defeat single-shot scanner traffic on
    UDP/1194) flips data_transfer_ok to True once two echoes arrive,
    so the listener verdict aligns with the client's OK.
    """
    r = _make_responder(tmp_path, _PRODUCTION_HANDSHAKE_PLUS_KEEPALIVE_NO_DATA)
    r._final_handshake_count, r._final_bytes_received = r._read_status()
    r._final_data_packets = 3  # 3 ICMP echo requests (ping_echo default)
    r._snapshot_taken = True
    assert r.connection_count == 1
    assert r.data_transfer_ok is True


def test_data_transfer_ok_rejects_scanner_pattern_without_handshake(tmp_path: Path) -> None:
    """Bug B regression (RU mobile 2026-05-10): listener observed
    ``handshakes=0, bytes=0, data_pkts=8`` and reported BLOCKED with
    data_transfer=yes — an inconsistent split. Eight ≥130-B UDP
    packets came in but none passed HMAC, so they were almost
    certainly Shodan/RB scanner shots on UDP/1194 on a cloud IP.

    The AND-gate against ``handshake_count > 0`` rejects this pattern:
    without an authed packet, no data-packet count is trustworthy.
    """
    r = _make_responder(tmp_path, _SCANNER_NOISE_ONLY)  # Auth=0
    r._final_handshake_count, r._final_bytes_received = r._read_status()
    r._final_data_packets = 8  # well past the threshold, but no auth
    r._snapshot_taken = True
    assert r.connection_count == 0
    assert r.data_transfer_ok is False, (
        "Without handshake_count > 0, no data-packet count can be "
        "trusted — must NOT report data_transfer=yes."
    )


def test_data_transfer_ok_rejects_single_scanner_shot_with_handshake(tmp_path: Path) -> None:
    """A single ≥130-B UDP packet on top of a real handshake is
    indistinguishable from one scanner artifact during a real session.
    Threshold 2 keeps the verdict honest.
    """
    r = _make_responder(tmp_path, _REAL_HANDSHAKE_NO_DATA)  # Auth=256 → hs=1
    r._final_handshake_count, r._final_bytes_received = r._read_status()
    r._final_data_packets = 1  # only one scanner-sized packet
    r._snapshot_taken = True
    assert r.connection_count == 1
    # 1 packet + Auth=256 (< 1500 fallback) → not enough to claim OK.
    assert r.data_transfer_ok is False


def test_data_transfer_ok_falls_back_to_auth_read_when_counter_missing(tmp_path: Path) -> None:
    """Hosts that drop iptables (e.g. macOS dev box) leave
    ``_final_data_packets`` at 0; ``data_transfer_ok`` then reverts
    to the auth-read threshold so we still flag long, data-rich
    sessions correctly.
    """
    r = _make_responder(tmp_path, _REAL_HANDSHAKE_WITH_DATA)  # Auth=8192
    r._final_handshake_count, r._final_bytes_received = r._read_status()
    r._final_data_packets = 0  # iptables not available on this host
    r._snapshot_taken = True
    assert r.data_transfer_ok is True


def test_iptables_rule_args_are_well_formed() -> None:
    """The rule args feeding ``iptables -A INPUT ...`` must lock the
    chain to inbound UDP on the configured port and require a length
    of at least 130 bytes. The comment is per-port so a future
    multi-instance setup keeps counters disjoint.
    """
    r = OpenVPNResponder(psk_pem="", port=1194)
    args = r._counter_rule_args()
    assert "-p" in args and "udp" in args
    assert "--dport" in args
    assert "1194" in args
    length_idx = args.index("--length")
    assert args[length_idx + 1].startswith("130")  # inclusive lower bound
    assert "censprobe-ovpn-data-1194" in args
