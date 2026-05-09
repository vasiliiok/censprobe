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
