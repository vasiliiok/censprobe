"""Regression tests for :meth:`OpenVPNResponder._read_status`.

Original bug: handshake count was derived from ``TCP/UDP read bytes``,
which counts *every* byte received on the listening UDP socket including
HMAC-failed scanner traffic. On a public IP this turned ZMap/Shodan/DPI
probes into phantom handshakes (e.g. "1 handshake, 144 bytes" with no
real client). The fix reads only HMAC-gated counters (Auth read bytes
and TUN/TAP read bytes) and ignores the raw socket counter.
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

    This is exactly the production false positive: public-IP listener
    with no real client, only scanner traffic, was reporting a phantom
    OpenVPN handshake. Auth=0 is the kill signal.
    """
    r = _make_responder(tmp_path, _SCANNER_NOISE_ONLY)
    handshake, tunnel_bytes = r._read_status()
    assert handshake == 0
    assert tunnel_bytes == 0


def test_real_handshake_without_data(tmp_path: Path) -> None:
    """Auth>0 with TUN/TAP=0 → handshake yes, but data_transfer_ok stays
    governed by the threshold (256 < _MIN_OVPN_BYTES would still register
    handshake; here 256 > _MIN_OVPN_BYTES=64 so transfer is also true)."""
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
    """When Auth and TUN/TAP labels are missing entirely, refuse to call
    raw TCP/UDP traffic a handshake. Better to under-report than to
    paint scanner noise as a successful connection."""
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
