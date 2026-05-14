"""
Tests for ``modules.telegram._has_ipv6_default_route``.

The IPv6 capability gate decides whether to fire the per-DC v6 ladder
or roll up to a single ``telegram_ipv6_skipped`` marker. Pre-2026-05-14
the gate checked only kernel-stack availability, which let hosts with
a v6 stack but no global route through — every DC v6 probe then failed
with EHOSTUNREACH and the dashboard filled with ~15 indistinguishable
INCONCLUSIVE rows. The route-check fix narrows the gate to "v6 stack
AND a non-loopback default route" so those rows collapse into one.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from censprobe_core.modules import telegram as telegram_mod


@pytest.fixture
def proc_route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Redirect ``_has_ipv6_default_route``'s open() at a temp file."""
    fake = tmp_path / "ipv6_route"

    real_open = open

    def _patched_open(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path) == "/proc/net/ipv6_route":
            return real_open(fake, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _patched_open)
    yield fake


_ZERO_ADDR = "0" * 32
_ROUTE_PAD = " ".join(
    [_ZERO_ADDR, "00", _ZERO_ADDR, "00000064", "00000000", "00000000", "00000003"]
)


def _route_line(dest_hex: str, dest_plen: str, iface: str) -> str:
    # Format: dest_addr dest_plen src_addr src_plen next_hop metric refcount use flags iface
    # 10 fields total — we only care about dest_addr, dest_plen, and iface (col 9).
    return f"{dest_hex} {dest_plen} {_ROUTE_PAD} {iface}\n"


class TestHasIpv6DefaultRoute:
    def test_default_route_via_eth0_returns_true(self, proc_route: Path) -> None:
        # Default route (all-zero dest, plen "00") via eth0 → present.
        proc_route.write_text(_route_line("0" * 32, "00", "eth0"))
        assert telegram_mod._has_ipv6_default_route() is True

    def test_default_route_via_loopback_excluded(self, proc_route: Path) -> None:
        # A default route via loopback is not a real global path.
        proc_route.write_text(_route_line("0" * 32, "00", "lo"))
        assert telegram_mod._has_ipv6_default_route() is False

    def test_only_link_local_returns_false(self, proc_route: Path) -> None:
        # fe80::/10 link-local — non-zero dest, not a default.
        link_local = "fe80" + "0" * 28
        proc_route.write_text(_route_line(link_local, "40", "eth0"))
        assert telegram_mod._has_ipv6_default_route() is False

    def test_empty_table_returns_false(self, proc_route: Path) -> None:
        proc_route.write_text("")
        assert telegram_mod._has_ipv6_default_route() is False

    def test_malformed_line_skipped_not_raised(self, proc_route: Path) -> None:
        # First line has < 10 fields (skipped), second is a real default route.
        proc_route.write_text("incomplete line\n" + _route_line("0" * 32, "00", "eth0"))
        assert telegram_mod._has_ipv6_default_route() is True

    def test_missing_proc_file_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # On hosts without /proc (BSD, Darwin CI, stripped containers),
        # conservatively report no v6 route.
        real_open = open

        def _missing(path: Any, *args: Any, **kwargs: Any) -> Any:
            if str(path) == "/proc/net/ipv6_route":
                raise OSError("ENOENT")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _missing)
        assert telegram_mod._has_ipv6_default_route() is False
