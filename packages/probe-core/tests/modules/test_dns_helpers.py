"""
Tests for DNS module helpers — pure-function pieces that don't need a
real DNS network: ``_parse_first_nameserver`` and ``_get_isp_resolver``
(systemd-resolved fallback path).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from censprobe_core.modules import dns as dns_mod
from censprobe_core.modules.dns import _parse_first_nameserver


class TestParseFirstNameserver:
    def test_returns_first_nameserver(self) -> None:
        body = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"
        assert _parse_first_nameserver(body) == "8.8.8.8"

    def test_skips_comments_and_options(self) -> None:
        body = "# comment\noptions edns0\nnameserver 9.9.9.9\n"
        assert _parse_first_nameserver(body) == "9.9.9.9"

    def test_empty_returns_none(self) -> None:
        assert _parse_first_nameserver("") is None

    def test_no_nameserver_returns_none(self) -> None:
        # search line is parsed via prefix match, not regex.
        assert _parse_first_nameserver("search example.com\n") is None

    def test_handles_extra_whitespace(self) -> None:
        body = "  nameserver 8.8.8.8  \n"
        assert _parse_first_nameserver(body) == "8.8.8.8"

    def test_lone_nameserver_keyword_returns_none(self) -> None:
        # Defensive: a malformed "nameserver\n" line must not raise.
        assert _parse_first_nameserver("nameserver\n") is None


class TestGetIspResolver:
    """``_get_isp_resolver`` reads /etc/resolv.conf, then falls back to
    /run/systemd/resolve/resolv.conf if the primary lists only a local
    stub address (127.0.0.53 etc).

    We monkeypatch ``Path.read_text`` so the test reflects the runtime
    decision, not whatever the host happens to have configured.
    """

    def _patch_files(
        self,
        monkeypatch: pytest.MonkeyPatch,
        files: dict[str, str | OSError],
    ) -> None:
        original = Path.read_text

        def _fake(self: Path, *args: object, **kwargs: object) -> str:
            key = str(self)
            if key in files:
                value = files[key]
                if isinstance(value, OSError):
                    raise value
                return value
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", _fake)

    def test_real_upstream_returned_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_files(
            monkeypatch,
            {
                "/etc/resolv.conf": "nameserver 8.8.8.8\n",
                "/run/systemd/resolve/resolv.conf": OSError("stat"),
            },
        )
        assert dns_mod._get_isp_resolver() == "8.8.8.8"

    def test_local_stub_falls_back_to_systemd(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_files(
            monkeypatch,
            {
                "/etc/resolv.conf": "nameserver 127.0.0.53\n",
                "/run/systemd/resolve/resolv.conf": "nameserver 192.168.1.1\n",
            },
        )
        assert dns_mod._get_isp_resolver() == "192.168.1.1"

    def test_local_stub_with_no_systemd_returns_stub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Worst case: only the stub IP is visible. We return it rather
        # than None — caller decides whether to flag this in evidence.
        self._patch_files(
            monkeypatch,
            {
                "/etc/resolv.conf": "nameserver 127.0.0.53\n",
                "/run/systemd/resolve/resolv.conf": OSError("stat"),
            },
        )
        assert dns_mod._get_isp_resolver() == "127.0.0.53"

    def test_no_resolv_conf_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_files(
            monkeypatch,
            {
                "/etc/resolv.conf": OSError("missing"),
                "/run/systemd/resolve/resolv.conf": OSError("missing"),
            },
        )
        assert dns_mod._get_isp_resolver() is None
