"""
Tests for :func:`censprobe_listener.main._generate_session_id`.

Operator no longer hand-types ``--session-id``; the listener mints one
from the two network-context booleans plus a short random suffix. The
prefix encoding is part of the file-naming contract — operators eyeball
``ls reports/<test_id>/`` and recognise sessions at a glance — so it
needs a deterministic mapping locked in by tests.
"""

from __future__ import annotations

import re

from censprobe_listener.main import _generate_session_id


class TestPrefixEncoding:
    """The four mobile×whitelist combinations map to distinct prefixes."""

    def test_neither_flag_uses_plain_prefix(self) -> None:
        sid = _generate_session_id(is_mobile=False, is_whitelist=False)
        assert sid.startswith("plain-")

    def test_only_mobile_uses_mob_prefix(self) -> None:
        sid = _generate_session_id(is_mobile=True, is_whitelist=False)
        assert sid.startswith("mob-")
        # Mustn't slip a "white" substring in — would mis-encode the flag.
        assert "white" not in sid

    def test_only_whitelist_uses_white_prefix(self) -> None:
        sid = _generate_session_id(is_mobile=False, is_whitelist=True)
        assert sid.startswith("white-")
        # Same defensive check for the symmetric direction.
        assert "mob" not in sid

    def test_both_flags_uses_mob_white_prefix(self) -> None:
        sid = _generate_session_id(is_mobile=True, is_whitelist=True)
        assert sid.startswith("mob-white-")


class TestSuffixShape:
    """The random tail keeps multiple sessions for one test_id unique."""

    _suffix_re = re.compile(r"-[0-9A-F]{4}$")

    def test_suffix_is_four_uppercase_hex_chars(self) -> None:
        sid = _generate_session_id(is_mobile=False, is_whitelist=False)
        assert self._suffix_re.search(sid), f"unexpected suffix in {sid!r}"

    def test_distinct_calls_produce_distinct_ids(self) -> None:
        # 1-in-65536 collision per pair — twenty samples is effectively
        # zero risk and catches a regression that drops the random part.
        samples = {_generate_session_id(is_mobile=False, is_whitelist=False) for _ in range(20)}
        assert len(samples) >= 19  # one accidental match still tolerable


class TestSafeIdContract:
    """Generated IDs must clear the same SAFE_ID_RE regex the listener
    used to validate the operator-typed ``--session-id`` argument. Without
    this, FastAPI's ``TestIdPath`` would 422 the value or filesystem
    path-traversal guards would reject the report filename."""

    _safe_id_re = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

    def test_plain_session_id_matches_safe_id_re(self) -> None:
        sid = _generate_session_id(is_mobile=False, is_whitelist=False)
        assert self._safe_id_re.match(sid), f"{sid!r} fails SAFE_ID_RE"

    def test_combined_prefix_session_id_matches_safe_id_re(self) -> None:
        # `mob-white-AAAA` is the longest prefix we'd ever emit; verify
        # the dash-separated form clears the validator too.
        sid = _generate_session_id(is_mobile=True, is_whitelist=True)
        assert self._safe_id_re.match(sid), f"{sid!r} fails SAFE_ID_RE"
