"""
Tests for utils.validate_id.

Security-critical: ``test_id`` and ``session_id`` flow into filesystem
paths (``reports/<id>/...``) and into Postgres row keys. Anything that
can path-traverse, smuggle a NULL byte, or break SQL/Grafana templating
must be rejected.
"""

from __future__ import annotations

import pytest
from censprobe_core.utils import validate_id


class TestValidIds:
    @pytest.mark.parametrize(
        "value",
        [
            "vultr-fra-01",
            "client-mobile-mts-msk",
            "test_id_42",
            "x",  # 1 char min
            "a.b-c_d",
            "0",
            "A" * 64,  # 64 char max
        ],
    )
    def test_valid(self, value: str) -> None:
        assert validate_id("test_id", value) == value


class TestRejectsTraversal:
    # NB: bare "." and ".." are accepted by the current regex (the dot is
    # in the allowed character class). Path-traversal protection here is
    # entirely via separator rejection — slashes / backslashes are not in
    # the allowed set, so ../etc/passwd, foo/../bar, etc. are rejected.
    # A bare ".." can still cause issues if the caller naively joins it
    # into a path, but that's the caller's contract — see the tests below.
    @pytest.mark.parametrize(
        "value",
        [
            "../etc/passwd",
            "foo/../bar",
            "/etc/passwd",
            "foo/bar",
            "C:\\Windows",
            "a\\b",
            "..\\..\\Windows",
        ],
    )
    def test_path_traversal_rejected(self, value: str) -> None:
        with pytest.raises(ValueError, match="must match"):
            validate_id("test_id", value)


class TestRejectsControlAndUnicode:
    @pytest.mark.parametrize(
        "value",
        [
            "\x00",  # NULL byte
            "foo\x00bar",
            "foo\nbar",
            "foo\rbar",
            "foo\tbar",
            "foo\u200bbar",  # zero-width space
            "foo\u202ebar",  # right-to-left override (display attack)
            "café",  # non-ASCII
            "тест",  # cyrillic
        ],
    )
    def test_special_chars_rejected(self, value: str) -> None:
        with pytest.raises(ValueError):
            validate_id("test_id", value)


class TestRejectsLengthBoundary:
    def test_empty_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_id("test_id", "")

    def test_too_long_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_id("test_id", "A" * 65)


class TestErrorMessage:
    def test_message_names_field(self) -> None:
        # Message must include the offending field name so operators
        # know which CLI flag to fix.
        with pytest.raises(ValueError, match="session_id"):
            validate_id("session_id", "../bad")

    def test_message_includes_value(self) -> None:
        # Including the value (repr-quoted) is the only way an operator
        # can trace what they actually passed in vs what they thought.
        with pytest.raises(ValueError, match=r"'\.\./bad'"):
            validate_id("test_id", "../bad")
