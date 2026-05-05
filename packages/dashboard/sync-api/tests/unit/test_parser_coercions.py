"""
Tests for parser coercion helpers (_to_float, _to_int, _parse_dt) and
the simple filename predicates (is_solo_report, is_listener_report).

These coercions sit at the boundary between disk JSON and DB rows —
they decide what wins when the producer wrote a string-of-a-number,
when a field is missing, or when a future schema sneaks in a typo.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sync_api.parser import (
    _parse_dt,
    _to_float,
    _to_int,
    is_listener_report,
    is_solo_report,
)


class TestToFloat:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, 1.0),  # default returned
            ("", 1.0),  # empty string === missing
            (3.14, 3.14),
            (42, 42.0),
            ("3.14", 3.14),
            ("nan", float("nan")),  # float() accepts it
            (True, 1.0),  # bool is a number
        ],
    )
    def test_coerce(self, value: object, expected: float) -> None:
        result = _to_float(value, default=1.0)
        if expected != expected:  # NaN
            assert result != result
        else:
            assert result == pytest.approx(expected)

    def test_default_none_passthrough(self) -> None:
        assert _to_float(None, default=None) is None

    @pytest.mark.parametrize("value", ["abc", {"x": 1}, [1, 2]])
    def test_invalid_returns_default(self, value: object) -> None:
        assert _to_float(value, default=99.0) == pytest.approx(99.0)


class TestToInt:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, 7),
            ("", 7),
            (42, 42),
            ("42", 42),
            (42.7, 42),  # truncates via int(float)
            ("42.7", 42),  # falls into the int(float()) branch
        ],
    )
    def test_coerce(self, value: object, expected: int) -> None:
        assert _to_int(value, default=7) == expected

    @pytest.mark.parametrize("value", ["abc", {}, []])
    def test_invalid_returns_default(self, value: object) -> None:
        assert _to_int(value, default=99) == 99


class TestParseDt:
    def test_iso_with_z_suffix(self) -> None:
        # The Z → +00:00 substitution is the load-bearing detail; the
        # solo writer emits "...Z" via datetime.isoformat().
        dt = _parse_dt("2026-05-04T12:34:56Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert dt == datetime(2026, 5, 4, 12, 34, 56, tzinfo=UTC)

    def test_iso_with_offset(self) -> None:
        dt = _parse_dt("2026-05-04T12:34:56+03:00")
        assert dt is not None
        assert dt.utcoffset() is not None
        assert dt.utcoffset().total_seconds() == 3 * 3600

    def test_naive_datetime_assumed_utc(self) -> None:
        dt = _parse_dt("2026-05-04T12:34:56")
        assert dt is not None
        assert dt.tzinfo == UTC

    @pytest.mark.parametrize("value", [None, "", 0, False])
    def test_falsy_returns_none(self, value: object) -> None:
        assert _parse_dt(value) is None

    @pytest.mark.parametrize("value", ["not-a-date", "2026-13-99T99:99:99Z", {}])
    def test_invalid_returns_none(self, value: object) -> None:
        # Coercion-side helper returns None on garbage rather than raising —
        # so the importer can keep running through one corrupt row.
        assert _parse_dt(value) is None


class TestFilenamePredicates:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("server-solo-2026-01-01.json", True),
            ("server-solo-x.json", True),
            ("server-listener-x.json", False),
            ("server-solo-x.txt", False),  # wrong suffix
            ("server-solo-x.json~", False),  # editor swap
            ("solo-x.json", False),  # missing prefix
        ],
    )
    def test_is_solo_report(self, name: str, expected: bool) -> None:
        assert is_solo_report(name) is expected

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("server-listener-sess-2026.json", True),
            ("server-listener-x.json", True),
            ("server-solo-x.json", False),
            ("server-listener-x.tar.gz", False),
            ("listener-sess.json", False),
        ],
    )
    def test_is_listener_report(self, name: str, expected: bool) -> None:
        assert is_listener_report(name) is expected
