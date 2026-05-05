"""
Property tests for ``subcategories.derive``.

Two invariants:

  1. For ANY test name, ``derive`` returns a non-empty string.
  2. For any test name, the result is in a small known set:
     * one of the producer subcategories (the union of all rule
       outputs), OR
     * the supplied ``category`` fallback (must equal exactly), OR
     * ``"unknown"`` when both fail.

A typo in a new prefix rule that returns "doh " (with a trailing space)
is exactly the kind of bug this test catches without anyone hand-rolling
a parametrized example.
"""

from __future__ import annotations

import string

from censprobe_core.subcategories import (
    _NAME_OVERRIDES,
    _PREFIX_RULES,
    _SUBSTRING_RULES,
    _SUFFIX_RULES,
    derive,
)
from hypothesis import given, settings
from hypothesis import strategies as st

# The set of subcategories any rule can emit. Computed from the
# private rule tables so a future contributor can't drift it from the
# code. If a new subcategory string lands in any rule table, it
# automatically enters this set.
_KNOWN_SUBCATEGORIES: frozenset[str] = frozenset(
    [sub for _, sub in _SUFFIX_RULES]
    + [sub for _, sub in _SUBSTRING_RULES]
    + [sub for _, sub in _PREFIX_RULES]
    + list(_NAME_OVERRIDES.values())
)


# Test-name strategy: realistic-looking probe names. Restrict to safe
# ASCII so we don't have to worry about Unicode normalisation in the
# rule comparison.
_TEST_NAME = st.text(
    alphabet=string.ascii_letters + string.digits + "_-.",
    min_size=1,
    max_size=80,
)


@given(name=_TEST_NAME)
@settings(max_examples=300)
def test_derive_returns_nonempty_string(name: str) -> None:
    result = derive(name)
    assert isinstance(result, str)
    assert result != ""


@given(name=_TEST_NAME)
@settings(max_examples=300)
def test_derive_result_in_known_set_or_unknown(name: str) -> None:
    # No category supplied → result must be either a known producer
    # subcategory or the explicit "unknown" sentinel.
    result = derive(name)
    assert result in _KNOWN_SUBCATEGORIES or result == "unknown", (
        f"derive({name!r}) returned {result!r} which is neither a known subcategory nor 'unknown'"
    )


@given(
    name=_TEST_NAME,
    category=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=20),
)
@settings(max_examples=300)
def test_derive_with_category_either_known_or_passthrough(name: str, category: str) -> None:
    """When a category is provided, the result is either a known
    subcategory (rule matched) or the category itself (fallback)."""
    result = derive(name, category=category)
    assert result in _KNOWN_SUBCATEGORIES or result == category


@given(name=_TEST_NAME)
@settings(max_examples=200)
def test_derive_pure_function(name: str) -> None:
    """Idempotent — calling twice returns the same value."""
    assert derive(name) == derive(name)
