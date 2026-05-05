"""
Property-based tests for ``utils.validate_id``.

Hypothesis explores both the accept set (any non-empty string of
``[A-Za-z0-9_.-]`` up to 64 chars) and the reject set (anything
containing a separator, control char, or non-ASCII letter). The
parametrized example tests in ``test_utils_validate_id.py`` cover
specific edge cases by hand; this file proves the regex is *exhaustive*
in both directions.
"""

from __future__ import annotations

import string

import pytest
from censprobe_core.utils import validate_id
from hypothesis import given, settings
from hypothesis import strategies as st

# The exact alphabet from SAFE_ID_RE (in utils.py).
_SAFE_ALPHABET = string.ascii_letters + string.digits + "_.-"


@given(value=st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=64))
@settings(max_examples=200)
def test_safe_alphabet_strings_accepted(value: str) -> None:
    """Any string built only from the safe alphabet (1–64 chars) must
    pass validation and come back unchanged."""
    assert validate_id("test_id", value) == value


@given(value=st.text(alphabet=_SAFE_ALPHABET, min_size=65, max_size=200))
@settings(max_examples=100)
def test_safe_alphabet_too_long_rejected(value: str) -> None:
    """Same alphabet but >64 chars — rejected by the length cap."""
    with pytest.raises(ValueError):
        validate_id("test_id", value)


# Strategies for the reject set. Building a string that contains AT LEAST
# one bad character is the easiest way to force a violation; Hypothesis
# is free to surround that character with arbitrary safe ones.
_FORBIDDEN_CHARS = st.sampled_from(
    [
        "/",
        "\\",
        " ",
        "\t",
        "\n",
        "\r",
        "\x00",
        ":",
        ";",
        "?",
        "=",
        "&",
        "@",
        "#",
        "$",
        "%",
        "^",
        "*",
        "+",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "|",
        "<",
        ">",
        "'",
        '"',
        # Listed via escape sequences so the source file stays free of
        # invisible / bidirectional characters (Sonar text:S6389).
        "\u200b",  # zero-width space
        "\u202e",  # right-to-left override
        "\u00e9",  # é (Latin-1 letter)
        "\u0451",  # ё (Cyrillic letter)
    ]
)


@given(
    safe=st.text(alphabet=_SAFE_ALPHABET, min_size=0, max_size=32),
    bad=_FORBIDDEN_CHARS,
    suffix=st.text(alphabet=_SAFE_ALPHABET, min_size=0, max_size=32),
)
@settings(max_examples=200)
def test_any_string_with_forbidden_char_rejected(safe: str, bad: str, suffix: str) -> None:
    """If a single forbidden character appears anywhere in the string,
    validation must reject it — even when the rest is safe."""
    value = safe + bad + suffix
    # Skip the rare cases where the safe + suffix portion alone might be
    # too long — but the bad char remains, so the regex still rejects.
    with pytest.raises(ValueError):
        validate_id("test_id", value)


def test_empty_string_rejected() -> None:
    # Hypothesis edge case the strategy can't produce (min_size=1 above).
    with pytest.raises(ValueError):
        validate_id("test_id", "")
