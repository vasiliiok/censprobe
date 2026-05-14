"""Tests for ``_verify_peer_cert_pin`` — the security boundary that
gates the bearer token against MitM.

Extracted from the inline pinning check in ``_pinned_get`` so it can
be unit-tested without standing up a TLS server. The function is the
sole reason the client is safe against a network attacker between
itself and the listener — chain validation is intentionally off
(self-signed cert), so pinning IS the trust mechanism. A bug here
silently leaks credentials to a MitM, hence the tests below cover
every documented failure mode + the happy path.
"""

from __future__ import annotations

import hashlib

import pytest
from censprobe_client.main import (
    _PermanentEndpointError,
    _TransientEndpointError,
    _verify_peer_cert_pin,
)

# Synthetic DER bytes — we never feed these into a real TLS context;
# only their SHA-256 fingerprint is what the function reads.
_FAKE_CERT_A = b"\x30\x82\x01\x00" + b"A" * 252
_FAKE_CERT_B = b"\x30\x82\x01\x00" + b"B" * 252


def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


class TestVerifyPeerCertPin:
    def test_matching_fingerprint_returns_silently(self) -> None:
        # Happy path: peer presents the exact cert the operator pinned.
        # Function returns None (no value) without raising.
        expected = _fingerprint(_FAKE_CERT_A)
        # No exception → pin verified.
        _verify_peer_cert_pin(_FAKE_CERT_A, expected)

    def test_mismatched_fingerprint_raises_permanent(self) -> None:
        # The most security-critical assertion in this file: a wrong cert
        # MUST raise _PermanentEndpointError (NOT transient — retrying
        # cannot fix a MitM). The error message must include both actual
        # and expected so the operator can sanity-check what they pasted.
        expected = _fingerprint(_FAKE_CERT_A)
        with pytest.raises(_PermanentEndpointError) as exc:
            _verify_peer_cert_pin(_FAKE_CERT_B, expected)
        msg = str(exc.value)
        assert _fingerprint(_FAKE_CERT_B) in msg  # what the peer showed
        assert expected in msg  # what the operator expected
        assert "fingerprint mismatch" in msg

    def test_empty_cert_raises_transient(self) -> None:
        # No cert at all = TLS handshake didn't complete properly.
        # Treat as transient so the retry wrapper has another go —
        # a mid-startup server can recover.
        expected = _fingerprint(_FAKE_CERT_A)
        with pytest.raises(_TransientEndpointError):
            _verify_peer_cert_pin(b"", expected)

    def test_none_cert_raises_transient(self) -> None:
        # getpeercert(binary_form=True) returns None when TLS hasn't
        # actually negotiated. Same handling as empty bytes.
        expected = _fingerprint(_FAKE_CERT_A)
        with pytest.raises(_TransientEndpointError):
            _verify_peer_cert_pin(None, expected)

    def test_case_insensitive_match(self) -> None:
        # _hex_eq lowercases both sides; an operator who pastes the
        # uppercase form (some terminals capitalise on copy) must still
        # see a successful pin. Verified via _pinned_get's input
        # normaliser too, but defending here is cheap insurance.
        expected_upper = _fingerprint(_FAKE_CERT_A).upper()
        # _verify_peer_cert_pin's contract says caller pre-normalises,
        # but the underlying hex compare is itself case-folding so we
        # verify that property explicitly.
        _verify_peer_cert_pin(_FAKE_CERT_A, expected_upper)

    def test_one_byte_diff_still_rejected(self) -> None:
        # The hash space is huge; flipping a single byte in the cert
        # MUST produce a totally different fingerprint and trigger
        # the mismatch branch. Defensive sanity-check that SHA-256
        # is actually being used (not e.g. a length-only comparison
        # that a future "optimisation" might introduce).
        expected = _fingerprint(_FAKE_CERT_A)
        almost_a = _FAKE_CERT_A[:-1] + bytes([_FAKE_CERT_A[-1] ^ 1])
        with pytest.raises(_PermanentEndpointError):
            _verify_peer_cert_pin(almost_a, expected)
