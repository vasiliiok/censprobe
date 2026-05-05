"""
Tests for ``modules.telegram._compile_owned_patterns`` and
``_match_owned_cert``.

The cert-pattern check decides whether a TLS cert presented by a CDN
endpoint actually belongs to Telegram. Glob patterns from
telegram.yaml use single-label wildcards (RFC 6125 cert-wildcard
semantics): ``*.t.me`` matches ``cdn.t.me`` but NOT ``evil.example.t.me``.
"""

from __future__ import annotations

import datetime as dt

from censprobe_core.modules.telegram import _compile_owned_patterns, _match_owned_cert


def _build_cert(*, cn: str | None = None, sans: list[str] | None = None) -> bytes:
    """Build a minimal self-signed cert with the given CN + SANs.

    Uses the cryptography backend the production code already imports.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    name_attrs = []
    if cn is not None:
        name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, "US"))
    subject = issuer = x509.Name(name_attrs)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2020, 1, 1))
        .not_valid_after(dt.datetime(2030, 1, 1))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(private_key=key, algorithm=None)
    return cert.public_bytes(serialization.Encoding.DER)


class TestCompileOwnedPatterns:
    def test_star_matches_one_label_only(self) -> None:
        patterns = _compile_owned_patterns(["*.t.me"])
        assert len(patterns) == 1
        # cdn.t.me (single-label) matches.
        assert patterns[0].match("cdn.t.me")
        # Multi-label name does NOT match.
        assert not patterns[0].match("evil.cdn.t.me")
        # Bare base does not match either (the * requires at least one char).
        assert not patterns[0].match("t.me")

    def test_literal_pattern_exact_match(self) -> None:
        patterns = _compile_owned_patterns(["telegram.org"])
        assert patterns[0].match("telegram.org")
        assert not patterns[0].match("evil.telegram.org")

    def test_case_insensitive(self) -> None:
        patterns = _compile_owned_patterns(["*.T.me"])
        assert patterns[0].match("CDN.t.me")


class TestMatchOwnedCert:
    def test_match_via_san(self) -> None:
        patterns = _compile_owned_patterns(["*.t.me", "telegram.org"])
        cert = _build_cert(sans=["www.t.me", "cdn.t.me"])
        # The first matching SAN (in order) is returned.
        match = _match_owned_cert(cert, patterns)
        assert match in {"www.t.me", "cdn.t.me"}

    def test_match_via_cn_when_no_san(self) -> None:
        patterns = _compile_owned_patterns(["telegram.org"])
        cert = _build_cert(cn="telegram.org")
        assert _match_owned_cert(cert, patterns) == "telegram.org"

    def test_no_match_returns_none(self) -> None:
        patterns = _compile_owned_patterns(["*.t.me"])
        cert = _build_cert(sans=["evil.example.com"])
        assert _match_owned_cert(cert, patterns) is None

    def test_no_patterns_returns_none(self) -> None:
        # Empty patterns list short-circuits — never returns a match.
        cert = _build_cert(sans=["www.t.me"])
        assert _match_owned_cert(cert, []) is None

    def test_malformed_cert_returns_none(self) -> None:
        patterns = _compile_owned_patterns(["*.t.me"])
        # Garbage DER → cryptography raises; helper returns None.
        assert _match_owned_cert(b"not a cert", patterns) is None
