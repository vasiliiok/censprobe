"""Regression tests for ``_cert_san_covers_domain_family``.

Reproduces the May 2026 ya-zone-a finding: ``dns_dw_com_system`` reported
ANOMALY with ``cert_valid: false`` even though the TLS module on the
same IP (194.55.30.46) succeeded with a chain-valid ``*.dw.com`` cert
issued by Thawte. The previous strict ``check_hostname=True`` rejected
``*.dw.com`` for SNI ``dw.com`` because RFC 6125 says wildcards do not
cover the bare apex — but DW (and many enterprises) deploy exactly that
configuration. Treating it as MITM-evidence drove down score confidence
on every run.

The SAN-with-apex-relaxation helper resolves that without weakening the
detection of real CA-cert MITMs (cert valid but SAN unrelated to
target domain).
"""

from __future__ import annotations

from censprobe_core.modules.dns import _cert_san_covers_domain_family


def _cert(*sans: str) -> dict[str, object]:
    """Build a cert dict shaped like ``ssl.SSLSocket.getpeercert()``."""
    return {"subjectAltName": tuple(("DNS", s) for s in sans)}


def _cert_cn_only(common_name: str) -> dict[str, object]:
    """Cert with no SAN entries — only Subject CommonName."""
    return {"subject": ((("commonName", common_name),),)}


def _cert_cn_plus_san(common_name: str, *sans: str) -> dict[str, object]:
    """Cert with both Subject CN and SAN list."""
    return {
        "subject": ((("commonName", common_name),),),
        "subjectAltName": tuple(("DNS", s) for s in sans),
    }


class TestApexRelaxation:
    def test_wildcard_covers_apex(self) -> None:
        """The DW regression: *.dw.com presented for SNI=dw.com is authentic."""
        assert _cert_san_covers_domain_family(_cert("*.dw.com"), "dw.com") is True

    def test_wildcard_plus_explicit_apex(self) -> None:
        """When cert lists both the apex and the wildcard, the apex wins first."""
        assert _cert_san_covers_domain_family(_cert("dw.com", "*.dw.com"), "dw.com") is True

    def test_explicit_apex_only(self) -> None:
        """Standard cert with the apex SAN entry works without relaxation."""
        assert _cert_san_covers_domain_family(_cert("example.com"), "example.com") is True


class TestStandardWildcard:
    def test_one_label_match(self) -> None:
        assert _cert_san_covers_domain_family(_cert("*.example.com"), "www.example.com") is True

    def test_no_two_label_match(self) -> None:
        """Wildcards do NOT span multiple labels (RFC 6125)."""
        cert = _cert("*.example.com")
        assert _cert_san_covers_domain_family(cert, "a.b.example.com") is False

    def test_unrelated_wildcard_rejected(self) -> None:
        """The CA-cert MITM case: wildcard for an unrelated domain."""
        cert = _cert("*.attacker.example", "attacker.example")
        assert _cert_san_covers_domain_family(cert, "dw.com") is False


class TestEdgeCases:
    def test_empty_san_list(self) -> None:
        assert _cert_san_covers_domain_family({"subjectAltName": ()}, "example.com") is False

    def test_missing_san_field(self) -> None:
        assert _cert_san_covers_domain_family({}, "example.com") is False

    def test_ip_san_ignored(self) -> None:
        """IP Address SANs do not satisfy a DNS-name target."""
        cert = {"subjectAltName": (("IP Address", "192.0.2.1"),)}
        assert _cert_san_covers_domain_family(cert, "example.com") is False

    def test_case_insensitive(self) -> None:
        assert _cert_san_covers_domain_family(_cert("*.DW.COM"), "dw.com") is True
        assert _cert_san_covers_domain_family(_cert("*.dw.com"), "DW.COM") is True

    def test_trailing_dot_normalised(self) -> None:
        assert _cert_san_covers_domain_family(_cert("*.dw.com."), "dw.com.") is True


class TestCommonNameFallback:
    """SAN-less legacy certs fall back to Subject CN.

    Mirrors Python's default ``check_hostname=True`` behaviour: SAN takes
    precedence; CN is consulted only when the SAN list contains no DNS
    entries. Real public CAs have been SAN-mandatory since 2017
    (CAB Forum baseline), so this branch is effectively dead-letter for
    our targets; tested for parity with the prior strict check_hostname
    implementation.
    """

    def test_cn_match_when_san_absent(self) -> None:
        assert _cert_san_covers_domain_family(_cert_cn_only("example.com"), "example.com") is True

    def test_cn_wildcard_apex_match_when_san_absent(self) -> None:
        # The same apex relaxation applies to a CN-only legacy cert.
        assert _cert_san_covers_domain_family(_cert_cn_only("*.dw.com"), "dw.com") is True

    def test_cn_unrelated_when_san_absent_rejected(self) -> None:
        assert _cert_san_covers_domain_family(_cert_cn_only("attacker.example"), "dw.com") is False

    def test_cn_ignored_when_san_present_and_matches(self) -> None:
        # CN matters only when SAN has no DNS entry. Here SAN matches
        # so the CN value is irrelevant — just confirm SAN wins.
        cert = _cert_cn_plus_san("attacker.example", "example.com")
        assert _cert_san_covers_domain_family(cert, "example.com") is True

    def test_cn_ignored_when_san_present_but_unrelated(self) -> None:
        # SAN list contains unrelated names → return False without
        # consulting CN. Avoids legitimising a CA-cert MITM whose
        # CN coincidentally matches the target.
        cert = _cert_cn_plus_san("example.com", "unrelated.example")
        assert _cert_san_covers_domain_family(cert, "example.com") is False

    def test_subject_field_missing(self) -> None:
        # Cert with neither SAN nor subject — defensively returns False.
        assert _cert_san_covers_domain_family({}, "example.com") is False

    def test_subject_without_common_name(self) -> None:
        cert = {"subject": ((("organizationName", "Acme Corp"),),)}
        assert _cert_san_covers_domain_family(cert, "example.com") is False
