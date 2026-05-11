"""Cert pinning + fingerprint normalisation unit tests.

Sync's pull side must verify the server's TLS cert by SHA-256
fingerprint **before** sending the bearer token (otherwise a
network attacker presenting any self-signed cert + sniffing
``Authorization: Basic`` would harvest the token without alerting
us). The fingerprint check is the ONLY thing standing between
``rclone copy`` and a MitM, so we exercise:

  * Canonical / colon-separated / mixed-case fingerprint formats
    are all accepted and normalised to one form.
  * Malformed fingerprints raise ``ValueError`` BEFORE any socket
    is opened — defence-in-depth so a typo can't silently degrade
    to "first cert presented wins".
  * The DER→PEM round-trip on a verified peer cert produces a
    valid PEM that ``cryptography`` can re-parse (rclone consumes
    the PEM via ``--ca-cert`` so it has to round-trip cleanly).
  * A non-matching peer cert raises ``ValueError`` with a clear
    "fingerprint mismatch" message and does NOT return PEM bytes.
  * A successful match returns the cert as PEM.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from censprobe_sync import main as sync_main
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _make_self_signed_cert() -> tuple[bytes, str]:
    """Build a fresh throwaway cert and return its DER bytes + SHA-256
    fingerprint. Avoids calling _generate_self_signed_cert directly so
    a regression in that helper doesn't mask issues in the validator
    under test.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-pin")])
    san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()
    return der, fingerprint


class TestNormaliseFingerprint:
    def test_canonical_lowercase(self) -> None:
        fp = "a" * 64
        assert sync_main._normalise_fingerprint(fp) == fp

    def test_uppercase_normalised(self) -> None:
        assert sync_main._normalise_fingerprint("A" * 64) == "a" * 64

    def test_colon_separated_accepted(self) -> None:
        # OpenSSL prints ``aa:bb:cc:..`` style; operator might paste it.
        with_colons = ":".join(["aa"] * 32)
        assert sync_main._normalise_fingerprint(with_colons) == "aa" * 32

    def test_whitespace_stripped(self) -> None:
        assert sync_main._normalise_fingerprint("  " + "f" * 64 + "\n") == "f" * 64

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "tooshort",
            "g" * 64,  # non-hex char
            "f" * 63,  # one short
            "f" * 65,  # one long
            "ZZ" * 32,  # non-hex uppercase
        ],
    )
    def test_malformed_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="64-char hex"):
            sync_main._normalise_fingerprint(bad)


class TestFetchAndVerifyPeerCert:
    """The full TLS-fetch-and-pin path with mocked ``socket.create_connection``
    and ``ssl.SSLContext.wrap_socket`` so no real network is touched.

    The handshake side returns a controlled DER blob via
    ``getpeercert(binary_form=True)``; we let the function compute its
    own SHA-256 against it, then assert behaviour both for a matching
    and a mismatching ``expected_fingerprint``.
    """

    @staticmethod
    def _patch_tls(monkeypatch: pytest.MonkeyPatch, peer_der: bytes) -> None:
        """Wire a fake socket pair such that ``getpeercert(binary_form=True)``
        returns ``peer_der``. Everything else (close, context manager,
        timeout) is a MagicMock — the validator only reads peer cert
        and never sends bytes.
        """
        # Mock the socket — only its context-manager protocol is used.
        sock = MagicMock()
        sock.__enter__ = MagicMock(return_value=sock)
        sock.__exit__ = MagicMock(return_value=False)
        monkeypatch.setattr(sync_main.socket, "create_connection", lambda *_a, **_kw: sock)

        # Mock the SSLContext.wrap_socket result — must support context
        # manager and getpeercert(binary_form=True).
        tls = MagicMock()
        tls.__enter__ = MagicMock(return_value=tls)
        tls.__exit__ = MagicMock(return_value=False)
        tls.getpeercert = MagicMock(return_value=peer_der)

        original_ssl_context = sync_main.ssl.SSLContext

        class _FakeContext:
            def __init__(self, *a: object, **kw: object) -> None:
                self.check_hostname = False
                self.verify_mode = sync_main.ssl.CERT_NONE
                self.minimum_version = sync_main.ssl.TLSVersion.TLSv1_2

            def wrap_socket(self, *a: object, **kw: object) -> MagicMock:
                return tls

        monkeypatch.setattr(sync_main.ssl, "SSLContext", _FakeContext)
        # Restore TLSVersion/CERT_NONE constants — _FakeContext referenced
        # them via the patched module; if the test uses ``original_ssl_context``
        # later we still have it on hand. Not currently used but kept for
        # symmetry with future expansion.
        _ = original_ssl_context

    def test_matching_fingerprint_returns_pem(self, monkeypatch: pytest.MonkeyPatch) -> None:
        peer_der, fp = _make_self_signed_cert()
        self._patch_tls(monkeypatch, peer_der)

        pem = sync_main._fetch_and_verify_peer_cert("1.2.3.4", 8444, fp)
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.endswith(b"-----END CERTIFICATE-----\n")

        # Round-trip: rclone will consume the PEM via --ca-cert; ensure
        # cryptography can re-parse it back to the same SHA-256.
        round_tripped = x509.load_pem_x509_certificate(pem)
        rt_der = round_tripped.public_bytes(serialization.Encoding.DER)
        assert hashlib.sha256(rt_der).hexdigest() == fp

    def test_fingerprint_mismatch_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        peer_der, _real_fp = _make_self_signed_cert()
        self._patch_tls(monkeypatch, peer_der)

        wrong = "0" * 64
        with pytest.raises(ValueError, match="fingerprint mismatch"):
            sync_main._fetch_and_verify_peer_cert("1.2.3.4", 8444, wrong)

    def test_missing_peer_cert_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Server completed TLS handshake but didn't present a cert (this
        # can happen with anonymous ciphersuites or a misconfigured
        # server). Treat as transient rather than silently passing.
        self._patch_tls(monkeypatch, b"")

        with pytest.raises(ValueError, match="did not present a TLS certificate"):
            sync_main._fetch_and_verify_peer_cert("1.2.3.4", 8444, "a" * 64)

    def test_malformed_fingerprint_short_circuits_before_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Defence-in-depth: a typo in --cert-fingerprint must error out
        # BEFORE we open a TCP socket. The fake socket would fail noisily
        # if it were called, so the test passes only if the validator
        # rejects the input first.
        def _explode(*_a: object, **_kw: object) -> None:
            raise AssertionError("network must not be touched on bad fingerprint")

        monkeypatch.setattr(sync_main.socket, "create_connection", _explode)

        with pytest.raises(ValueError, match="64-char hex"):
            sync_main._fetch_and_verify_peer_cert("1.2.3.4", 8444, "not a fingerprint")


class TestFetchAndVerifyPeerCertRetry:
    """``_fetch_and_verify_peer_cert_with_retry`` mirrors the
    listener/client pair's retry policy: transient OSError/SSLError →
    bounded retry with exponential backoff; ValueError (fingerprint
    typo or mismatch) → no retry.
    """

    @staticmethod
    def _zero_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
        # Strip sleeps so unit tests stay fast.
        monkeypatch.setattr(sync_main, "_PIN_RETRY_BACKOFF_BASE_SEC", 0.0)
        monkeypatch.setattr(sync_main.time, "sleep", lambda _s: None)

    def test_first_attempt_succeeds_no_retry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._zero_backoff(monkeypatch)
        calls = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> bytes:
            calls["n"] += 1
            return b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"

        monkeypatch.setattr(sync_main, "_fetch_and_verify_peer_cert", _fake)
        out = sync_main._fetch_and_verify_peer_cert_with_retry("h", 1, "a" * 64)
        assert b"BEGIN CERTIFICATE" in out
        assert calls["n"] == 1

    def test_transient_then_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> bytes:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ConnectionRefusedError("serve not bound yet")
            return b"ok"

        monkeypatch.setattr(sync_main, "_fetch_and_verify_peer_cert", _fake)
        out = sync_main._fetch_and_verify_peer_cert_with_retry("h", 1, "a" * 64)
        assert out == b"ok"
        assert attempts["n"] == 3

    def test_transient_exhausts_max_attempts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> bytes:
            attempts["n"] += 1
            raise ConnectionRefusedError("serve never came up")

        monkeypatch.setattr(sync_main, "_fetch_and_verify_peer_cert", _fake)
        with pytest.raises(ConnectionRefusedError, match="never came up"):
            sync_main._fetch_and_verify_peer_cert_with_retry("h", 1, "a" * 64)
        # Default _PIN_MAX_ATTEMPTS == 3.
        assert attempts["n"] == 3

    def test_value_error_propagates_without_retry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # ValueError = fingerprint mismatch or typo — retrying never
        # fixes it. Must propagate after a single attempt.
        self._zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> bytes:
            attempts["n"] += 1
            raise ValueError("cert fingerprint mismatch: ...")

        monkeypatch.setattr(sync_main, "_fetch_and_verify_peer_cert", _fake)
        with pytest.raises(ValueError, match="fingerprint mismatch"):
            sync_main._fetch_and_verify_peer_cert_with_retry("h", 1, "a" * 64)
        assert attempts["n"] == 1


class TestSelfSignedCertGenerator:
    """``_generate_self_signed_cert`` is duplicated from cred_server until
    the helper is hoisted into probe-core. Until then, regression tests
    here pin the same shape (RSA-2048 + 24h lifetime + correct SHA-256
    fingerprint format).
    """

    def test_returns_pem_pem_fingerprint(self) -> None:
        cert_pem, key_pem, fingerprint = sync_main._generate_self_signed_cert()
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----") or key_pem.startswith(
            b"-----BEGIN PRIVATE KEY-----"
        )
        assert len(fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in fingerprint)

    def test_fingerprint_matches_cert_der(self) -> None:
        cert_pem, _, fingerprint = sync_main._generate_self_signed_cert()
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        der = cert_obj.public_bytes(serialization.Encoding.DER)
        assert hashlib.sha256(der).hexdigest() == fingerprint

    def test_san_covers_loopback(self) -> None:
        cert_pem, _, _ = sync_main._generate_self_signed_cert()
        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san_ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("127.0.0.1") in ips

    def test_each_call_returns_fresh_fingerprint(self) -> None:
        # Each serve session must issue a new cert — otherwise replay of
        # an old printed command (from a previous container that's been
        # restarted) would still validate against the new server.
        _, _, fp1 = sync_main._generate_self_signed_cert()
        _, _, fp2 = sync_main._generate_self_signed_cert()
        assert fp1 != fp2

    def test_extra_ip_appears_in_san(self) -> None:
        # rclone HTTP backend verifies SAN against URL host even with
        # --ca-cert; without the actual server IP in SAN, pull fails
        # with "x509: certificate is valid for 127.0.0.1, ::1, not
        # <server-host>". We add the externally-detected IP to SAN at
        # generation time so the puller can connect to it cleanly.
        cert_pem, _, _ = sync_main._generate_self_signed_cert(extra_ip="203.0.113.42")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san_ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("203.0.113.42") in ips
        # Loopback entries still present — sanity that we extended the
        # list rather than replaced it.
        assert ipaddress.IPv4Address("127.0.0.1") in ips

    def test_extra_ip_dnsname_fallback(self) -> None:
        # If extra_ip isn't a parseable IPv4 (e.g. operator-supplied
        # hostname), it goes into SAN as a DNSName rather than IPAddress.
        cert_pem, _, _ = sync_main._generate_self_signed_cert(extra_ip="my-host")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "my-host" in dns_names


class TestExternalIpDetection:
    """``_detect_external_ip`` is duplicated from cred_server. Mirror
    the few core paths so a future refactor of the helper into
    probe-core surfaces here too if it changes shape.
    """

    def test_routable_local_ip_returned_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # When the kernel's source-IP for a public destination is itself
        # public (cloud VPS), we return it without hitting the echo
        # service. 8.8.8.8 isn't in any reserved/private range so
        # ``is_private`` correctly returns False.
        monkeypatch.setattr(sync_main, "_udp_connect_local_ip", lambda: "8.8.8.8")

        called = {"echo": False}

        def _echo() -> str | None:
            called["echo"] = True
            return "should-not-be-used"

        monkeypatch.setattr(sync_main, "_query_public_ip_echo", _echo)

        assert sync_main._detect_external_ip() == "8.8.8.8"
        assert called["echo"] is False

    def test_private_ip_falls_through_to_echo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Local source is RFC 1918 → operator is behind NAT → ask echo.
        # Echo returns a Cloudflare anycast address (clearly non-private).
        monkeypatch.setattr(sync_main, "_udp_connect_local_ip", lambda: "192.168.1.10")
        monkeypatch.setattr(sync_main, "_query_public_ip_echo", lambda: "1.1.1.1")

        assert sync_main._detect_external_ip() == "1.1.1.1"

    def test_cgnat_falls_through_to_echo(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # 100.64.0.0/10 (RFC 6598) — mobile carriers + budget VPS.
        monkeypatch.setattr(sync_main, "_udp_connect_local_ip", lambda: "100.64.0.5")
        monkeypatch.setattr(sync_main, "_query_public_ip_echo", lambda: "9.9.9.9")

        assert sync_main._detect_external_ip() == "9.9.9.9"

    def test_no_outbound_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sync_main, "_udp_connect_local_ip", lambda: None)

        assert sync_main._detect_external_ip() is None
