"""
ephemeral_cert.py — Shared self-signed cert + external-IP detection.

Used by the two paths that hand the operator a one-shot bearer-token
HTTPS endpoint:

* ``censprobe_listener.cred_server`` (port 8443) — credential YAML.
* ``censprobe_sync`` (port 8444) — rclone reports/ transfer.

Both follow the same pinning model: self-signed cert, ``CERT_NONE`` +
manual SHA-256 compare on the client side, bearer token only sent after
the fingerprint matches. The cert generator and the external-IP detector
used to be copy-pasted between the two modules (with a TODO to hoist
them); they're now a single source of truth here. ``sync`` could not
import directly from ``listener`` without pulling in mtg / openvpn /
wg-tools / amneziawg-go binary expectations, hence the probe-core home.

Threat model:
  * 0o600 keys via ``write_secret`` everywhere — no umask-based
    world-readable window between open and chmod.
  * RSA-2048 with a 2-hour validity window by default. Earlier
    implementations used 24h "to match listener session"; 2h is the
    actual session ceiling on any realistic test (and 24h is just a
    bigger blast-radius window if the ephemeral private key leaks).
    Callers that need longer can pass ``validity_hours=``.
  * SAN covers ``localhost``, IPv4 loopback, IPv6 loopback, plus the
    operator-supplied externally-routable IP (so rclone-style Go
    clients that always verify cert name don't trip RFC 6125).
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_DEFAULT_VALIDITY_HOURS = 2

# Public-IP echo services queried only when the kernel's local default-
# route source is a private / CGNAT / loopback address. First parseable
# IPv4 wins. Three providers (was two before 2026-05-14 audit) so a
# regional block on the first one doesn't drop the listener into the
# ``<your-server-ip>`` placeholder path.
_PUBLIC_IP_ECHOES: tuple[str, ...] = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://api.my-ip.io/v2/ip.txt",
)
_PUBLIC_IP_TIMEOUT_SEC = 5.0
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def generate_self_signed_cert(
    *,
    common_name: str,
    extra_ip: str | None = None,
    validity_hours: int = _DEFAULT_VALIDITY_HOURS,
) -> tuple[bytes, bytes, str]:
    """Generate an RSA-2048 self-signed cert.

    Returns ``(cert_pem, key_pem, sha256_fingerprint_hex)``.

    SAN entries:
      * ``DNSName(common_name)``  — the cert's claimed identity
      * ``DNSName("localhost")``  + IPv4/IPv6 loopback — local debug
      * ``IPAddress(extra_ip)`` if provided and parseable as IPv4,
        else ``DNSName(extra_ip)`` (allows operator-set hostnames).

    Validity defaults to 2 hours — every realistic listener / sync
    session is minutes. A leaked private key has at most 2 hours of
    impersonation potential before the cert expires; callers that
    deliberately want longer pass ``validity_hours=``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    san_entries: list[x509.GeneralName] = [
        x509.DNSName(common_name),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    if extra_ip:
        try:
            san_entries.append(x509.IPAddress(ipaddress.IPv4Address(extra_ip)))
        except (ipaddress.AddressValueError, ValueError):
            # Not a parseable IPv4 — treat as a DNS hostname so an
            # operator running on a named host (``censprobe.example``)
            # can still pin without RFC 6125 errors.
            san_entries.append(x509.DNSName(extra_ip))
    san = x509.SubjectAlternativeName(san_entries)

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=validity_hours))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_pem, key_pem, fingerprint


def detect_external_ip() -> str | None:
    """Best-effort detection of the IPv4 a remote client should connect to.

    Two-step strategy:

      1. Kernel routing trick — open a UDP socket "connected" to a public
         anycast (SOCK_DGRAM connect never actually sends a packet) and
         ask the kernel which source address it would use. Instant, works
         on any host with a default route. On a cloud VPS with a directly
         attached public IP this is the answer.

      2. If step 1 returned a private / CGNAT / loopback address, the
         listener is behind NAT — the local source IP is useless to a
         remote client. Query a public-IP echo service to learn the
         externally-routable address. Bounded by ~5 s per endpoint, three
         providers tried in fallback order.

    Returns ``None`` only if the host has no outbound network at all.
    """
    local_ip = _udp_connect_local_ip()
    if local_ip is None:
        return None

    if not _is_unroutable(local_ip):
        return local_ip

    public_ip = _query_public_ip_echo()
    return public_ip or local_ip


def _udp_connect_local_ip() -> str | None:
    """Return the IPv4 source address the kernel would use for a public destination."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip: str = s.getsockname()[0]
            return ip
        finally:
            s.close()
    except OSError:
        return None


def _is_unroutable(ip: str) -> bool:
    """Treat an IPv4 as unusable for a remote client.

    Covers all the cases where a behind-NAT listener would otherwise hand
    the client an IP it cannot reach:
      * RFC 1918 (10/8, 172.16/12, 192.168/16),
      * loopback (127/8) and link-local (169.254/16) — :meth:`is_private`
        captures both,
      * CGNAT (100.64/10, RFC 6598) — explicitly NOT covered by
        :meth:`is_private` in CPython, so we add a direct subnet
        membership check. Mobile uplinks and several budget VPS
        providers hand out CGNAT addresses, and falling through to the
        echo lookup is exactly the path we want for those listeners.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        # AddressValueError is a ValueError subclass — Sonar S5713.
        return True
    return addr.is_private or addr in _CGNAT_NETWORK


def _query_public_ip_echo() -> str | None:
    """Ask the public-IP echo services in fallback order; return the first parseable IPv4."""
    for url in _PUBLIC_IP_ECHOES:
        try:
            # URLs are a hardcoded module-level tuple of trusted https
            # endpoints — no operator/network input is mixed into the
            # URL, so the "audit URL open" warning doesn't apply.
            with urllib.request.urlopen(url, timeout=_PUBLIC_IP_TIMEOUT_SEC) as r:  # noqa: S310  # nosec B310
                ip: str = r.read().decode("ascii", errors="replace").strip()
            ipaddress.IPv4Address(ip)  # validate; raises if junk
            return ip
        except (OSError, ValueError):
            # AddressValueError is already a ValueError subclass.
            continue
    return None
