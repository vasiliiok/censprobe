"""
modules/dns.py — DNS measurement module.

Tests (per domain from targets/):
  1. Resolve via system resolver (/etc/resolv.conf)
  2. Resolve via ISP upstream resolver (auto-detected)
  3. Resolve via public resolvers: 8.8.8.8, 1.1.1.1, 77.88.8.8, 9.9.9.9
  4. Resolve via DoH: cloudflare-dns.com, dns.google, mozilla.cloudflare-dns.com
  5. Resolve via DoT: 1.1.1.1:853, 8.8.8.8:853
  6. Validate: TLS connect to returned IP + cert check (CERTainty approach)

Verdicts:
  OK               — all resolvers consistent, cert valid
  DNS_POISONING    — system/ISP returns different IP with invalid cert
  DNS_BLOCKED      — NXDOMAIN from ISP, correct from DoH
  DOH_BLOCKED      — cannot connect to DoH endpoint
  ANOMALY          — inconsistency without clear attribution
  INCONCLUSIVE     — cert handshake failed, can't determine
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from censprobe_core.models import TestResult, Verdict, BlockingMethod

logger = logging.getLogger(__name__)

# Process-wide HTTP clients for DoH and ASN lookups. Re-used across the
# whole probe run — fresh httpx.AsyncClient per call meant a new TLS
# handshake to 1.1.1.1/dns.google for every domain, which inflated DNS
# RTT readings (we measure them inside the same path).
_DOH_CLIENT: httpx.AsyncClient | None = None
_ASN_CLIENT: httpx.AsyncClient | None = None

# All geo/ASN lookups go over HTTPS — see server_meta.py opsec note: an
# on-path observer must not be able to cheaply link this server's IP to
# censorship-measurement activity. Plain-HTTP probes to ip-api.com would
# leak the queried IP plus our return path in cleartext.
# Same source-of-truth contract as server_meta.py: empty string means
# "free tier", missing env var is a deployment bug.
_IPAPI_IS_KEY = os.environ["IPAPI_IS_KEY"]
_IPAPI_IS_URL = "https://api.ipapi.is/"


def _get_doh_client() -> httpx.AsyncClient:
    global _DOH_CLIENT
    if _DOH_CLIENT is None:
        _DOH_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(10.0), http2=True)
    return _DOH_CLIENT


def _get_asn_client() -> httpx.AsyncClient:
    global _ASN_CLIENT
    if _ASN_CLIENT is None:
        _ASN_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    return _ASN_CLIENT

# Public DNS resolvers to test
PUBLIC_RESOLVERS = [
    ("google_1", "8.8.8.8"),
    ("google_2", "8.8.4.4"),
    ("cloudflare_1", "1.1.1.1"),
    ("yandex", "77.88.8.8"),
    ("quad9", "9.9.9.9"),
]

DOH_RESOLVERS = [
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    # Google's /dns-query endpoint only accepts RFC 8484 wire format.
    # For the JSON API (application/dns-json), the endpoint is /resolve.
    ("google", "https://dns.google/resolve"),
    ("mozilla", "https://mozilla.cloudflare-dns.com/dns-query"),
]

DOT_RESOLVERS = [
    ("cloudflare", "1.1.1.1", 853),
    ("google", "8.8.8.8", 853),
]


async def run_dns_tests(
    domains: list[str],
    repeats: int = 3,
) -> list[TestResult]:
    """Run all DNS tests for a list of domains."""
    results: list[TestResult] = []

    # Test DoH resolver accessibility first
    results.extend(await _test_doh_accessibility())

    # Per domain tests
    for domain in domains:
        results.extend(await _test_domain(domain, repeats))

    return results


async def _test_doh_accessibility() -> list[TestResult]:
    """Test whether DoH resolvers are reachable at all."""
    results = []
    client = _get_doh_client()
    for name, url in DOH_RESOLVERS:
        test_name = f"doh_access_{name}"
        try:
            # Send a minimal DoH query for 'example.com'
            r = await client.get(
                url,
                params={"name": "example.com", "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            verdict = Verdict.OK if r.status_code == 200 else Verdict.ANOMALY
            results.append(TestResult(
                test=test_name,
                category="dns",
                target=url,
                verdict=verdict,
                evidence={"status_code": r.status_code},
            ))
        except Exception as e:
            results.append(TestResult(
                test=test_name,
                category="dns",
                target=url,
                verdict=Verdict.BLOCKED,
                method=BlockingMethod.DOH_BLOCKED,
                evidence={"error": str(e)},
            ))
    return results


async def _test_domain(
    domain: str,
    repeats: int,
) -> list[TestResult]:
    """Full DNS test suite for one domain."""
    results = []

    # 1. System resolver — distinguish NXDOMAIN from network/SERVFAIL errors,
    #    otherwise every transient failure looks like censorship and produces
    #    a false DNS_BLOCKED verdict.
    sys_ips, sys_ttl, sys_status = await _resolve_system_with_ttl(domain)
    sys_nxdomain = sys_status == "nxdomain"
    sys_error = sys_status if sys_status not in ("ok", "nxdomain") else None

    # 2. Public resolvers (NXDOMAIN flag preserved for cross-checking)
    public_results: dict[str, list[str]] = {}
    public_nxdomain: dict[str, bool] = {}
    for rname, rip in PUBLIC_RESOLVERS:
        ips, nx = await _resolve_via(domain, rip)
        public_results[rname] = ips
        public_nxdomain[rname] = nx

    # 3. DoH resolvers
    doh_results: dict[str, list[str]] = {}
    for rname, url in DOH_RESOLVERS:
        ips = await _resolve_doh(domain, url)
        doh_results[rname] = ips

    # 3b. DoT resolvers — run in parallel; errors are silently swallowed
    # since DoT is a supplementary signal, not required for a verdict.
    dot_tasks = [_resolve_dot(domain, host, port) for _, host, port in DOT_RESOLVERS]
    dot_raw = await asyncio.gather(*dot_tasks, return_exceptions=True)
    dot_results: dict[str, list[str]] = {}
    for (rname, _, _), res in zip(DOT_RESOLVERS, dot_raw):
        dot_results[rname] = res if isinstance(res, list) else []

    # 4. Determine "ground truth" from DoH (most reliable, bypasses ISP).
    # Include DoT answers as additional corroboration.
    doh_ips: list[str] = []
    for ips in doh_results.values():
        doh_ips.extend(ips)
    for ips in dot_results.values():
        doh_ips.extend(ips)
    doh_ips = list(set(doh_ips))

    # 5. Detect ISP resolver (first nameserver in /etc/resolv.conf)
    isp_resolver = _get_isp_resolver()
    if isp_resolver:
        isp_ips, isp_nxdomain = await _resolve_via(domain, isp_resolver)
    else:
        isp_ips, isp_nxdomain = [], False

    # 6. NXDOMAIN detection — only if the system resolver actually returned
    #    NXDOMAIN. A bare network/timeout error is reported as INCONCLUSIVE,
    #    not DNS_BLOCKED, otherwise we get false positives from any DNS
    #    hiccup. We also corroborate with DoH: if DoH has the answer but the
    #    system resolver returned NXDOMAIN, that's strong DNS-blocking signal.
    if sys_nxdomain:
        # If DoH (or any public resolver) has answers but ISP/system NXDOMAIN
        # → ISP-level NXDOMAIN injection with high confidence.
        public_has_answer = any(public_results[name] for name in public_results)
        if doh_ips or public_has_answer:
            # DoH or public resolvers resolve it → ISP is blocking via NXDOMAIN.
            results.append(TestResult(
                test=f"dns_{_slug(domain)}_system",
                category="dns",
                target=domain,
                verdict=Verdict.DNS_BLOCKED,
                method=BlockingMethod.DNS_BLOCKED_NXDOMAIN,
                evidence={
                    "system_nxdomain": True,
                    "doh_ips": doh_ips,
                    "public_resolver_ips": public_results,
                    "public_resolver_nxdomain": public_nxdomain,
                    "isp_resolver": isp_resolver,
                    "isp_ips": isp_ips,
                    "isp_nxdomain": isp_nxdomain,
                },
                confidence=0.9,
            ))
        else:
            # All resolvers (ISP + DoH + public) return NXDOMAIN — the domain
            # may legitimately not exist rather than being blocked. Return
            # INCONCLUSIVE; the Telegram module handles wrong-cert CDN
            # subdomains separately via inline cert-pattern validation.
            results.append(TestResult(
                test=f"dns_{_slug(domain)}_system",
                category="dns",
                target=domain,
                verdict=Verdict.INCONCLUSIVE,
                method=BlockingMethod.DNS_BLOCKED_NXDOMAIN,
                evidence={
                    "system_nxdomain": True,
                    "doh_ips": doh_ips,
                    "public_resolver_ips": public_results,
                    "public_resolver_nxdomain": public_nxdomain,
                    "isp_resolver": isp_resolver,
                    "isp_ips": isp_ips,
                    "isp_nxdomain": isp_nxdomain,
                },
                confidence=0.5,
                notes="NXDOMAIN from all resolvers including DoH — domain may not exist.",
            ))
        return results

    if sys_error and not sys_ips:
        # Pure system-resolver error (not NXDOMAIN) — can't conclude blocking
        # from this alone. Surface as INCONCLUSIVE with the error in evidence.
        results.append(TestResult(
            test=f"dns_{_slug(domain)}_system",
            category="dns",
            target=domain,
            verdict=Verdict.INCONCLUSIVE,
            evidence={
                "system_error": sys_error,
                "doh_ips": doh_ips,
                "public_resolver_ips": public_results,
                "isp_resolver": isp_resolver,
            },
            confidence=0.2,
        ))
        return results

    # 7. CERTainty-style verdict: cert validity + DoH consensus.
    #    ASN is collected for forensics only — comparing against a static
    #    expected-ASN list misclassifies CDN regional rotation as poisoning.
    resolved_asn = await _ip_to_asn(sys_ips[0]) if sys_ips else None
    cert_valid = await _validate_cert(domain, sys_ips[0]) if sys_ips else None

    sys_set = set(sys_ips)
    doh_set = set(doh_ips)
    ip_overlap = bool(sys_set & doh_set) if sys_set and doh_set else False

    verdict: Verdict
    method: BlockingMethod | None = None
    confidence: float

    if cert_valid is False:
        # Cert from system-resolver IP doesn't validate as `domain`.
        if ip_overlap:
            # System and DoH agree on the IP but cert validation failed —
            # ambiguous (could be expired root, broken chain, or a real
            # server-side cert issue rather than DNS-level redirection).
            verdict = Verdict.ANOMALY
            confidence = 0.6
        elif not doh_ips:
            # DoH itself was unreachable / blocked, so we have no second
            # source of truth. Cert-failure alone (without DoH consensus)
            # cannot prove DNS poisoning per CERTainty PETS 2023 — the
            # IP could be authentic but serving a broken cert. Downgrade
            # to ANOMALY rather than overclaiming DNS_POISONING.
            verdict = Verdict.ANOMALY
            confidence = 0.4
        else:
            # System and DoH disagree on the IP, AND cert from the system
            # IP doesn't validate as `domain` → poisoned.
            verdict = Verdict.DNS_POISONING
            method = BlockingMethod.DNS_POISONING
            confidence = 0.9
    elif cert_valid is True:
        # System resolver returns an IP that serves a valid cert for the
        # domain. Whether the ASN matches a hard-coded expected list is
        # irrelevant — the destination is authentically the domain.
        verdict = Verdict.OK
        confidence = 0.9
    else:
        # cert_valid is None — connection failed for non-cert reasons
        # (TCP RST, timeout). Use DoH-overlap as the secondary signal.
        if ip_overlap:
            verdict = Verdict.OK
            confidence = 0.5
        elif doh_ips and sys_ips:
            # System IPs disagree with DoH and we couldn't reach 443 to
            # validate the cert. This is suspicious but not provable
            # without a working TLS handshake — leave as INCONCLUSIVE
            # rather than overclaim DNS_POISONING.
            verdict = Verdict.INCONCLUSIVE
            confidence = 0.3
        else:
            verdict = Verdict.INCONCLUSIVE
            confidence = 0.2

    results.append(TestResult(
        test=f"dns_{_slug(domain)}_system",
        category="dns",
        target=domain,
        verdict=verdict,
        method=method,
        evidence={
            "system_ips": sys_ips,
            "system_ttl": sys_ttl,
            "isp_ips": isp_ips,
            "doh_ips": doh_ips,
            "resolved_asn": resolved_asn,
            "cert_valid": cert_valid,
            "ip_overlap_with_doh": ip_overlap,
            "isp_resolver": isp_resolver,
            "public_resolver_ips": public_results,
        },
        confidence=confidence,
    ))

    return results


async def _resolve_system_with_ttl(
    domain: str,
) -> tuple[list[str], int | None, str]:
    """Resolve via system resolver, returning (ips, ttl, status).

    status is one of:
      "ok"        — resolved
      "nxdomain"  — authoritative NXDOMAIN
      "noanswer"  — no A records (NoAnswer / empty rrset)
      "timeout"   — DNS timeout / lifetime exceeded
      "servfail"  — SERVFAIL or other resolver-side failure
      "error:<m>" — unexpected exception (m = type name)

    Distinguishing NXDOMAIN from generic errors is required so callers
    don't tag every transient DNS failure as DNS_BLOCKED_NXDOMAIN.
    """
    try:
        resolver = dns.asyncresolver.Resolver()
        # Bound the lifetime so a hung resolver doesn't stall the suite.
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        answers = await resolver.resolve(domain, "A")
        ttl = int(getattr(answers.rrset, "ttl", 0)) if answers.rrset else None
        return [str(r) for r in answers], ttl, "ok"
    except dns.resolver.NXDOMAIN:
        return [], None, "nxdomain"
    except dns.resolver.NoAnswer:
        return [], None, "noanswer"
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return [], None, "timeout"
    except dns.resolver.NoNameservers:
        return [], None, "servfail"
    except Exception as e:
        return [], None, f"error:{type(e).__name__}"


async def _resolve_via(domain: str, nameserver_ip: str) -> tuple[list[str], bool]:
    """Resolve via a specific nameserver IP."""
    try:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [nameserver_ip]
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        answers = await resolver.resolve(domain, "A")
        return [str(r) for r in answers], False
    except dns.resolver.NXDOMAIN:
        return [], True
    except Exception:
        return [], False


async def _resolve_doh(domain: str, url: str) -> list[str]:
    """Resolve via DoH endpoint."""
    try:
        client = _get_doh_client()
        r = await client.get(
            url,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
        )
        if r.status_code == 200:
            data = r.json()
            return [
                ans["data"]
                for ans in data.get("Answer", [])
                if ans.get("type") == 1  # A record
            ]
    except Exception:
        pass
    return []


async def _resolve_dot(domain: str, host: str, port: int = 853) -> list[str]:
    """Resolve domain via DNS-over-TLS (RFC 7858).

    Wraps a standard UDP DNS query inside a TLS connection to the resolver.
    Returns a list of IPv4 addresses, or empty list on any error. DoT
    bypasses ISP DNS manipulation in the same way DoH does, and its
    failure (TLS connect refused) is separately meaningful for detecting
    DoT blocking.
    """
    import struct

    def _build_a_query(name: str, qid: int = 1) -> bytes:
        """Build a minimal A-record DNS query wire packet."""
        labels = b"".join(
            bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")
        ) + b"\x00"
        # Header: id, flags (RD), qdcount=1, ancount=0, nscount=0, arcount=0
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        question = labels + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        return header + question

    def _parse_a_records(data: bytes) -> list[str]:
        """Extract A-record IPs from a DNS response wire packet."""
        import ipaddress
        if len(data) < 12:
            return []
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []
        # Skip past the question section by scanning past the qname labels.
        pos = 12
        try:
            while pos < len(data) and data[pos] != 0:
                if (data[pos] & 0xC0) == 0xC0:  # pointer
                    pos += 2
                    break
                pos += data[pos] + 1
            else:
                pos += 1  # zero label
            pos += 4  # qtype + qclass
        except IndexError:
            return []
        ips = []
        for _ in range(ancount):
            try:
                # Skip name (may be a pointer)
                if pos >= len(data):
                    break
                if (data[pos] & 0xC0) == 0xC0:
                    pos += 2
                else:
                    while pos < len(data) and data[pos] != 0:
                        pos += data[pos] + 1
                    pos += 1
                if pos + 10 > len(data):
                    break
                rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos+10])
                pos += 10
                if rtype == 1 and rdlen == 4:  # A record
                    ips.append(str(ipaddress.IPv4Address(data[pos:pos+4])))
                pos += rdlen
            except (IndexError, struct.error, ValueError):
                break
        return ips

    ctx = ssl.create_default_context()
    query = _build_a_query(domain)
    # DoT framing: 2-byte big-endian length prefix before the DNS message.
    framed = struct.pack(">H", len(query)) + query

    loop = asyncio.get_running_loop()

    def _do_dot() -> list[str]:
        try:
            with socket.create_connection((host, port), timeout=5.0) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    tls.sendall(framed)
                    # Read the 2-byte length prefix
                    header = b""
                    while len(header) < 2:
                        chunk = tls.recv(2 - len(header))
                        if not chunk:
                            return []
                        header += chunk
                    resp_len = struct.unpack(">H", header)[0]
                    resp = b""
                    while len(resp) < resp_len:
                        chunk = tls.recv(resp_len - len(resp))
                        if not chunk:
                            break
                        resp += chunk
                    return _parse_a_records(resp)
        except Exception:
            return []

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _do_dot),
            timeout=8.0,
        )
    except Exception:
        return []


async def _validate_cert(domain: str, ip: str) -> bool | None:
    """
    Connect to IP:443 with SNI=domain and check if cert is valid for domain.
    Returns True/False/None (None = connection failed, inconclusive).
    """
    ctx = ssl.create_default_context()

    def _check() -> bool | None:
        try:
            with socket.create_connection((ip, 443), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    s.getpeercert()  # raises if cert invalid
                    return True
        except ssl.SSLCertVerificationError:
            return False
        except Exception:
            # Connection or non-cert TLS failure — caller treats None as
            # "inconclusive", NOT as "cert invalid", which prevents flagging
            # a TCP/RST as DNS_POISONING.
            return None

    try:
        # Bound total time even if the underlying socket ignores its
        # own timeout (e.g. blocked SYN with no RST → SYN backoff).
        return await asyncio.wait_for(asyncio.to_thread(_check), timeout=8.0)
    except Exception:
        # Covers asyncio.TimeoutError and any unexpected error from
        # to_thread/_check; in either case the verdict is "inconclusive".
        return None


_ASN_CACHE: dict[str, str | None] = {}
_ASN_BACKOFF_UNTIL: float = 0.0


async def _ip_to_asn(ip: str) -> str | None:
    """Look up ASN for an IP via ipapi.is over HTTPS, with process-local caching.

    Why HTTPS / ipapi.is: server_meta.py already uses the same provider
    for the (single) external-IP lookup; routing the per-domain ASN
    forensics over the same TLS-protected path keeps the project's
    on-path-observer threat model consistent — plain-HTTP queries to
    ip-api.com would leak the resolved IP for every probed domain in
    cleartext.

    Caching: the free tier of ipapi.is is rate-limited (1k/day without a
    key); a single solo run issues 30+ domains × N rounds. We cache per-IP
    in-process and enter a global 90-second backoff the moment the server
    signals 429 to avoid melting the rest of the suite.
    """
    import time as _time
    if ip in _ASN_CACHE:
        return _ASN_CACHE[ip]

    global _ASN_BACKOFF_UNTIL
    now = _time.monotonic()
    if now < _ASN_BACKOFF_UNTIL:
        # During the cool-down we return None transiently but do NOT cache
        # it: once the backoff window ends we want the next probe to try
        # again, not be stuck on a permanent None forever.
        return None

    try:
        client = _get_asn_client()
        r = await client.get(
            _IPAPI_IS_URL,
            params={"q": ip, "key": _IPAPI_IS_KEY},
        )
        if r.status_code == 429:
            _ASN_BACKOFF_UNTIL = now + 90.0
            return None
        if r.status_code == 200:
            data = r.json()
            asn_block = data.get("asn") or {}
            asn_num = asn_block.get("asn")
            if asn_num:
                asn = f"AS{asn_num}"
                _ASN_CACHE[ip] = asn
                return asn
    except Exception:
        pass
    _ASN_CACHE[ip] = None
    return None


# Loopback addresses used by local DNS stubs (systemd-resolved on
# 127.0.0.53, dnsmasq on 127.0.0.1, NetworkManager on 127.0.0.54). When we
# see one in /etc/resolv.conf, the file points at a forwarder, not at the
# real ISP/upstream resolver — and resolving through it gives the same
# answers as the system call already produced, eliminating the cross-check.
_LOCAL_STUB_ADDRESSES = {"127.0.0.53", "127.0.0.54", "127.0.0.1", "::1"}


def _parse_first_nameserver(content: str) -> str | None:
    """Return the first ``nameserver <ip>`` line value from a resolv.conf body."""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("nameserver "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def _get_isp_resolver() -> str | None:
    """Get the first real upstream resolver visible to this host.

    On distributions running systemd-resolved (Ubuntu 18.04+, Fedora,
    modern Debian on cloud images), ``/etc/resolv.conf`` points at the
    127.0.0.53 stub-listener — useless for cross-checking against the
    system resolver because every query goes through the same path. The
    upstream the stub forwards to is recorded in
    ``/run/systemd/resolve/resolv.conf``; prefer that when the primary
    resolv.conf lists only a known local stub address.
    """
    from pathlib import Path
    try:
        primary = _parse_first_nameserver(Path("/etc/resolv.conf").read_text())
    except OSError:
        primary = None

    if primary and primary not in _LOCAL_STUB_ADDRESSES:
        return primary

    # systemd-resolved fallback: the real upstreams the stub forwards to.
    try:
        upstream = _parse_first_nameserver(
            Path("/run/systemd/resolve/resolv.conf").read_text()
        )
    except OSError:
        upstream = None

    return upstream or primary


def _slug(domain: str) -> str:
    """Convert domain to safe slug: meduza.io → meduza_io"""
    return domain.replace(".", "_").replace("-", "_").lower()
