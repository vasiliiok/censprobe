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
  DNS_BLOCKED      — NXDOMAIN from ISP, correct from DoH/control
  DOH_BLOCKED      — cannot connect to DoH endpoint
  ANOMALY          — inconsistency without clear attribution
  INCONCLUSIVE     — baseline unavailable
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from censprobe_core.models import TestResult, Verdict, BlockingMethod
from censprobe_core.baseline import BaselineComparator

logger = logging.getLogger(__name__)

# Process-wide HTTP clients for DoH and ASN lookups. Re-used across the
# whole probe run — fresh httpx.AsyncClient per call meant a new TLS
# handshake to 1.1.1.1/dns.google for every domain, which inflated DNS
# RTT readings (we measure them inside the same path).
_DOH_CLIENT: Optional[httpx.AsyncClient] = None
_ASN_CLIENT: Optional[httpx.AsyncClient] = None


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
    comparator: BaselineComparator,
    repeats: int = 3,
) -> list[TestResult]:
    """Run all DNS tests for a list of domains."""
    results: list[TestResult] = []

    # Test DoH resolver accessibility first
    results.extend(await _test_doh_accessibility())

    # Per domain tests
    for domain in domains:
        results.extend(await _test_domain(domain, comparator, repeats))

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
    comparator: BaselineComparator,
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
            # INCONCLUSIVE; the Telegram module handles these CDN/web subdomains
            # separately by comparing against the control baseline.
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

    # 7. ASN comparison
    resolved_asn = await _ip_to_asn(sys_ips[0]) if sys_ips else None
    cert_valid = await _validate_cert(domain, sys_ips[0]) if sys_ips else None

    verdict, method = comparator.compare_dns(domain, resolved_asn, cert_valid)

    # Override INCONCLUSIVE with basic sanity if we have DoH data
    if verdict == Verdict.INCONCLUSIVE and doh_ips and sys_ips:
        # If system IPs don't overlap with DoH IPs — suspicious
        sys_set = set(sys_ips)
        doh_set = set(doh_ips)
        if not sys_set.intersection(doh_set):
            # Cert will tell us if it's poisoning
            if cert_valid is False:
                verdict = Verdict.DNS_POISONING
                method = BlockingMethod.DNS_POISONING

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
            "isp_resolver": isp_resolver,
            "public_resolver_ips": public_results,
        },
        # ANOMALY with valid cert = ASN mismatch likely from CDN migration/geo-distribution,
        # not DNS manipulation. Reduce confidence to avoid misleading scores.
        confidence=(
            0.55 if verdict == Verdict.ANOMALY and cert_valid
            else 0.9 if verdict != Verdict.INCONCLUSIVE
            else 0.3
        ),
    ))

    return results


async def _resolve_system_with_ttl(
    domain: str,
) -> tuple[list[str], Optional[int], str]:
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


async def _validate_cert(domain: str, ip: str) -> Optional[bool]:
    """
    Connect to IP:443 with SNI=domain and check if cert is valid for domain.
    Returns True/False/None (None = connection failed, inconclusive).
    """
    ctx = ssl.create_default_context()

    def _check() -> Optional[bool]:
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
    except (asyncio.TimeoutError, Exception):
        return None


_ASN_CACHE: dict[str, Optional[str]] = {}
_ASN_BACKOFF_UNTIL: float = 0.0


async def _ip_to_asn(ip: str) -> Optional[str]:
    """Look up ASN for an IP via ip-api.com, with process-local caching.

    The free ip-api.com tier is 45 requests/min — a single control run
    can issue well over that (5 runs × 30+ domains). A 429 burns the
    rest of the test and leaves every baseline ASN at None. We cache
    per-IP in-process and enter a global 90-second backoff the moment
    the server asks us to slow down.
    """
    import time as _time
    if ip in _ASN_CACHE:
        return _ASN_CACHE[ip]

    global _ASN_BACKOFF_UNTIL
    now = _time.monotonic()
    if now < _ASN_BACKOFF_UNTIL:
        # During the cool-down we return None transiently but do NOT cache
        # it: once the backoff window ends we want the next probe to try
        # ip-api again, not be stuck on a permanent None forever.
        return None

    try:
        client = _get_asn_client()
        r = await client.get(f"http://ip-api.com/json/{ip}?fields=as")
        if r.status_code == 429:
            # ip-api returns plaintext 429 with a Retry-After-ish hint;
            # be conservative and pause for 90s so we don't melt the
            # whole suite. Don't poison this IP in the cache — once
            # the backoff expires we want to retry it.
            _ASN_BACKOFF_UNTIL = now + 90.0
            return None
        if r.status_code == 200:
            data = r.json()
            raw = data.get("as", "")
            if raw:
                asn = raw.split(" ")[0]  # "AS13335 Cloudflare" → "AS13335"
                _ASN_CACHE[ip] = asn
                return asn
    except Exception:
        pass
    _ASN_CACHE[ip] = None
    return None


def _get_isp_resolver() -> Optional[str]:
    """Get first nameserver from /etc/resolv.conf."""
    try:
        from pathlib import Path
        content = Path("/etc/resolv.conf").read_text()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("nameserver "):
                return line.split()[1]
    except Exception:
        pass
    return None


def _slug(domain: str) -> str:
    """Convert domain to safe slug: meduza.io → meduza_io"""
    return domain.replace(".", "_").replace("-", "_").lower()
