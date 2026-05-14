"""
modules/dns.py — DNS measurement module.

Tests (per domain from targets/):
  1. Resolve via system resolver (/etc/resolv.conf)
  2. Resolve via ISP upstream resolver (auto-detected)
  3. Resolve via public resolvers: 8.8.8.8, 1.1.1.1, 77.88.8.8, 9.9.9.9
  4. Resolve via DoH: cloudflare-dns.com, dns.google, mozilla.cloudflare-dns.com
  5. Resolve via DoT: 1.1.1.1:853, 8.8.8.8:853
  6. Validate: TLS connect to returned IP + cert check (CERTainty approach)

Outcomes (verdict + method):
  OK                                          — all resolvers consistent, cert valid
  BLOCKED + method=dns_poisoning              — system/ISP returns different IP
                                                with invalid cert
  BLOCKED + method=dns_blocked_nxdomain       — NXDOMAIN from ISP, correct from DoH
  BLOCKED + method=doh_blocked                — cannot connect to DoH endpoint
  ANOMALY                                     — inconsistency without clear attribution
  INCONCLUSIVE                                — cert handshake failed, can't determine
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import ssl
from dataclasses import dataclass
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from censprobe_core.models import BlockingMethod, TestResult, Verdict

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
# Lazy: don't fail import when IPAPI_IS_KEY is unset — only the actual
# ASN lookup needs it, and an empty string is the "free tier" state.
_IPAPI_IS_URL = "https://api.ipapi.is/"


def _ipapi_key() -> str:
    return os.environ.get("IPAPI_IS_KEY", "")


def _get_doh_client() -> httpx.AsyncClient:
    """Lazy singleton DoH client.

    Timeout is read lazily from CensprobeConfig if available so the
    operator's censprobe.yaml::modules.dns.doh_timeout_sec actually
    takes effect (previously hardcoded at 10s regardless of yaml).
    Falls back to a sensible 10s when the config hasn't loaded yet —
    matters for the rare test path that imports this module before
    load_config has run.
    """
    global _DOH_CLIENT
    if _DOH_CLIENT is None:
        timeout = _config_doh_timeout()
        _DOH_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(timeout), http2=True)
    return _DOH_CLIENT


def _get_asn_client() -> httpx.AsyncClient:
    global _ASN_CLIENT
    if _ASN_CLIENT is None:
        _ASN_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    return _ASN_CLIENT


def _config_doh_timeout() -> float:
    """Read DoH timeout from the loaded config; 10s fallback for tests."""
    try:
        from censprobe_core.config import get_config

        return float(get_config().modules.dns.doh_timeout_sec)
    except (RuntimeError, AttributeError):
        return 10.0


def _config_asn_backoff_sec() -> float:
    """Read ipapi.is backoff cool-off from the loaded config; 90s fallback."""
    try:
        from censprobe_core.config import get_config

        return float(get_config().modules.dns.asn_lookup_backoff_sec)
    except (RuntimeError, AttributeError):
        return 90.0


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


async def run_dns_tests(domains: list[str]) -> list[TestResult]:
    """Run all DNS tests for a list of domains.

    DNS attribution is verified via the multi-resolver ladder
    (system + ISP + 4 public + 3 DoH + 2 DoT) — that cross-check IS
    the retry surface. Single-record repeats would only add load
    without changing the verdict shape, so this entry point doesn't
    expose a ``repeats`` parameter. (Removed 2026-05-14: previously
    accepted-and-ignored, which misled the operator into thinking
    censprobe.yaml::modules.dns.repeats did something.)
    """
    results: list[TestResult] = []

    # Test DoH resolver accessibility first
    results.extend(await _test_doh_accessibility())

    for domain in domains:
        results.extend(await _test_domain(domain))

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
            results.append(
                TestResult(
                    test=test_name,
                    category="dns",
                    target=url,
                    verdict=verdict,
                    evidence={"status_code": r.status_code},
                )
            )
        except Exception as e:
            results.append(
                TestResult(
                    test=test_name,
                    category="dns",
                    target=url,
                    verdict=Verdict.BLOCKED,
                    method=BlockingMethod.DOH_BLOCKED,
                    evidence={"error": str(e)},
                )
            )
    return results


@dataclass
class _ResolverEvidence:
    """Aggregated DNS answers for one domain across every resolver path."""

    sys_ips: list[str]
    sys_ttl: int | None
    sys_status: str
    public_results: dict[str, list[str]]
    public_nxdomain: dict[str, bool]
    doh_ips: list[str]
    per_resolver_sets: list[set[str]]
    isp_resolver: str | None
    isp_ips: list[str]
    isp_nxdomain: bool

    @property
    def sys_nxdomain(self) -> bool:
        return self.sys_status == "nxdomain"

    @property
    def sys_error(self) -> str | None:
        return self.sys_status if self.sys_status not in ("ok", "nxdomain") else None


async def _gather_resolver_evidence(domain: str) -> _ResolverEvidence:
    """Probe every resolver path (system, public, DoH, DoT, ISP) for ``domain``."""
    sys_ips, sys_ttl, sys_status = await _resolve_system_with_ttl(domain)

    public_results: dict[str, list[str]] = {}
    public_nxdomain: dict[str, bool] = {}
    for rname, rip in PUBLIC_RESOLVERS:
        ips, nx = await _resolve_via(domain, rip)
        public_results[rname] = ips
        public_nxdomain[rname] = nx

    doh_results: dict[str, list[str]] = {}
    for rname, url in DOH_RESOLVERS:
        doh_results[rname] = await _resolve_doh(domain, url)

    # DoT resolvers — parallel; errors silently swallowed (supplementary signal).
    dot_tasks = [_resolve_dot(domain, host, port) for _, host, port in DOT_RESOLVERS]
    dot_raw = await asyncio.gather(*dot_tasks, return_exceptions=True)
    dot_results: dict[str, list[str]] = {}
    for (rname, _, _), res in zip(DOT_RESOLVERS, dot_raw, strict=True):
        dot_results[rname] = res if isinstance(res, list) else []

    # Per-resolver answer sets are kept separately so the system-resolver
    # ↔ "ground truth" overlap check can accept ANY single resolver as a
    # match. Pooling all resolvers into one big set was producing false
    # INCONCLUSIVE on CDN domains where each resolver returned a
    # different rotated edge IP — the union-set then disagreed with the
    # system answer 100% of the time.
    doh_ips: list[str] = []
    per_resolver_sets: list[set[str]] = []
    for ips in (*doh_results.values(), *dot_results.values()):
        if ips:
            per_resolver_sets.append(set(ips))
        doh_ips.extend(ips)
    doh_ips = list(set(doh_ips))

    isp_resolver = _get_isp_resolver()
    if isp_resolver:
        isp_ips, isp_nxdomain = await _resolve_via(domain, isp_resolver)
    else:
        isp_ips, isp_nxdomain = [], False

    return _ResolverEvidence(
        sys_ips=sys_ips,
        sys_ttl=sys_ttl,
        sys_status=sys_status,
        public_results=public_results,
        public_nxdomain=public_nxdomain,
        doh_ips=doh_ips,
        per_resolver_sets=per_resolver_sets,
        isp_resolver=isp_resolver,
        isp_ips=isp_ips,
        isp_nxdomain=isp_nxdomain,
    )


def _build_nxdomain_result(domain: str, ev: _ResolverEvidence) -> TestResult:
    """Build the system-resolver result when sys_status == nxdomain.

    DoH (or any public resolver) returning answers while ISP/system NXDOMAIN
    means ISP-level NXDOMAIN injection (high-confidence DNS_BLOCKED).
    Otherwise — every resolver also NXDOMAINs — the domain may legitimately
    not exist: INCONCLUSIVE so the dashboard isn't poisoned by missing TLDs.
    """
    public_has_answer = any(ev.public_results[name] for name in ev.public_results)
    common_evidence: dict[str, Any] = {
        "system_nxdomain": True,
        "doh_ips": ev.doh_ips,
        "public_resolver_ips": ev.public_results,
        "public_resolver_nxdomain": ev.public_nxdomain,
        "isp_resolver": ev.isp_resolver,
        "isp_ips": ev.isp_ips,
        "isp_nxdomain": ev.isp_nxdomain,
    }
    if ev.doh_ips or public_has_answer:
        return TestResult(
            test=f"dns_{_slug(domain)}_system",
            category="dns",
            target=domain,
            verdict=Verdict.BLOCKED,
            method=BlockingMethod.DNS_BLOCKED_NXDOMAIN,
            evidence=common_evidence,
            confidence=0.9,
        )
    return TestResult(
        test=f"dns_{_slug(domain)}_system",
        category="dns",
        target=domain,
        verdict=Verdict.INCONCLUSIVE,
        method=BlockingMethod.DNS_BLOCKED_NXDOMAIN,
        evidence=common_evidence,
        confidence=0.5,
        notes="NXDOMAIN from all resolvers including DoH — domain may not exist.",
    )


async def _aggregate_cert_validity(domain: str, sys_ips: list[str]) -> bool | None:
    """Validate cert across EVERY system-returned IP.

    Round-robin DNS poisoning (one valid IP + one captive) escapes the
    single-IP check: the attacker's first answer is fine, every
    subsequent answer is the censor. Treat the system as poisoned iff
    ANY of the returned IPs presents an invalid cert; treat as valid
    iff ALL of them validate.
    """
    if not sys_ips:
        return None
    cert_results = await asyncio.gather(*[_validate_cert(domain, ip) for ip in sys_ips])
    if any(r is False for r in cert_results):
        return False
    if all(r is True for r in cert_results):
        return True
    return None


def _decide_dns_verdict(
    *,
    cert_valid: bool | None,
    ip_overlap: bool,
    doh_ips: list[str],
    sys_ips: list[str],
) -> tuple[Verdict, BlockingMethod | None, float]:
    """CERTainty-style verdict: cert validity + DoH consensus."""
    if cert_valid is False:
        if ip_overlap:
            return Verdict.ANOMALY, None, 0.6
        if not doh_ips:
            # DoH itself was unreachable / blocked, so we have no second
            # source of truth. Cert-failure alone (without DoH consensus)
            # cannot prove DNS poisoning per CERTainty PETS 2023 — the IP
            # could be authentic but serving a broken cert.
            return Verdict.ANOMALY, None, 0.4
        return Verdict.BLOCKED, BlockingMethod.DNS_POISONING, 0.9
    if cert_valid is True:
        return Verdict.OK, None, 0.9
    # cert_valid is None — connection failed for non-cert reasons
    # (TCP RST, timeout). Use DoH-overlap as the secondary signal.
    if ip_overlap:
        return Verdict.OK, None, 0.5
    if doh_ips and sys_ips:
        return Verdict.INCONCLUSIVE, None, 0.3
    return Verdict.INCONCLUSIVE, None, 0.2


async def _test_domain(domain: str) -> list[TestResult]:
    """Full DNS test suite for one domain."""
    ev = await _gather_resolver_evidence(domain)

    if ev.sys_nxdomain:
        return [_build_nxdomain_result(domain, ev)]

    if ev.sys_error and not ev.sys_ips:
        # Pure system-resolver error (not NXDOMAIN) — can't conclude blocking
        # from this alone. Surface as INCONCLUSIVE with the error in evidence.
        return [
            TestResult(
                test=f"dns_{_slug(domain)}_system",
                category="dns",
                target=domain,
                verdict=Verdict.INCONCLUSIVE,
                evidence={
                    "system_error": ev.sys_error,
                    "doh_ips": ev.doh_ips,
                    "public_resolver_ips": ev.public_results,
                    "isp_resolver": ev.isp_resolver,
                },
                confidence=0.2,
            )
        ]

    # CERTainty-style verdict: cert validity + DoH consensus.
    # ASN is collected for forensics only — comparing against a static
    # expected-ASN list misclassifies CDN regional rotation as poisoning.
    resolved_asn = await _ip_to_asn(ev.sys_ips[0]) if ev.sys_ips else None
    cert_valid = await _aggregate_cert_validity(domain, ev.sys_ips)

    # Match against ANY single resolver's answer set — CDNs return
    # different edge IPs to different resolvers, and a union-overlap
    # check fails on those even when every resolver agrees the domain
    # is healthy.
    sys_set = set(ev.sys_ips)
    ip_overlap = any(sys_set & rs for rs in ev.per_resolver_sets) if sys_set else False

    verdict, method, confidence = _decide_dns_verdict(
        cert_valid=cert_valid,
        ip_overlap=ip_overlap,
        doh_ips=ev.doh_ips,
        sys_ips=ev.sys_ips,
    )

    return [
        TestResult(
            test=f"dns_{_slug(domain)}_system",
            category="dns",
            target=domain,
            verdict=verdict,
            method=method,
            evidence={
                "system_ips": ev.sys_ips,
                "system_ttl": ev.sys_ttl,
                "isp_ips": ev.isp_ips,
                "doh_ips": ev.doh_ips,
                "resolved_asn": resolved_asn,
                "cert_valid": cert_valid,
                "ip_overlap_with_doh": ip_overlap,
                "isp_resolver": ev.isp_resolver,
                "public_resolver_ips": ev.public_results,
            },
            confidence=confidence,
        )
    ]


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
    # DoH is one of several resolver paths probed in parallel; any error
    # (timeout, TLS failure, blocked) means "this resolver is unreachable",
    # which is itself a useful signal — the caller compares answer-set
    # disagreement across resolvers, not their up-ness individually.
    with contextlib.suppress(Exception):
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
    return []


def _build_a_query(name: str, qid: int = 1) -> bytes:
    """Minimal A-record DNS query wire packet (RFC 1035)."""
    import struct

    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"
    # Header: id, flags (RD), qdcount=1, ancount=0, nscount=0, arcount=0
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    # QTYPE 1 (A), QCLASS 1 (IN). No "=" in the trailing comment so
    # Sonar's commented-out-code heuristic (S125) does not misfire on it.
    question = labels + struct.pack(">HH", 1, 1)
    return header + question


def _skip_dns_qname(data: bytes, pos: int) -> int:
    """Advance ``pos`` past one DNS name (label sequence or 16-bit pointer)."""
    if pos >= len(data):
        return pos
    if (data[pos] & 0xC0) == 0xC0:
        return pos + 2
    while pos < len(data) and data[pos] != 0:
        pos += data[pos] + 1
    return pos + 1


def _parse_a_records(data: bytes) -> list[str]:
    """Extract A-record IPs from a DNS response wire packet."""
    import ipaddress
    import struct

    if len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return []

    # Skip past the question section (qname + qtype + qclass).
    pos = _skip_dns_qname(data, 12) + 4

    ips: list[str] = []
    for _ in range(ancount):
        if pos >= len(data):
            break
        try:
            pos = _skip_dns_qname(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos : pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                ips.append(str(ipaddress.IPv4Address(data[pos : pos + 4])))
            pos += rdlen
        except (IndexError, struct.error, ValueError):
            break
    return ips


def _dot_query_blocking(host: str, port: int, framed: bytes, ctx: ssl.SSLContext) -> list[str]:
    """Send one framed DNS query over TLS, return parsed A records (or [] on any error)."""
    import struct

    try:
        with socket.create_connection((host, port), timeout=5.0) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(framed)
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


async def _resolve_dot(domain: str, host: str, port: int = 853) -> list[str]:
    """Resolve domain via DNS-over-TLS (RFC 7858).

    Wraps a standard UDP DNS query inside a TLS connection to the resolver.
    Returns a list of IPv4 addresses, or empty list on any error. DoT
    bypasses ISP DNS manipulation in the same way DoH does, and its
    failure (TLS connect refused) is separately meaningful for detecting
    DoT blocking.
    """
    import struct

    ctx = ssl.create_default_context()
    query = _build_a_query(domain)
    # DoT framing: 2-byte big-endian length prefix before the DNS message.
    framed = struct.pack(">H", len(query)) + query

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _dot_query_blocking, host, port, framed, ctx),
            timeout=8.0,
        )
    except Exception:
        return []


def _name_matches_with_apex(name: str, target: str) -> bool:
    """Hostname match with apex relaxation.

    Both arguments must already be lowercased and trailing-dot-stripped.

    Behaviours:
      * exact match (``foo.com`` == ``foo.com``)
      * standard one-label wildcard (``*.foo.com`` covers ``a.foo.com``)
      * apex relaxation (``*.foo.com`` is treated as also covering
        ``foo.com`` even though RFC 6125 says wildcards only match a
        subdomain label — see :func:`_cert_san_covers_domain_family`).
    """
    if name == target:
        return True
    if not name.startswith("*."):
        return False
    wild_base = name[2:]
    # Standard one-label wildcard.
    if target.endswith("." + wild_base) and target.count(".") == wild_base.count(".") + 1:
        return True
    # Apex relaxation.
    return wild_base == target


def _subject_common_name(cert: dict[str, Any]) -> str | None:
    """Return the cert's Subject CommonName, or ``None`` if absent.

    ``getpeercert()`` shapes the subject as a tuple of RDN tuples:
    ``((("commonName", "foo.com"),), (("organizationName", "..."),))``.
    Walk the structure defensively — non-conforming certs may omit
    fields entirely, in which case CN is simply absent.
    """
    for rdn in cert.get("subject") or ():
        for key, value in rdn:
            if key == "commonName":
                return value if isinstance(value, str) else None
    return None


def _cert_san_covers_domain_family(cert: dict[str, Any], domain: str) -> bool:
    """Whether ``cert``'s SAN/CN legitimately belongs to ``domain``'s family.

    Standard wildcard semantics PLUS an apex relaxation: a SAN entry of
    ``*.example.com`` is treated as covering the bare apex ``example.com``,
    even though RFC 6125 says wildcards only match a single subdomain
    label. Operators routinely deploy a single ``*.foo.com`` cert and
    serve the apex from the same fleet — DW (``*.dw.com``) is the
    canonical example. The strict RFC reading flagged that as
    DNS_POISONING with confidence 0.6 every run; the relaxation says
    "this cert was issued to the domain owner, no censor in path".

    Subject CommonName is a fallback used only when the cert has no DNS
    SAN entries — it mirrors what Python's default ``check_hostname=True``
    does, and only matters for legacy CAs. Public CAs have been
    SAN-mandatory since the CAB Forum baseline of 2017, so production
    targets effectively never hit this branch.

    A real MITM with a CA-signed cert for an unrelated domain (e.g.
    ``*.attacker.example``) still fails this check because no SAN entry
    or CN covers the target's domain family. That residual edge case is
    further pruned by the ASN/ip_overlap signals in
    ``_decide_dns_verdict``.
    """
    target = domain.lower().rstrip(".")
    sans = cert.get("subjectAltName") or ()
    has_dns_san = False
    for kind, value in sans:
        if kind != "DNS":
            continue
        has_dns_san = True
        if _name_matches_with_apex(value.lower().rstrip("."), target):
            return True
    if has_dns_san:
        # SAN list present but no entry matched — strictly per RFC 6125,
        # CN is NOT consulted as a fallback in that case. Avoids granting
        # legitimacy to a cert whose CN happens to match the target while
        # its SAN list points at unrelated names.
        return False
    cn = _subject_common_name(cert)
    if cn is None:
        return False
    return _name_matches_with_apex(cn.lower().rstrip("."), target)


async def _validate_cert(domain: str, ip: str) -> bool | None:
    """
    Connect to IP:443 with SNI=domain and check if cert is valid for domain.
    Returns True/False/None (None = connection failed, inconclusive).

    Validation strategy: validate the **chain** strictly, then check the
    **hostname** against the cert's SAN list manually with apex-relaxed
    wildcard semantics (see :func:`_cert_san_covers_domain_family`).
    Standard ``check_hostname=True`` rejects ``*.dw.com`` for SNI=``dw.com``
    per RFC 6125 even though the cert is the legitimate one DW provisions
    on its fleet — strict-mode flagged that as DNS_POISONING every run.

    Three failure modes still count as "cert invalid for `domain`":

      * ssl.SSLCertVerificationError — chain failed verification (real
        MITM with a self-signed or untrusted cert).
      * ssl.SSLError without the verification subclass — TSPU MITM
        serving a cert that fails OpenSSL chain checks at handshake
        time ("unable to get local issuer certificate").
      * Chain valid but SAN list belongs to an unrelated domain
        family — possible CA-cert MITM (rare; a censor would need to
        actually obtain a CA-issued cert for some other name).
    """

    def _check() -> bool | None:
        # Build a context that validates the chain but defers hostname
        # check to our SAN-with-apex-relaxation logic below.
        ctx = ssl.create_default_context()
        # Hostname verification is performed manually below by
        # _cert_san_covers_domain_family with apex relaxation — Python's
        # strict RFC 6125 check_hostname rejects legitimate `*.dw.com`
        # certs presented for SNI=`dw.com` (the canonical example), and
        # we need that case to validate. Chain verification stays on
        # (verify_mode=CERT_REQUIRED), so a self-signed / untrusted-CA
        # MITM still surfaces as SSLCertVerificationError and is mapped
        # to cert_valid=False. The S5527 suppression on the next assignment
        # is justified because hostname verification is not skipped — it is
        # moved into the SAN-with-apex helper, which also rejects CA-cert
        # MITMs whose SAN list does not cover the target domain family.
        ctx.check_hostname = False  # NOSONAR S5527
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection((ip, 443), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    cert = s.getpeercert()
                    if not cert:
                        return None
                    return _cert_san_covers_domain_family(cert, domain)
        except ssl.SSLCertVerificationError:
            # Chain itself failed: untrusted root, expired, self-signed,
            # signature mismatch. Either real MITM or a misconfigured
            # endpoint — call it invalid for `domain`.
            return False
        except ssl.SSLError:
            # MITM with a self-signed cert raises bare SSLError, not
            # SSLCertVerificationError. Treat as "cert invalid" so
            # DNS_POISONING is correctly attributed.
            return False
        except Exception:
            # Pre-TLS failure (TCP RST, timeout, ECONNREFUSED). Caller
            # treats None as "inconclusive", NOT "cert invalid" — this
            # prevents flagging a TCP-RST as DNS_POISONING.
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

    # ipapi.is is a soft enrichment — any failure (network error, parse
    # error, schema drift) just means we don't get an ASN annotation.
    # Cache the negative below so we don't hammer the API on the next probe.
    with contextlib.suppress(Exception):
        client = _get_asn_client()
        r = await client.get(
            _IPAPI_IS_URL,
            params={"q": ip, "key": _ipapi_key()},
        )
        if r.status_code == 429:
            _ASN_BACKOFF_UNTIL = now + _config_asn_backoff_sec()
            return None
        if r.status_code == 200:
            data = r.json()
            asn_block = data.get("asn") or {}
            asn_num = asn_block.get("asn")
            if asn_num:
                asn = f"AS{asn_num}"
                _ASN_CACHE[ip] = asn
                return asn
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
        upstream = _parse_first_nameserver(Path("/run/systemd/resolve/resolv.conf").read_text())
    except OSError:
        upstream = None

    return upstream or primary


def _slug(domain: str) -> str:
    """Convert domain to safe slug: meduza.io → meduza_io"""
    return domain.replace(".", "_").replace("-", "_").lower()
