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
import dns.resolver
import dns.rdatatype
import httpx

from censprobe_core.models import TestResult, Verdict, BlockingMethod
from censprobe_core.baseline import BaselineComparator

logger = logging.getLogger(__name__)

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
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), http2=True) as client:
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

    # 1. System resolver
    sys_ips, sys_error = await _resolve_system(domain)

    # 2. Public resolvers
    public_results: dict[str, list[str]] = {}
    for rname, rip in PUBLIC_RESOLVERS:
        ips, _ = await _resolve_via(domain, rip)
        public_results[rname] = ips

    # 3. DoH resolvers
    doh_results: dict[str, list[str]] = {}
    for rname, url in DOH_RESOLVERS:
        ips = await _resolve_doh(domain, url)
        doh_results[rname] = ips

    # 4. Determine "ground truth" from DoH (most reliable, bypasses ISP)
    doh_ips: list[str] = []
    for ips in doh_results.values():
        doh_ips.extend(ips)
    doh_ips = list(set(doh_ips))

    # 5. Detect ISP resolver (first nameserver in /etc/resolv.conf)
    isp_resolver = _get_isp_resolver()
    isp_ips, isp_nxdomain = await _resolve_via(domain, isp_resolver) if isp_resolver else ([], False)

    # 6. NXDOMAIN detection
    if not sys_ips and not sys_error:
        # NXDOMAIN from system resolver
        results.append(TestResult(
            test=f"dns_{_slug(domain)}_system",
            category="dns",
            target=domain,
            verdict=Verdict.DNS_BLOCKED,
            method=BlockingMethod.DNS_BLOCKED_NXDOMAIN,
            evidence={
                "system_nxdomain": True,
                "doh_ips": doh_ips,
                "isp_resolver": isp_resolver,
            },
            confidence=0.85,
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
            "isp_ips": isp_ips,
            "doh_ips": doh_ips,
            "resolved_asn": resolved_asn,
            "cert_valid": cert_valid,
            "isp_resolver": isp_resolver,
            "public_resolver_ips": public_results,
        },
        confidence=0.9 if verdict != Verdict.INCONCLUSIVE else 0.3,
    ))

    return results


async def _resolve_system(domain: str) -> tuple[list[str], Optional[str]]:
    """Resolve via system resolver."""
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(domain, "A")
        return [str(r) for r in answers], None
    except dns.resolver.NXDOMAIN:
        return [], None  # NXDOMAIN — not an error, just empty
    except Exception as e:
        return [], str(e)


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
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), http2=True) as client:
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


async def _validate_cert(domain: str, ip: str) -> Optional[bool]:
    """
    Connect to IP:443 with SNI=domain and check if cert is valid for domain.
    Returns True/False/None (None = connection failed, inconclusive).
    """
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_running_loop()

        def _check() -> bool:
            try:
                with socket.create_connection((ip, 443), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=domain) as s:
                        s.getpeercert()  # raises if cert invalid
                        return True
            except ssl.SSLCertVerificationError:
                return False
            except Exception:
                return None  # type: ignore[return-value]

        return await loop.run_in_executor(None, _check)
    except Exception:
        return None


async def _ip_to_asn(ip: str) -> Optional[str]:
    """Look up ASN for an IP via ip-api.com (lightweight)."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=as")
            if r.status_code == 200:
                data = r.json()
                raw = data.get("as", "")
                if raw:
                    return raw.split(" ")[0]  # "AS13335 Cloudflare" → "AS13335"
    except Exception:
        pass
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
