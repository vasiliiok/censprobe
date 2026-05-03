"""
server_meta.py — Server metadata detection and ipapi.is enrichment.

Public API:
  detect_server_meta()         — full server-side detection (IP → enrichment
                                  + IPv6 + kernel/distro). Used by solo and
                                  listener at startup.
  enrich_endpoint(ip, client)  — IP → EndpointMeta. Reusable helper, called
                                  from listener for client-side enrichment
                                  when a client hits the cred-endpoint.

OpSec:
  * All geo/ASN lookups go over HTTPS so an on-path observer cannot cheaply
    link the queried IP to censorship-measurement activity.
  * The exit IP is detected at runtime to drive the lookup but is not
    returned to callers — only the structured EndpointMeta is. This keeps
    raw IPv4 literals out of every serialized report by construction.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
from pathlib import Path

import httpx

from censprobe_core.models import (
    AsnInfo,
    CompanyInfo,
    DatacenterInfo,
    EndpointMeta,
    LocationInfo,
    ServerMeta,
)

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0)

# Vantage country code (ISO-3166 alpha-2). Set once after server_meta
# detection; consumed by measurement modules to gate censor-specific
# attribution heuristics — e.g. tcp.py's <30 ms RST_INJECTED label
# produces false positives from Frankfurt because anycast RTT to closed
# ports is below the threshold without any censor in the path.
_VANTAGE_COUNTRY: str | None = None


def set_vantage_country(cc: str | None) -> None:
    """Record the probe vantage's country code (ISO-3166 alpha-2).

    Honours :data:`censprobe_core.config.VantageConfig.override` if set
    — useful for testing the heuristics from outside a censor's network
    or when the host's auto-detected country diverges from the network
    actually being measured (e.g. a tunnelled host)."""
    from censprobe_core.config import get_config

    global _VANTAGE_COUNTRY
    override = get_config().vantage.override
    if override:
        _VANTAGE_COUNTRY = override.upper()
    else:
        _VANTAGE_COUNTRY = cc.upper() if cc else None


def get_vantage_country() -> str | None:
    """Return the recorded vantage country, or None if never set."""
    return _VANTAGE_COUNTRY


def is_censoring_vantage() -> bool:
    """True iff the vantage country is in
    :data:`censprobe_core.config.VantageConfig.censoring_countries`.

    Modules that calibrate timing/RTT thresholds for RU/CN/IR-style
    networks gate on this so a Frankfurt VM (or any other uncensored
    vantage) doesn't get a flood of spurious BLOCKED verdicts from
    heuristics that only make sense behind a state filter.

    The whitelist is configured via ``vantage.censoring_countries``
    in censprobe.yaml; extend it when probing from another censoring
    vantage.
    """
    # Lazy import keeps server_meta importable without triggering
    # a circular import at module load time.
    from censprobe_core.config import get_config

    if _VANTAGE_COUNTRY is None:
        return False
    return _VANTAGE_COUNTRY in {
        cc.upper() for cc in get_config().vantage.censoring_countries
    }


# Back-compat alias. Kept indefinitely because the module ecosystem
# (dns/tcp/cloudflare/throttling) used this name for several months and
# external tooling may still call it. New code should prefer
# :func:`is_censoring_vantage`.
def is_ru_vantage() -> bool:
    """Deprecated: prefer :func:`is_censoring_vantage`."""
    return is_censoring_vantage()

# Lazy lookup: importing this module must not require the env var to be
# set. Code paths that never actually call _enrich (probe-core consumers
# that only use models/runner) must still be able to `import censprobe_core`.
# An empty string is a valid runtime state ("no key, use ipapi.is free tier");
# a missing env var only matters when we actually issue the lookup.
_IPAPI_IS_URL = "https://api.ipapi.is/"


def _ipapi_key() -> str:
    return os.environ.get("IPAPI_IS_KEY", "")


async def detect_server_meta() -> ServerMeta:
    """Auto-detect server metadata.

    Returns ServerMeta with EndpointMeta populated from ipapi.is plus host
    info (kernel, distro, IPv6). The exit IP itself is detected to drive
    the lookup but is not stored on ServerMeta.
    """
    meta = ServerMeta()

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        exit_ip = await _detect_exit_ip(client)
        if exit_ip:
            endpoint = await enrich_endpoint(exit_ip, client=client)
            if endpoint is not None:
                meta.endpoint = endpoint
        else:
            logger.warning(
                "Could not detect server exit IP. Network may be unreachable. "
                "Server endpoint metadata (ASN, location, company) will be empty."
            )

    meta.ipv6_available = await _check_ipv6()
    meta.kernel = detect_kernel()
    meta.distro = detect_distro()

    return meta


async def enrich_endpoint(
    ip: str,
    client: httpx.AsyncClient | None = None,
) -> EndpointMeta | None:
    """Look up `ip` against ipapi.is and return a structured EndpointMeta.

    Returns None on any failure (transport, non-200, JSON shape mismatch,
    rate-limit). Callers treat None as "enrichment unavailable" — distinct
    from "endpoint not connected at all".

    The `client` argument lets the caller share an httpx client across
    multiple enrichments. If omitted we open a short-lived one.
    """
    if client is None:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as own_client:
            return await _enrich(ip, own_client)
    return await _enrich(ip, client)


async def _enrich(ip: str, client: httpx.AsyncClient) -> EndpointMeta | None:
    try:
        r = await client.get(
            _IPAPI_IS_URL,
            params={"q": ip, "key": _ipapi_key()},
        )
        if r.status_code != 200:
            logger.debug("ipapi.is non-200: %s", r.status_code)
            return None
        data = r.json()
    except Exception as e:
        logger.debug("ipapi.is failed: %s", e)
        return None

    return _endpoint_from_ipapi(data)


def _endpoint_from_ipapi(data: dict) -> EndpointMeta:
    """Map an ipapi.is JSON response onto EndpointMeta.

    Tolerates missing nested objects (free tier returns thinner payloads
    than keyed). Returns an EndpointMeta with as much populated as the
    response provides; nested objects stay None when their source block
    is absent.
    """
    asn_block = data.get("asn") or {}
    company_block = data.get("company") or {}
    datacenter_block = data.get("datacenter") or {}
    loc_block = data.get("location") or {}

    asn_num = asn_block.get("asn")
    asn_info: AsnInfo | None = None
    if asn_num is not None:
        try:
            asn_info = AsnInfo(
                asn=int(asn_num),
                descr=asn_block.get("descr"),
                org=asn_block.get("org"),
                domain=asn_block.get("domain"),
                route=asn_block.get("route"),
            )
        except (TypeError, ValueError):
            asn_info = None

    company_info: CompanyInfo | None = None
    if company_block:
        company_info = CompanyInfo(
            name=company_block.get("name"),
            domain=company_block.get("domain"),
            network=company_block.get("network"),
        )

    is_datacenter = bool(data.get("is_datacenter", False))
    datacenter_info: DatacenterInfo | None = None
    # Only populate datacenter block when the flag is true AND ipapi
    # returned the nested object — free tier sometimes returns the flag
    # without the nested details.
    if is_datacenter and datacenter_block:
        datacenter_info = DatacenterInfo(
            # ipapi returns the DC operator under the key "datacenter"
            # inside the datacenter block — flatten that to `name` to
            # match the rest of our naming.
            name=datacenter_block.get("datacenter") or datacenter_block.get("name"),
            domain=datacenter_block.get("domain"),
            network=datacenter_block.get("network"),
        )

    location_info: LocationInfo | None = None
    if loc_block:
        location_info = LocationInfo(
            country_code=loc_block.get("country_code"),
            city=loc_block.get("city"),
        )

    return EndpointMeta(
        is_mobile=bool(data.get("is_mobile", False)),
        is_datacenter=is_datacenter,
        asn=asn_info,
        company=company_info,
        datacenter=datacenter_info,
        location=location_info,
    )


async def _detect_exit_ip(client: httpx.AsyncClient) -> str | None:
    """Detect external IP via Cloudflare trace (primary) and icanhazip.com (fallback)."""
    try:
        r = await client.get("https://www.cloudflare.com/cdn-cgi/trace")
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.startswith("ip="):
                    return line.split("=", 1)[1].strip()
    except Exception as e:
        logger.debug("Cloudflare trace failed: %s", e)

    try:
        r = await client.get("https://icanhazip.com/")
        if r.status_code == 200:
            return r.text.strip()
    except Exception as e:
        logger.debug("icanhazip failed: %s", e)

    return None


async def _check_ipv6() -> bool:
    """Check if IPv6 connectivity is available.

    On hosts where the kernel has IPv6 disabled (some hardened/minimal Linux
    images), `socket.socket(AF_INET6, ...)` itself raises OSError(EAFNOSUPPORT)
    — we treat that as "no IPv6" rather than letting it tear down the whole
    `detect_server_meta` flow.
    """
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return False
    try:
        loop = asyncio.get_running_loop()
        sock.settimeout(3.0)
        await loop.run_in_executor(
            None,
            lambda: sock.connect(("2606:4700:4700::1111", 80)),
        )
        return True
    except Exception:
        return False
    finally:
        sock.close()


def detect_kernel() -> str:
    """Detect kernel version string. Cheap, no network."""
    try:
        return platform.uname().release
    except Exception:
        return "unknown"


def detect_distro() -> str:
    """Detect Linux distro from /etc/os-release. Cheap, no network."""
    try:
        path = Path("/etc/os-release")
        if path.exists():
            data = {}
            for line in path.read_text().splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip().strip('"')
            name = data.get("PRETTY_NAME") or data.get("NAME", "Linux")
            version = data.get("VERSION_ID", "")
            return f"{name} {version}".strip()
    except Exception:
        pass
    return platform.system()
