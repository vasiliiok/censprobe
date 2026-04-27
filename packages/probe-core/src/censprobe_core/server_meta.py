"""
server_meta.py — Auto-detection of server metadata.

Detects:
  - External/exit IP (via Cloudflare trace + icanhazip.com)
  - ASN and AS name (via ipapi.is over HTTPS)
  - IPv6 availability
  - Kernel version, distro

OpSec:
  * All geo/ASN lookups go over HTTPS so an on-path observer cannot cheaply
    link this server's IP to censorship-measurement activity.
  * Exit IP is masked to /24 before being written into git.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
from pathlib import Path
from typing import Optional

import httpx

from censprobe_core.models import ServerMeta

logger = logging.getLogger(__name__)

# Timeout for external requests
_TIMEOUT = httpx.Timeout(10.0)

_IPAPI_IS_KEY = os.environ.get("IPAPI_IS_KEY", "")
_IPAPI_IS_URL = "https://api.ipapi.is/"


async def detect_server_meta() -> ServerMeta:
    """
    Auto-detect server metadata from the environment.
    Returns ServerMeta with sensitive fields masked.
    """
    meta = ServerMeta()

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # --- Exit IP and ASN ---
        exit_ip = await _detect_exit_ip(client)
        if exit_ip:
            meta._exit_ip = exit_ip
            meta.ipv4_masked = _mask_ip(exit_ip)
            asn_info = await _detect_asn(client, exit_ip)
            if asn_info:
                meta.asn = asn_info.get("asn")
                meta.as_name = asn_info.get("as_name")
                meta.location = asn_info.get("city")
                # `country` is recorded too — control orchestrator now
                # threads it into BaselineControlPoint instead of falling
                # back to a hardcoded "DE".
                meta.country = asn_info.get("country")
                meta.provider = _guess_provider(asn_info.get("as_name", ""))
        else:
            logger.warning(
                "Could not detect server exit IP. Network may be unreachable. "
                "Server metadata (ASN, location, provider) will be empty."
            )

    # --- IPv6 ---
    meta.ipv6_available = await _check_ipv6()

    # --- Kernel / Distro ---
    meta.kernel = detect_kernel()
    meta.distro = detect_distro()

    return meta


async def _detect_exit_ip(client: httpx.AsyncClient) -> Optional[str]:
    """Detect external IP via Cloudflare trace (primary) and icanhazip.com (fallback)."""
    # Primary: Cloudflare CDN-CGI trace
    try:
        r = await client.get("https://www.cloudflare.com/cdn-cgi/trace")
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.startswith("ip="):
                    return line.split("=", 1)[1].strip()
    except Exception as e:
        logger.debug("Cloudflare trace failed: %s", e)

    # Fallback: icanhazip.com
    try:
        r = await client.get("https://icanhazip.com/")
        if r.status_code == 200:
            return r.text.strip()
    except Exception as e:
        logger.debug("icanhazip failed: %s", e)

    return None


async def _detect_asn(client: httpx.AsyncClient, ip: str) -> Optional[dict]:
    """
    Detect ASN, AS name, and city for an IP via ipapi.is (HTTPS, keyed).

    ipapi.is response shape (relevant subset):
      {
        "ip": "...",
        "asn": {"asn": 49505, "org": "JSC Selectel", ...},
        "company": {"name": "Selectel", ...},
        "location": {"city": "...", "country": "...", "state": "..."},
      }
    """
    try:
        r = await client.get(
            _IPAPI_IS_URL,
            params={"q": ip, "key": _IPAPI_IS_KEY},
        )
        if r.status_code != 200:
            logger.debug("ipapi.is non-200: %s", r.status_code)
            return None

        data = r.json()
        asn_block = data.get("asn") or {}
        loc_block = data.get("location") or {}
        company_block = data.get("company") or {}

        asn_num = asn_block.get("asn")
        asn_str = f"AS{asn_num}" if asn_num else None
        as_name = (
            asn_block.get("org")
            or company_block.get("name")
            or data.get("company", {}).get("name")
        )

        return {
            "asn": asn_str,
            "as_name": as_name,
            "city": loc_block.get("city"),
            "country": loc_block.get("country"),
            "region": loc_block.get("state"),
        }
    except Exception as e:
        logger.debug("ipapi.is failed: %s", e)

    return None


def _mask_ip(ip: str) -> str:
    """
    Mask IPv4 to /24 for privacy: 1.2.3.4 → 1.2.3.0/24.
    For IPv6: mask to /48 (first 3 hextets).
    Returns "unknown" if the input isn't a valid IP.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip.strip())
    except Exception:
        return "unknown"
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{addr}/24", strict=False)
        return str(net)
    # IPv6
    net = ipaddress.ip_network(f"{addr}/48", strict=False)
    return str(net)


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


# Backwards-compatible aliases for any external caller still importing the
# private names. Internal call sites use the public spelling above.
_detect_kernel = detect_kernel
_detect_distro = detect_distro


def _guess_provider(as_name: str) -> Optional[str]:
    """Guess VPS provider name from AS name string."""
    as_lower = as_name.lower()
    mapping = {
        "selectel": "Selectel",
        "timeweb": "Timeweb",
        "vdsina": "VDSina",
        "hetzner": "Hetzner",
        "digitalocean": "DigitalOcean",
        "linode": "Linode",
        "vultr": "Vultr",
        "ovh": "OVH",
        "serverius": "Serverius",
        "ihor": "ihor",
        "king": "King Servers",
    }
    for key, val in mapping.items():
        if key in as_lower:
            return val
    return as_name[:32] if as_name else None
