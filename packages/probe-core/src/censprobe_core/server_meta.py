"""
server_meta.py — Auto-detection of server metadata.

Detects:
  - External/exit IP (via Cloudflare trace + icanhazip.com)
  - ASN and AS name (via ip-api.com)
  - IPv6 availability
  - Kernel version, distro

Sensitive: exit IP is masked to /24 before writing to git.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import platform
import re
import socket
from pathlib import Path
from typing import Optional

import httpx

from censprobe_core.models import ServerMeta

logger = logging.getLogger(__name__)

# Timeout for external requests
_TIMEOUT = httpx.Timeout(10.0)


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
                meta.provider = _guess_provider(asn_info.get("as_name", ""))

    # --- IPv6 ---
    meta.ipv6_available = await _check_ipv6()

    # --- Kernel / Distro ---
    meta.kernel = _detect_kernel()
    meta.distro = _detect_distro()

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
    """Detect ASN, AS name, city for a given IP via ip-api.com."""
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,as,org,city,country,regionName"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                raw_as = data.get("as", "")  # e.g. "AS49505 JSC Selectel"
                asn, as_name = _parse_as_field(raw_as)
                return {
                    "asn": asn,
                    "as_name": as_name or data.get("org", ""),
                    "city": data.get("city"),
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                }
    except Exception as e:
        logger.debug("ip-api.com failed: %s", e)

    return None


def _parse_as_field(raw: str) -> tuple[Optional[str], Optional[str]]:
    """Parse 'AS49505 JSC Selectel' into ('AS49505', 'JSC Selectel')."""
    m = re.match(r"(AS\d+)\s*(.*)", raw)
    if m:
        return m.group(1), m.group(2).strip() or None
    return None, None


def _mask_ip(ip: str) -> str:
    """Mask IP to /24 for privacy: 1.2.3.4 → XXX.XXX.XXX.0/24"""
    try:
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        parts = str(net.network_address).split(".")
        return f"XXX.XXX.{parts[2]}.0/24"
    except Exception:
        return "XXX.XXX.XXX.0/24"


async def _check_ipv6() -> bool:
    """Check if IPv6 connectivity is available."""
    try:
        loop = __import__("asyncio").get_event_loop()
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.settimeout(3.0)
        # Try connecting to Cloudflare IPv6
        await loop.run_in_executor(
            None,
            lambda: sock.connect(("2606:4700:4700::1111", 80)),
        )
        sock.close()
        return True
    except Exception:
        return False


def _detect_kernel() -> str:
    """Detect kernel version string."""
    try:
        return platform.uname().release
    except Exception:
        return "unknown"


def _detect_distro() -> str:
    """Detect Linux distro from /etc/os-release."""
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
