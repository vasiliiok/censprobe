"""
modules/protocols.py — VPN protocol signature tests from the probe side.

Solo sends actual VPN handshakes using real binaries to a control-point (listener) 
and checks whether they arrive and get a valid response.

Tests:
  - OpenVPN:        Uses openvpn in static-key mode
  - WireGuard:      Uses wg-quick
  - AmneziaWG:      Uses awg-quick
  - Shadowsocks:    Uses sing-box 2022
  - VLESS+Reality:  Uses xray vision
  - Hysteria 2:     Uses hysteria client

If control_endpoints is None (solo-only mode), returns INCONCLUSIVE.
When listener is running, control_endpoints comes from protocols.yaml.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from censprobe_core.models import BlockingMethod, TestResult, Verdict
from censprobe_core.protocol_probes import (
    probe_openvpn,
    probe_wireguard,
    probe_amneziawg,
    probe_shadowsocks,
    probe_vless_reality,
    probe_hysteria2,
)

logger = logging.getLogger(__name__)


async def run_protocol_tests(
    control_endpoints: list[dict] | None = None,
) -> list[TestResult]:
    """
    Run VPN protocol signature tests using real binaries.

    In solo-without-listener mode, these return INCONCLUSIVE because there
    is no server to respond. When listener is deployed, pass control_endpoints
    from protocols.yaml so probes can measure actual reachability.
    """
    if not control_endpoints:
        return [
            TestResult(
                test="protocols_listener_not_configured",
                category="protocols",
                target="n/a",
                verdict=Verdict.INCONCLUSIVE,
                evidence={"reason": "No listener endpoint configured. Run listener container first."},
                notes="Protocol tests require listener container to be running",
            )
        ]

    results = []
    for ep in control_endpoints:
        protocol = ep.get("protocol", "unknown")
        ip = ep.get("ip", "")
        port = ep.get("port", 0)
        if not ip or not port:
            continue

        test_name = f"protocol_{protocol}_{ip}_{port}"
        target = f"{ip}:{port}"
        r = TestResult(test=test_name, category="protocols", target=target)
        
        try:
            if protocol == "openvpn":
                pr = await probe_openvpn(ip, port, ep.get("psk_b64", ""))
            elif protocol == "wireguard":
                pr = await probe_wireguard(
                    ip, port, ep.get("server_public_key", ""),
                    ep.get("client_public_key", ""), ep.get("preshared_key", ""),
                    ep.get("client_private_key", "")
                )
            elif protocol == "amneziawg":
                pr = await probe_amneziawg(
                    ip, port, ep.get("server_public_key", ""),
                    ep.get("client_public_key", ""), ep.get("preshared_key", ""),
                    ep.get("client_private_key", ""),
                    ep.get("jc", 4), ep.get("jmin", 40), ep.get("jmax", 70),
                    ep.get("s1", 0), ep.get("s2", 0),
                    ep.get("h1", 0), ep.get("h2", 0), ep.get("h3", 0), ep.get("h4", 0)
                )
            elif protocol == "shadowsocks":
                pr = await probe_shadowsocks(ip, port, ep.get("method", ""), ep.get("password_b64", ""))
            elif protocol == "vless_reality":
                pr = await probe_vless_reality(
                    ip, port, ep.get("uuid", ""), ep.get("public_key", ""),
                    ep.get("short_id", ""), ep.get("server_name", "apimaps.yandex.ru")
                )
            elif protocol == "hysteria2":
                pr = await probe_hysteria2(ip, port, ep.get("auth", ""), ep.get("obfs_password", ""))
            else:
                r.verdict = Verdict.INCONCLUSIVE
                r.evidence = {"reason": f"Protocol '{protocol}' not supported"}
                results.append(r)
                continue

            r.verdict = pr.verdict
            r.rtt_ms = pr.rtt_ms
            if pr.error:
                r.evidence = {"error": pr.error}
            elif pr.verdict == Verdict.BLOCKED:
                r.method = BlockingMethod.IP_DROPPED
                r.evidence = {"reason": "Handshake timeout or reset"}
            elif pr.verdict == Verdict.HANDSHAKE_ONLY:
                r.evidence = {"reason": "Handshake ok, but data transfer failed"}
                r.method = BlockingMethod.VPN_DATA_PHASE_BLOCKED

        except Exception as e:
            r.verdict = Verdict.ERROR
            r.evidence = {"exception": str(e)}

        results.append(r)

    return results
