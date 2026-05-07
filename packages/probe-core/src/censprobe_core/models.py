"""
Pydantic data models for Censprobe.

Covers:
- Verdict and BlockingMethod enums
- TestResult — single test outcome
- EndpointMeta — IP-free network identity (server or client)
- ReportMeta — reports/<test_id>/meta.yaml
- ServerMeta — auto-detected server metadata (EndpointMeta + host info)
- ListenerReport — output of censprobe-listener
- ProtocolResult — single VPN protocol handshake outcome

OpSec note: no specific IPv4/IPv6 host literals are stored in any
serialized model. ipapi.is enrichment exposes ASN, organization,
datacenter, and CIDR-level network ranges, which is sufficient for
cross-test/cross-session grouping without persisting host identifiers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from censprobe_core.subcategories import derive as _derive_subcategory

# Enums


class Verdict(StrEnum):
    """Top-level verdict for a single test."""

    OK = "OK"
    BLOCKED = "BLOCKED"
    HANDSHAKE_ONLY = "HANDSHAKE_ONLY"
    ANOMALY = "ANOMALY"
    GEOBLOCK_NOT_CENSORSHIP = "GEOBLOCK_NOT_CENSORSHIP"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"
    # DNS-specific
    DNS_POISONING = "DNS_POISONING"
    DNS_BLOCKED = "DNS_BLOCKED"
    DOH_BLOCKED = "DOH_BLOCKED"
    # TCP-specific
    IP_DROPPED = "IP_DROPPED"
    RST_INJECTED = "RST_INJECTED"
    REFUSED = "REFUSED"
    # Throttling-specific (Method B is the only throttling test left;
    # a generic THROTTLED verdict was retired with Method A).
    YOUTUBE_SNI_THROTTLED = "YOUTUBE_SNI_THROTTLED"


class BlockingMethod(StrEnum):
    """Attribution of the blocking/censorship technique."""

    DNS_POISONING = "dns_poisoning"
    DNS_BLOCKED_NXDOMAIN = "dns_blocked_nxdomain"
    DOH_BLOCKED = "doh_blocked"
    IP_DROPPED = "ip_dropped"
    TCP_RST_INJECTION = "tcp_rst_injection"
    TCP_RST_AFTER_TLS_CH = "tcp_rst_after_tls_ch"
    TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"
    ECH_BLOCKED = "ech_blocked"
    SNI_THROTTLING = "sni_throttling"
    QUIC_DROPPED = "quic_dropped"
    OPENVPN_SIGNATURE_BLOCKED = "openvpn_signature_blocked"
    WIREGUARD_SIGNATURE_BLOCKED = "wireguard_signature_blocked"
    SHADOWSOCKS_ACTIVE_PROBED = "shadowsocks_active_probed"
    VPN_DATA_PHASE_BLOCKED = "vpn_data_phase_blocked"
    MIDDLEBOX_HTTP_MANIPULATION = "middlebox_http_manipulation"
    UNKNOWN = "unknown"


# Core result model


class TestResult(BaseModel):
    """Single test result — one measurement of one target.

    ``subcategory`` is auto-derived from ``test`` + ``category`` via
    :mod:`censprobe_core.subcategories` — modules don't set it
    explicitly. Grafana SQL filters on this stable column instead of
    fragile ``test LIKE '...'`` patterns; see the subcategories module
    for the prefix→name contract.
    """

    test: str = Field(description="Test name, e.g. 'dns_meduza_io_system'")
    category: str = Field(
        description="Module category: dns|tcp|tls|http|telegram|throttling|protocols|middlebox"
    )
    subcategory: str = Field(
        default="",
        description="Stable family identifier auto-derived from `test`/`category`",
    )
    target: str = Field(description="Target URL, domain, or IP:port")
    verdict: Verdict
    method: BlockingMethod | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    rtt_ms: float | None = None
    attempts: int = 1
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    notes: str | None = None

    @model_validator(mode="after")
    def _populate_subcategory(self) -> TestResult:
        # Auto-fill only when the producer didn't supply one explicitly.
        # Old reports without ``subcategory`` round-trip through here on
        # re-import and pick up the derived value automatically.
        if not self.subcategory:
            self.subcategory = _derive_subcategory(self.test, self.category)
        return self


# Endpoint identity (IP-free)
#
# Three nested objects mirror the ipapi.is response shape so analytics can
# compare on whichever axis matters: ASN (network operator), company
# (legal owner), datacenter (physical hosting). They often coincide on a
# clean VPS but diverge when a tenant resells capacity inside someone
# else's facility, when an ISP runs multiple ASNs, or for residential
# clients where datacenter is null entirely. Keeping the three separate
# preserves that distinction; group-by for cross-test comparison uses
# `asn.asn` as the canonical key.


class AsnInfo(BaseModel):
    """Network-operator-level identity (one ASN = one routing entity)."""

    asn: int
    descr: str | None = None  # human-readable AS name, e.g. "AS-VULTR ..."
    org: str | None = None  # legal org behind the ASN
    domain: str | None = None  # e.g. "constant.com"
    route: str | None = None  # CIDR, e.g. "104.238.166.0/23"


class CompanyInfo(BaseModel):
    """Legal-entity-level identity (often == AsnInfo.org but not always)."""

    name: str | None = None
    domain: str | None = None
    network: str | None = None  # range, e.g. "104.238.128.0 - 104.238.191.255"


class DatacenterInfo(BaseModel):
    """Physical-DC identity. Populated only when is_datacenter is true."""

    name: str | None = None
    domain: str | None = None
    network: str | None = None


class LocationInfo(BaseModel):
    """Geographic identity. country_code is ISO-3166 alpha-2."""

    country_code: str | None = None  # "RU", "DE"
    city: str | None = None


class EndpointMeta(BaseModel):
    """IP-free network identity for one endpoint (server or client).

    `is_datacenter` is the primary QA signal for client endpoints: a
    client whose source IP belongs to a hosting provider is almost
    certainly behind a self-hosted VPN, which taints VPN-protocol
    verdicts in this run. This is more reliable than ipapi.is's
    `is_vpn`/`is_proxy` flags, which only catch services that mark
    themselves.

    `is_mobile` distinguishes mobile-carrier networks; mobile uplinks
    in RU are subject to heavier filtering than residential, so it
    matters as a comparison axis.
    """

    is_mobile: bool = False
    is_datacenter: bool = False
    asn: AsnInfo | None = None
    company: CompanyInfo | None = None
    datacenter: DatacenterInfo | None = None
    location: LocationInfo | None = None


# Server & report metadata


class ServerMeta(BaseModel):
    """Auto-detected metadata about the probe server.

    Embeds EndpointMeta for network identity; adds host-only fields the
    operator wants visible (kernel, distro, IPv6 availability). No IPv4
    literal is stored — `network` (in EndpointMeta nested objects) gives
    the CIDR range, which is enough for grouping without exposing host
    identifiers.
    """

    endpoint: EndpointMeta = Field(default_factory=EndpointMeta)
    ipv6_available: bool = False
    kernel: str | None = None
    distro: str | None = None


class ReportMeta(BaseModel):
    """Structure of reports/<test_id>/meta.yaml"""

    test_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    description: str | None = None
    server: ServerMeta = Field(default_factory=ServerMeta)
    purpose: str = "vpn-entry"  # vpn-entry | vpn-exit | vpn-relay
    planned_sessions: list[str] = Field(default_factory=list)
    probe_core_version: str = "0.1.0"


# Listener / Protocol models


class ProtocolResult(BaseModel):
    """Aggregated result for one protocol in a listener session.

    ``avg_throughput_mbps`` and ``throughput_throttled`` are populated only
    for the SOCKS-routed protocols (Shadowsocks, VLESS+Reality, Hysteria 2)
    via the listener's loopback echo-server's ``/throughput`` handler.
    OpenVPN / WireGuard / AmneziaWG keep both fields ``None``/``False``
    because their data-phase verification is a single ICMP ping, not a
    bulk download. The numeric value is *informational only* — never
    consumed by scoring, so a narrow server uplink isn't mis-attributed
    as censorship. ``throughput_throttled=True`` flags the case where the
    download didn't complete inside the timeout, i.e. sustained data
    plane is heavily throttled (or absent).
    """

    verdict: Verdict = Verdict.BLOCKED
    handshake_count: int = 0
    data_transfer_ok: bool = False
    first_handshake_at: datetime | None = None
    avg_rtt_ms: float | None = None
    avg_data_echo_ms: float | None = None
    avg_throughput_mbps: float | None = None
    throughput_throttled: bool = False
    note: str | None = None

    def finalize(self) -> None:
        """Set verdict based on counts."""
        if self.handshake_count > 0 and self.data_transfer_ok:
            self.verdict = Verdict.OK
        elif self.handshake_count > 0 and not self.data_transfer_ok:
            self.verdict = Verdict.HANDSHAKE_ONLY
        else:
            self.verdict = Verdict.BLOCKED


class ListenerReport(BaseModel):
    """Output of censprobe-listener — reports/<test_id>/server-listener-<session>-<ts>.json

    `client_connected` and `client` describe whether the operator-side
    client reached the listener's credentials HTTPS endpoint at all, and
    if so, what network it came from. Three valid states:

      1. client_connected=True, client=<EndpointMeta>
         — normal session, enrichment succeeded.
      2. client_connected=True, client=None
         — client hit the endpoint but ipapi.is enrichment failed
           (rate-limit, transient network). Per-protocol verdicts are
           still meaningful.
      3. client_connected=False, client=None
         — client never reached the endpoint. Strongest blocking
           signal: credentials were issued but the network did not
           even allow the cred fetch to complete. Per-protocol BLOCKED
           verdicts in this state are network-level, not protocol-level.
    """

    test_id: str
    session_id: str
    listener_started_at: datetime
    listener_stopped_at: datetime | None = None
    duration_sec: float | None = None
    client_connected: bool = False
    client: EndpointMeta | None = None
    results: dict[str, ProtocolResult] = Field(default_factory=dict)


# Scores


class ServerScores(BaseModel):
    """Computed suitability scores for a server."""

    entry_score: float = 0.0  # As VPN entry
    exit_score: float = 0.0  # As VPN exit
    relay_score: float = 0.0  # As relay node
    overall: float = 0.0
    # Number of listener-session reports that fed compute_scores. When 0,
    # entry_score is built on a neutral 0.5 fallback for protocol
    # reachability and overall is averaged over (exit, relay) only. Used
    # by CLI/dashboard to label the score as partial.
    listener_session_count: int = 0
    telegram_health: float = 0.0
    dns_integrity: float = 0.0
    tls_integrity: float = 0.0
    throttling_detected: bool = False
    recommended_protocols: list[str] = Field(default_factory=list)
    detected_techniques: list[str] = Field(default_factory=list)
