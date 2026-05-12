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

    `is_datacenter` flags whether the source IP belongs to a hosting
    provider per ipapi.is. It used to be treated as "almost certainly
    behind a self-hosted VPN", but that turned out to over-trigger:
    public-WiFi gateways, mobile-carrier NAT pools and reseller blocks
    are routinely mis-classified as datacenter. We still record the
    flag for visibility but do NOT infer VPN/test-validity from it.

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
    server: ServerMeta = Field(default_factory=ServerMeta)
    planned_sessions: list[str] = Field(default_factory=list)
    probe_core_version: str = "0.1.0"


# Listener / Protocol models


class LiveSnapshot(BaseModel):
    """Live per-protocol counter snapshot served by the listener's
    cred-server ``/snapshot`` endpoint mid-session.

    The client probe fetches one of these after its own probes finish
    so it can render an "agreed verdict" — counter values are the
    listener's authoritative ground truth, while the client's pass/fail
    is the *probe-side* observation. When the two agree the verdict is
    trustworthy; when they disagree the disagreement itself is the
    interesting signal (e.g. Windows Docker Desktop spoofing ICMP/UDP
    replies for a tunnel that never reached the listener).

    Fields are deliberately the same shape as :class:`ProtocolResult`
    (handshake_count + data_transfer_ok) so the client can apply the
    SAME ``finalize()`` logic to derive the listener's verdict from a
    snapshot. The data-phase counter (data_packets / rx_bytes) is
    surfaced as a non-authoritative diagnostic for operators who want
    to see the underlying tick rate.
    """

    handshake_count: int = 0
    data_transfer_ok: bool = False
    # Diagnostic only — exposes the underlying counter so operators
    # can see "how close was it to flipping". None when the responder
    # has no per-protocol data-counter (mostly the SOCKS-routed
    # families, which signal data-phase via the echo server).
    data_packets: int | None = None
    # Subprotocol-flavoured diagnostic. For OpenVPN this is "Auth read
    # bytes" from the status file; for WG/AWG it's the kernel's
    # ``peer->rx_bytes`` counter. Independent of ``data_packets``.
    bytes_received: int | None = None
    # Mirror of :attr:`ProtocolResult.responder_self_test_ok` so the
    # client-side cross-verification table can apply the SAME BLOCKED→
    # ERROR downgrade the listener will write into the final report.
    # Without this, the client would still print BLOCKED in its
    # cross-verification panel even though the listener report
    # downgraded the same protocol to ERROR, confusing operators about
    # which signal to trust. The listener injects this value into the
    # snapshot dict at commit time (``main.py`` ``commit_final_snapshots``)
    # — the per-responder ``live_snapshot()`` methods don't carry it
    # so a fleet of responders doesn't have to learn a new field.
    responder_self_test_ok: bool | None = None


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
    avg_throughput_mbps: float | None = None
    throughput_throttled: bool = False
    note: str | None = None
    # Result of the listener-side startup self-test (loopback probe of
    # the just-started responder). ``None`` when no self-test was
    # configured for this protocol (most have none — only mtproto_orig
    # ships one currently, because its C upstream-relayed handshake is
    # the only failure mode where the responder can be silently wedged
    # at the application layer in a way that mimics DPI silent-drop).
    # ``False`` means the responder couldn't complete its own handshake
    # against itself, so any later session-time BLOCKED for this
    # protocol is NOT trustworthy as a censorship signal — preserving
    # the "BLOCKED ≡ confirmed block" invariant requires downgrading
    # such a verdict (see finalize()).
    responder_self_test_ok: bool | None = None

    def finalize(self) -> None:
        """Derive verdict from the two responder signals.

        ``data_transfer_ok`` wins over ``handshake_count`` because it is the
        cryptographically/kernel-verified evidence — bytes only arrive at the
        listener's echo-server, only show up in the ``wg show transfer``
        rx_bytes counter, and only tick the OpenVPN/mtg iptables PSH+ACK
        counter once a successful handshake has completed. ``handshake_count``,
        on the other hand, is derived for the SOCKS-routed family
        (shadowsocks/vless_reality/hysteria2) and for ``mtproto_proxy`` from
        substring matches against the foreign binary's stdout, which drifts
        across xray/sing-box/hysteria/mtg releases. When the log-line
        marker is missed but real data flowed, treating data as the source
        of truth keeps the verdict aligned with the client's experience
        instead of collapsing to a false ``BLOCKED``.

        WG/AWG read both signals off the same ``wg show`` snapshot, OpenVPN
        AND-gates ``data_transfer_ok`` against ``handshake_count > 0`` for
        scanner-resistance, and ``mtproto_orig`` derives ``data_transfer_ok``
        from ``connection_count > 0`` outright — so for those protocols the
        ``data_transfer_ok=True, handshake_count=0`` case is by construction
        impossible and this change is a no-op.
        """
        if self.data_transfer_ok:
            self.verdict = Verdict.OK
        elif self.handshake_count > 0:
            self.verdict = Verdict.HANDSHAKE_ONLY
        else:
            self.verdict = Verdict.BLOCKED

        # Listener-side self-test downgrade. If the responder couldn't
        # complete a probe against itself at startup, a session-time
        # BLOCKED for this protocol cannot be distinguished from a real
        # network block — and the strict "BLOCKED ≡ confirmed block"
        # invariant forbids reporting one. Reclassify to ERROR with a
        # diagnostic note so cross-verification surfaces it as
        # "listener-side, not network" rather than censorship.
        if (
            self.responder_self_test_ok is False
            and self.verdict == Verdict.BLOCKED
            and self.handshake_count == 0
            and not self.data_transfer_ok
        ):
            self.verdict = Verdict.ERROR
            self.note = (
                "listener-side responder self-test failed at startup — "
                "this BLOCKED-shape result is not a confirmed network block "
                "(the listener's own loopback probe could not complete the "
                "responder handshake either)"
            )


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
    # Operator-supplied network-context flags (listener CLI ``--mobile``
    # / ``--white``). Surfaced as first-class Grafana filter dimensions
    # so a 96-test campaign across multiple companies × zones × client
    # networks can be sliced by network type without parsing session_id
    # strings. Default False keeps older reports (and tests that don't
    # pass the flag) on the "regular" axis.
    is_mobile: bool = False
    is_whitelist: bool = False
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
