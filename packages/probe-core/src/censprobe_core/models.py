"""
Pydantic data models for Censprobe.

Covers:
- Verdict and BlockingMethod enums
- TestResult — single test outcome
- BaselineData — structure of baseline/latest.json
- ReportMeta — reports/<test_id>/meta.yaml
- ServerMeta — auto-detected server metadata
- ListenerReport — output of censprobe-listener
- ProtocolResult — single VPN protocol handshake outcome
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional
from pydantic import BaseModel, Field, PrivateAttr


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class Verdict(StrEnum):
    """Top-level verdict for a single test."""
    OK = "OK"
    BLOCKED = "BLOCKED"
    THROTTLED = "THROTTLED"
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
    # Throttling-specific
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
    BLOCKPAGE_RETURNED = "blockpage_returned"
    BANDWIDTH_THROTTLING = "bandwidth_throttling"
    SNI_THROTTLING = "sni_throttling"
    QUIC_DROPPED = "quic_dropped"
    OPENVPN_SIGNATURE_BLOCKED = "openvpn_signature_blocked"
    WIREGUARD_SIGNATURE_BLOCKED = "wireguard_signature_blocked"
    SHADOWSOCKS_ACTIVE_PROBED = "shadowsocks_active_probed"
    VPN_DATA_PHASE_BLOCKED = "vpn_data_phase_blocked"
    MIDDLEBOX_HTTP_MANIPULATION = "middlebox_http_manipulation"
    UNKNOWN = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Core result model
# ─────────────────────────────────────────────────────────────────────────────

class ControlComparison(BaseModel):
    """Comparison with baseline/control results."""
    control_verdict: Optional[Verdict] = None
    control_rtt_ms: Optional[float] = None
    baseline_version: Optional[str] = None


class TestResult(BaseModel):
    """Single test result — one measurement of one target."""
    test: str = Field(description="Test name, e.g. 'dns_meduza_io_system'")
    category: str = Field(description="Module category: dns|tcp|tls|http|telegram|throttling|protocols|middlebox")
    target: str = Field(description="Target URL, domain, or IP:port")
    verdict: Verdict
    method: Optional[BlockingMethod] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    rtt_ms: Optional[float] = None
    attempts: int = 1
    control_comparison: Optional[ControlComparison] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Baseline models
# ─────────────────────────────────────────────────────────────────────────────

class BaselineDnsEntry(BaseModel):
    a_records_asn: list[str] = Field(default_factory=list)
    aaaa_records_asn: list[str] = Field(default_factory=list)
    observed_ips_v4: list[str] = Field(default_factory=list)
    ttl_range: list[int] = Field(default_factory=lambda: [60, 300])


class BaselineTlsEntry(BaseModel):
    cert_chain_sha256: list[str] = Field(default_factory=list)
    cert_subject_cn: Optional[str] = None
    cert_issuer_cn: Optional[str] = None
    ja4_server: Optional[str] = None
    alpn: list[str] = Field(default_factory=list)


class BaselineHttpEntry(BaseModel):
    status: int = 200
    title_regex: Optional[str] = None
    body_length_range: list[int] = Field(default_factory=lambda: [0, 999999999])
    stable_fragments_sha256: dict[str, str] = Field(default_factory=dict)


class BaselineTelegramEntry(BaseModel):
    reachable: bool = True
    rtt_range_ms: list[float] = Field(default_factory=lambda: [0.0, 9999.0])


class BaselineThrottlingEntry(BaseModel):
    bandwidth_mbps_p50: float = 0.0
    bandwidth_mbps_p10: float = 0.0
    ttfb_ms_p50: float = 0.0


class BaselineSniThrottlingRun(BaseModel):
    sni: str
    bandwidth_mbps_p50: float = 0.0
    drop_pattern: str = "none"  # none | burst_then_drop


class BaselineSniThrottling(BaseModel):
    target_ip_host: str = "speedtest.selectel.ru"
    runs: dict[str, BaselineSniThrottlingRun] = Field(default_factory=dict)


class BaselineControlPoint(BaseModel):
    control_id: str
    asn: str
    country: str
    city: str
    ipv6_available: bool = True


class BaselineData(BaseModel):
    """Structure of baseline/latest.json — generated by control container."""
    version: str = "stub-0.0.0"
    generated_at: Optional[datetime] = None
    generated_from: Optional[BaselineControlPoint] = None
    probe_core_version: str = "0.1.0"
    targets_version: str = "initial"
    validity_until: Optional[datetime] = None
    runs_count: int = 0
    dns: dict[str, BaselineDnsEntry] = Field(default_factory=dict)
    tls: dict[str, BaselineTlsEntry] = Field(default_factory=dict)
    http: dict[str, BaselineHttpEntry] = Field(default_factory=dict)
    telegram: dict[str, BaselineTelegramEntry] = Field(default_factory=dict)
    throttling: dict[str, BaselineThrottlingEntry] = Field(default_factory=dict)
    sni_throttling: Optional[BaselineSniThrottling] = None

    def is_stub(self) -> bool:
        return self.generated_at is None or self.runs_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# Server & report metadata
# ─────────────────────────────────────────────────────────────────────────────

class ServerMeta(BaseModel):
    """Auto-detected metadata about the probe server."""
    provider: Optional[str] = None
    location: Optional[str] = None
    asn: Optional[str] = None
    as_name: Optional[str] = None
    ipv4_masked: Optional[str] = None   # masked to /24
    ipv6_available: bool = False
    plan: Optional[str] = None
    kernel: Optional[str] = None
    distro: Optional[str] = None
    # Raw detected values (not stored in git)
    _exit_ip: Optional[str] = PrivateAttr(default=None)


class ReportMeta(BaseModel):
    """Structure of reports/<test_id>/meta.yaml"""
    test_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: Optional[str] = None
    server: ServerMeta = Field(default_factory=ServerMeta)
    purpose: str = "vpn-entry"   # vpn-entry | vpn-exit | vpn-relay
    planned_sessions: list[str] = Field(default_factory=list)
    probe_core_version: str = "0.1.0"
    baseline_version: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Listener / Protocol models
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolPhase(StrEnum):
    HANDSHAKE = "handshake"
    DATA_ECHO = "data_echo"


class ProtocolEvent(BaseModel):
    """Single protocol handshake/data event logged by listener."""
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    protocol: str
    phase: ProtocolPhase
    from_asn: Optional[str] = None
    duration_ms: Optional[float] = None
    bytes: Optional[int] = None
    success: bool = True
    notes: Optional[str] = None


class ProtocolResult(BaseModel):
    """Aggregated result for one protocol in a listener session."""
    verdict: Verdict = Verdict.BLOCKED
    handshake_count: int = 0
    data_transfer_ok: bool = False
    first_handshake_at: Optional[datetime] = None
    avg_rtt_ms: Optional[float] = None
    avg_data_echo_ms: Optional[float] = None
    from_asn: Optional[str] = None
    note: Optional[str] = None

    def finalize(self) -> None:
        """Set verdict based on counts."""
        if self.handshake_count > 0 and self.data_transfer_ok:
            self.verdict = Verdict.OK
        elif self.handshake_count > 0 and not self.data_transfer_ok:
            self.verdict = Verdict.HANDSHAKE_ONLY
        else:
            self.verdict = Verdict.BLOCKED


class ListenerReport(BaseModel):
    """Output of censprobe-listener — reports/<test_id>/server-listener-<session>-<ts>.json.gz"""
    test_id: str
    session_id: str
    listener_started_at: datetime
    listener_stopped_at: Optional[datetime] = None
    duration_sec: Optional[float] = None
    results: dict[str, ProtocolResult] = Field(default_factory=dict)
    events: list[ProtocolEvent] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Scores
# ─────────────────────────────────────────────────────────────────────────────

class ServerScores(BaseModel):
    """Computed suitability scores for a server."""
    entry_score: float = 0.0   # As VPN entry
    exit_score: float = 0.0    # As VPN exit
    relay_score: float = 0.0   # As relay node
    overall: float = 0.0
    telegram_health: float = 0.0
    dns_integrity: float = 0.0
    tls_integrity: float = 0.0
    throttling_detected: bool = False
    recommended_protocols: list[str] = Field(default_factory=list)
    detected_techniques: list[str] = Field(default_factory=list)
