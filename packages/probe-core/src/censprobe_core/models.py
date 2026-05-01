"""
Pydantic data models for Censprobe.

Covers:
- Verdict and BlockingMethod enums
- TestResult — single test outcome
- ReportMeta — reports/<test_id>/meta.yaml
- ServerMeta — auto-detected server metadata
- ListenerReport — output of censprobe-listener
- ProtocolResult — single VPN protocol handshake outcome
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, PrivateAttr


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Core result model
# ─────────────────────────────────────────────────────────────────────────────

class TestResult(BaseModel):
    """Single test result — one measurement of one target."""
    test: str = Field(description="Test name, e.g. 'dns_meduza_io_system'")
    category: str = Field(description="Module category: dns|tcp|tls|http|telegram|throttling|protocols|middlebox")
    target: str = Field(description="Target URL, domain, or IP:port")
    verdict: Verdict
    method: BlockingMethod | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    rtt_ms: float | None = None
    attempts: int = 1
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Server & report metadata
# ─────────────────────────────────────────────────────────────────────────────

class ServerMeta(BaseModel):
    """Auto-detected metadata about the probe server."""
    provider: str | None = None
    location: str | None = None
    country: str | None = None       # ISO-3166 alpha-2, e.g. "DE"
    asn: str | None = None
    as_name: str | None = None
    ipv4: str | None = None
    ipv6_available: bool = False
    plan: str | None = None
    kernel: str | None = None
    distro: str | None = None
    # Raw detected values (not stored in git)
    _exit_ip: str | None = PrivateAttr(default=None)


class ReportMeta(BaseModel):
    """Structure of reports/<test_id>/meta.yaml"""
    test_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str | None = None
    server: ServerMeta = Field(default_factory=ServerMeta)
    purpose: str = "vpn-entry"   # vpn-entry | vpn-exit | vpn-relay
    planned_sessions: list[str] = Field(default_factory=list)
    probe_core_version: str = "0.1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Listener / Protocol models
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolResult(BaseModel):
    """Aggregated result for one protocol in a listener session."""
    verdict: Verdict = Verdict.BLOCKED
    handshake_count: int = 0
    data_transfer_ok: bool = False
    first_handshake_at: datetime | None = None
    avg_rtt_ms: float | None = None
    avg_data_echo_ms: float | None = None
    from_asn: str | None = None
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
    """Output of censprobe-listener — reports/<test_id>/server-listener-<session>-<ts>.json"""
    test_id: str
    session_id: str
    listener_started_at: datetime
    listener_stopped_at: datetime | None = None
    duration_sec: float | None = None
    results: dict[str, ProtocolResult] = Field(default_factory=dict)


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
