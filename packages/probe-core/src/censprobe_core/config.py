"""
config.py — Top-level censprobe configuration.

User-facing knobs live in ``censprobe.yaml`` at the workspace root.
This module loads the file once at startup, validates it via pydantic,
and exposes the result as a module-global. Modules read what they need
via ``get_config()``.

Defaults baked into the pydantic models match the historical hardcoded
values, so running without a ``censprobe.yaml`` is a no-op.

Reload is intentionally not supported: solo / listener / client are
short-lived processes; restart is the way.
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Vantage
# ─────────────────────────────────────────────────────────────────────────────

class VantageConfig(BaseModel):
    """Whitelist of country codes treated as 'censoring' vantages.

    RU-specific timing heuristics (TCP fast-RST attribution, QUIC drop
    attribution, Method-B throttling) are gated on this list — outside
    of it, the heuristics either downgrade to neutral verdicts or skip
    entirely to avoid false positives on uncensored networks.

    ``override`` forces a country code regardless of ipapi.is detection,
    useful for testing the heuristics or running from a tunnelled host
    whose ipapi-detected country differs from the network being tested.
    """
    model_config = ConfigDict(extra="forbid")
    censoring_countries: list[str] = Field(default_factory=lambda: ["RU", "BY"])
    override: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Per-module configuration
# ─────────────────────────────────────────────────────────────────────────────

class ModuleBase(BaseModel):
    """Common base for module configs — every module can be toggled on/off."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class DnsModuleConfig(ModuleBase):
    repeats: int = 3
    doh_resolvers: list[str] = Field(default_factory=lambda: [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://mozilla.cloudflare-dns.com/dns-query",
    ])
    doh_timeout_sec: float = 10.0
    asn_lookup_backoff_sec: float = 90.0


class TcpModuleConfig(ModuleBase):
    repeats: int = 3
    syn_timeout_sec: float = 5.0
    fast_rst_threshold_ms: int = 30
    max_parallel: int = 16


class TlsModuleConfig(ModuleBase):
    repeats: int = 2
    timeout_sec: float = 10.0
    max_parallel: int = 6


class HttpModuleConfig(ModuleBase):
    repeats: int = 3
    body_cap_bytes: int = 524_288
    timeout_connect_sec: float = 10.0
    timeout_read_sec: float = 30.0
    max_parallel: int = 8


class TelegramModuleConfig(ModuleBase):
    targets_file: str = "telegram"
    timeout_sec: float = 8.0


class ThrottlingModuleConfig(ModuleBase):
    """Method-B SNI throttling — TSPU-specific.

    ``require_censoring_vantage`` skips the test entirely when the
    vantage country isn't in :class:`VantageConfig.censoring_countries`,
    because off-vantage routing variance dominates and produces
    unreliable verdicts. Override the SNI strings if probing a different
    target than speedtest.selectel.ru.
    """
    require_censoring_vantage: bool = True
    target_url: str = "https://speedtest.selectel.ru/100MB"
    correct_sni: str = "speedtest.selectel.ru"
    typo_sni: str = "speedtset.selectel.ru"
    trigger_sni: str = "1-googlevideo.com"
    sequential_runs: int = 3
    bandwidth_ratio_threshold: float = 0.25
    curl_timeout_sec: float = 35.0


class CloudflareModuleConfig(ModuleBase):
    targets_file: str = "cloudflare"


class MiddleboxModuleConfig(ModuleBase):
    pass


class ModulesConfig(BaseModel):
    """Per-module knobs — disable, retune, point at custom YAMLs."""
    model_config = ConfigDict(extra="forbid")
    dns: DnsModuleConfig = Field(default_factory=DnsModuleConfig)
    tcp: TcpModuleConfig = Field(default_factory=TcpModuleConfig)
    tls: TlsModuleConfig = Field(default_factory=TlsModuleConfig)
    http: HttpModuleConfig = Field(default_factory=HttpModuleConfig)
    telegram: TelegramModuleConfig = Field(default_factory=TelegramModuleConfig)
    throttling: ThrottlingModuleConfig = Field(default_factory=ThrottlingModuleConfig)
    cloudflare: CloudflareModuleConfig = Field(default_factory=CloudflareModuleConfig)
    middlebox: MiddleboxModuleConfig = Field(default_factory=MiddleboxModuleConfig)


# ─────────────────────────────────────────────────────────────────────────────
# Protocols
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolsConfig(BaseModel):
    """Which VPN protocols to test in the listener+client phase.

    ``enabled`` is the operator-facing on/off list. Names not present
    in :data:`censprobe_core.protocol_registry.PROTOCOLS` are ignored
    with a warning, so a typo doesn't silently disable a real protocol.

    ``priority`` orders the recommendation list in scoring output —
    first protocol with verdict==OK wins. Same name policy as ``enabled``.
    """
    model_config = ConfigDict(extra="forbid")
    enabled: list[str] = Field(default_factory=lambda: [
        "openvpn", "wireguard", "amneziawg",
        "shadowsocks", "vless_reality", "hysteria2",
    ])
    priority: list[str] = Field(default_factory=lambda: [
        "vless_reality", "hysteria2", "amneziawg",
        "shadowsocks", "wireguard", "openvpn",
    ])


# ─────────────────────────────────────────────────────────────────────────────
# Throughput probe
# ─────────────────────────────────────────────────────────────────────────────

class ThroughputConfig(BaseModel):
    """Sustained-data probe parameters for SOCKS-routed protocols.

    Only SS / VLESS+Reality / Hysteria 2 use the SOCKS+echo-server data
    path; OpenVPN / WireGuard / AmneziaWG use a single ICMP ping and
    ignore these knobs.

    Tuning math:
        target_bytes / timeout_sec = floor of "throttled" detection.
        1 MiB / 30 s ≈ 280 kbps below which throughput_throttled fires.
    """
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    target_bytes: int = 1_048_576
    timeout_sec: float = 30.0


# ─────────────────────────────────────────────────────────────────────────────
# Score weights
# ─────────────────────────────────────────────────────────────────────────────

class EntryScoreWeights(BaseModel):
    """entry_score = protocol·W_p + uplink·W_u + latency·W_l (×100)."""
    model_config = ConfigDict(extra="forbid")
    protocol: float = 0.6
    uplink: float = 0.3
    latency: float = 0.1


class ExitScoreWeights(BaseModel):
    """exit_score = uplink·W_u + censorship·W_c (×100).

    The historical third axis (no_geoblock) was removed because it
    degenerated to a duplicated copy of uplink_quality. Until inbound
    geoblocking is measured for real, the exit score is two-axis.
    """
    model_config = ConfigDict(extra="forbid")
    uplink: float = 0.6
    censorship: float = 0.4


class RelayScoreWeights(BaseModel):
    """relay_score = tcp·W_t + latency·W_l (×100)."""
    model_config = ConfigDict(extra="forbid")
    tcp: float = 0.7
    latency: float = 0.3


class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entry: EntryScoreWeights = Field(default_factory=EntryScoreWeights)
    exit: ExitScoreWeights = Field(default_factory=ExitScoreWeights)
    relay: RelayScoreWeights = Field(default_factory=RelayScoreWeights)


# ─────────────────────────────────────────────────────────────────────────────
# Targets discovery
# ─────────────────────────────────────────────────────────────────────────────

class TargetsConfig(BaseModel):
    """Where to discover target YAMLs and how to filter them.

    By default every ``*.yaml`` under ``directory`` is auto-loaded.
    ``files`` (when non-empty) overrides that with an explicit list of
    basenames. ``module_owned`` lists files owned by specialised modules
    (telegram, cloudflare) — they are still loaded, but excluded from
    the generic-target view fed to dns/tcp/tls/http modules. Drop a new
    YAML into the targets directory and it picks up on the next run.
    """
    model_config = ConfigDict(extra="forbid")
    directory: str = "targets"
    files: list[str] = Field(default_factory=list)
    module_owned: list[str] = Field(default_factory=lambda: ["telegram", "cloudflare"])


# ─────────────────────────────────────────────────────────────────────────────
# Top-level
# ─────────────────────────────────────────────────────────────────────────────

class CensprobeConfig(BaseModel):
    """Root configuration object.

    extra="ignore" (rather than "forbid") so a future version that adds
    a new top-level section doesn't crash older deployments — they'll
    just see the missing fields as their defaults.
    """
    model_config = ConfigDict(extra="ignore")

    vantage: VantageConfig = Field(default_factory=VantageConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    protocols: ProtocolsConfig = Field(default_factory=ProtocolsConfig)
    throughput: ThroughputConfig = Field(default_factory=ThroughputConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    targets: TargetsConfig = Field(default_factory=TargetsConfig)


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

_CONFIG: CensprobeConfig | None = None
CONFIG_FILENAME = "censprobe.yaml"


def load_config(workspace: Path) -> CensprobeConfig:
    """Load ``workspace/censprobe.yaml``; fall back to all-defaults if absent.

    A missing file is the normal case for a fresh checkout — we log
    once and move on with defaults. A *malformed* file (invalid YAML,
    type mismatch on a required field) raises ``ValueError`` so the
    operator sees the problem at startup rather than getting silent
    fallback to defaults that mask the misconfiguration.
    """
    global _CONFIG
    cfg_path = workspace / CONFIG_FILENAME
    if not cfg_path.exists():
        logger.info("No %s at %s; using defaults", CONFIG_FILENAME, workspace)
        _CONFIG = CensprobeConfig()
        return _CONFIG

    try:
        text = cfg_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"Could not read {cfg_path}: {e}") from e

    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {cfg_path}: {e}") from e

    if not isinstance(raw, dict):
        raise ValueError(
            f"{cfg_path} must be a YAML mapping at the top level "
            f"(got {type(raw).__name__})"
        )

    try:
        _CONFIG = CensprobeConfig.model_validate(raw)
    except Exception as e:
        # Pydantic ValidationError formatting is verbose; re-raise as a
        # plain ValueError with the rendered detail so the operator
        # sees a single readable line in the rich console.
        raise ValueError(f"Invalid {CONFIG_FILENAME}: {e}") from e

    logger.info("Loaded %s", cfg_path)
    return _CONFIG


def get_config() -> CensprobeConfig:
    """Return the loaded config, or a defaults instance if not loaded."""
    if _CONFIG is None:
        return CensprobeConfig()
    return _CONFIG


def set_config(config: CensprobeConfig) -> None:
    """Override the active config — primarily for tests."""
    global _CONFIG
    _CONFIG = config


def reset_config() -> None:
    """Drop the loaded config — primarily for tests."""
    global _CONFIG
    _CONFIG = None
