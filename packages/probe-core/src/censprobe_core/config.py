"""
config.py — Top-level censprobe configuration.

User-facing knobs live in ``censprobe.yaml`` at the workspace root.
This module loads the file once at startup, validates it via pydantic,
and exposes the result as a module-global. Modules read what they need
via ``get_config()``.

censprobe.yaml is REQUIRED and must be fully populated. There are no
fallback defaults anywhere — if a field is missing, pydantic raises a
``ValidationError`` at startup and the operator sees exactly which key
needs to be added. This is by design: the config file is the single
source of truth for every runtime knob, and its content must always
reflect the exact current state of the project.

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
    censoring_countries: list[str]
    override: str | None


# ─────────────────────────────────────────────────────────────────────────────
# Per-module configuration
# ─────────────────────────────────────────────────────────────────────────────

class ModuleBase(BaseModel):
    """Common base for module configs — every module must have an explicit
    ``enabled`` flag in censprobe.yaml."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class DnsModuleConfig(ModuleBase):
    repeats: int
    doh_resolvers: list[str]
    doh_timeout_sec: float
    asn_lookup_backoff_sec: float


class TcpModuleConfig(ModuleBase):
    repeats: int
    syn_timeout_sec: float
    fast_rst_threshold_ms: int
    max_parallel: int


class TlsModuleConfig(ModuleBase):
    repeats: int
    timeout_sec: float
    max_parallel: int


class HttpModuleConfig(ModuleBase):
    repeats: int
    body_cap_bytes: int
    timeout_connect_sec: float
    timeout_read_sec: float
    max_parallel: int


class TelegramModuleConfig(ModuleBase):
    targets_file: str
    timeout_sec: float


class ThrottlingModuleConfig(ModuleBase):
    """Method-B SNI throttling — TSPU-specific.

    ``require_censoring_vantage`` skips the test entirely when the
    vantage country isn't in :class:`VantageConfig.censoring_countries`,
    because off-vantage routing variance dominates and produces
    unreliable verdicts. Override the SNI strings if probing a different
    target than speedtest.selectel.ru.
    """
    require_censoring_vantage: bool
    target_url: str
    correct_sni: str
    typo_sni: str
    trigger_sni: str
    sequential_runs: int
    bandwidth_ratio_threshold: float
    curl_timeout_sec: float


class CloudflareModuleConfig(ModuleBase):
    targets_file: str


class MiddleboxModuleConfig(ModuleBase):
    pass


class ModulesConfig(BaseModel):
    """Per-module knobs — every module must be explicitly configured."""
    model_config = ConfigDict(extra="forbid")
    dns: DnsModuleConfig
    tcp: TcpModuleConfig
    tls: TlsModuleConfig
    http: HttpModuleConfig
    telegram: TelegramModuleConfig
    throttling: ThrottlingModuleConfig
    cloudflare: CloudflareModuleConfig
    middlebox: MiddleboxModuleConfig


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
    enabled: list[str]
    priority: list[str]


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
    enabled: bool
    target_bytes: int
    timeout_sec: float


# ─────────────────────────────────────────────────────────────────────────────
# Score weights
# ─────────────────────────────────────────────────────────────────────────────

class EntryScoreWeights(BaseModel):
    """entry_score = protocol·W_p + uplink·W_u + latency·W_l (×100)."""
    model_config = ConfigDict(extra="forbid")
    protocol: float
    uplink: float
    latency: float


class ExitScoreWeights(BaseModel):
    """exit_score = uplink·W_u + censorship·W_c (×100).

    The historical third axis (no_geoblock) was removed because it
    degenerated to a duplicated copy of uplink_quality. Until inbound
    geoblocking is measured for real, the exit score is two-axis.
    """
    model_config = ConfigDict(extra="forbid")
    uplink: float
    censorship: float


class RelayScoreWeights(BaseModel):
    """relay_score = tcp·W_t + latency·W_l (×100)."""
    model_config = ConfigDict(extra="forbid")
    tcp: float
    latency: float


class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entry: EntryScoreWeights
    exit: ExitScoreWeights
    relay: RelayScoreWeights


# ─────────────────────────────────────────────────────────────────────────────
# Targets discovery
# ─────────────────────────────────────────────────────────────────────────────

class TargetsConfig(BaseModel):
    """Where to discover target YAMLs and how to filter them.

    When ``files`` is empty, every ``*.yaml`` under ``directory`` is
    auto-loaded. When non-empty, only the listed basenames are loaded.
    ``module_owned`` lists files owned by specialised modules
    (telegram, cloudflare) — they are still loaded, but excluded from
    the generic-target view fed to dns/tcp/tls/http modules. Drop a new
    YAML into the targets directory and it picks up on the next run.
    """
    model_config = ConfigDict(extra="forbid")
    directory: str
    files: list[str]
    module_owned: list[str]


# ─────────────────────────────────────────────────────────────────────────────
# Top-level
# ─────────────────────────────────────────────────────────────────────────────

class CensprobeConfig(BaseModel):
    """Root configuration object.

    Every section is required — censprobe.yaml must be fully populated.
    extra="ignore" (rather than "forbid") so a future version that adds
    a new top-level section doesn't crash older deployments — they'll
    just ignore the unknown section while still requiring all known ones.
    """
    model_config = ConfigDict(extra="ignore")

    vantage: VantageConfig
    modules: ModulesConfig
    protocols: ProtocolsConfig
    throughput: ThroughputConfig
    scoring: ScoringConfig
    targets: TargetsConfig


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

_CONFIG: CensprobeConfig | None = None
CONFIG_FILENAME = "censprobe.yaml"


def load_config(workspace: Path) -> CensprobeConfig:
    """Load ``workspace/censprobe.yaml``.

    The config file is required and must contain all fields. A missing
    file, a malformed file, or a file with missing fields all raise
    ``ValueError`` — the operator sees the problem at startup rather
    than getting a silent fallback that masks the misconfiguration.
    """
    global _CONFIG
    cfg_path = workspace / CONFIG_FILENAME
    if not cfg_path.exists():
        raise ValueError(
            f"{CONFIG_FILENAME} not found at {workspace}. "
            f"The config file is required — no fallback defaults. "
            f"Create {cfg_path} with all required fields."
        )

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
    """Return the loaded config; raises if not loaded yet.

    Every entry point (solo, listener, client) must call
    ``load_config(workspace)`` at startup before any module accesses
    the config. A missing call is a programming error, not a recoverable
    state — hence RuntimeError.
    """
    if _CONFIG is None:
        raise RuntimeError(
            "Config not loaded. Call load_config(workspace) at startup "
            "before accessing config."
        )
    return _CONFIG


def set_config(config: CensprobeConfig) -> None:
    """Override the active config — primarily for tests."""
    global _CONFIG
    _CONFIG = config


def reset_config() -> None:
    """Drop the loaded config — primarily for tests."""
    global _CONFIG
    _CONFIG = None
