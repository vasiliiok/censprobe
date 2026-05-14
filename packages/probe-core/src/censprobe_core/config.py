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
import re
from pathlib import Path
from typing import ClassVar

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

logger = logging.getLogger(__name__)


# Vantage


_ISO_3166_ALPHA2_RE = re.compile(r"^[A-Z]{2}$")


class VantageConfig(BaseModel):
    """Whitelist of country codes treated as 'censoring' vantages.

    Censoring-vantage timing heuristics (TCP fast-RST attribution, QUIC drop
    attribution, Method-B throttling) are gated on this list — outside
    of it, the heuristics either downgrade to neutral verdicts or skip
    entirely to avoid false positives on uncensored networks.

    ``override`` forces a country code regardless of ipapi.is detection,
    useful for testing the heuristics or running from a tunnelled host
    whose ipapi-detected country differs from the network being tested.

    Country codes must be ISO-3166 alpha-2 uppercase (``RU``, ``BY``,
    ``IR``, ``CN``, ``KZ``). The validator rejects ``Ru`` / ``RUS``-style
    typos at startup; without it, ``is_censoring_vantage()`` would silently
    miss the match and disable the heuristics.
    """

    model_config = ConfigDict(extra="forbid")
    censoring_countries: list[str]
    override: str | None

    @field_validator("censoring_countries", mode="after")
    @classmethod
    def _check_country_codes(cls, v: list[str]) -> list[str]:
        bad = [cc for cc in v if not _ISO_3166_ALPHA2_RE.match(cc)]
        if bad:
            raise ValueError(
                f"censoring_countries must be ISO-3166 alpha-2 uppercase "
                f"(e.g. 'RU', 'BY'); offenders: {bad}"
            )
        return v

    @field_validator("override", mode="after")
    @classmethod
    def _check_override_code(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _ISO_3166_ALPHA2_RE.match(v):
            raise ValueError(
                f"vantage.override must be ISO-3166 alpha-2 uppercase or null "
                f"(e.g. 'RU'); got {v!r}"
            )
        return v


# Per-module configuration


class ModuleBase(BaseModel):
    """Common base for module configs — every module must have an explicit
    ``enabled`` flag in censprobe.yaml."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool


class DnsModuleConfig(ModuleBase):
    # NOTE: there is no ``repeats`` field. DNS attribution is verified via
    # the multi-resolver ladder (system + ISP + 4 public + 3 DoH + 2 DoT) —
    # the cross-check IS the retry surface, single-record repeats add no
    # signal. The field used to live here but was wired up to nothing
    # downstream (run_dns_tests dropped the parameter on the floor); the
    # 2026-05-14 audit removed it to stop pretending the knob did anything.
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
    """Method-B SNI throttling — robust on every vantage.

    ``require_censoring_vantage`` is opt-in (default false in
    censprobe.yaml). Method B uses a within-run **relative** bandwidth
    ratio across three SNIs on the same uplink, so it self-calibrates
    against geographic latency and link width. Off-vantage you get
    ratio ≈ 1.0 → OK (baseline-confirmed); on TSPU paths the trigger
    SNI drops → THROTTLED. Set this flag to true only if you have
    explicit reason to skip non-censoring vantages. Override the SNI
    strings if probing a different target than speedtest.selectel.ru.
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


# Middlebox has no knobs beyond ``enabled``. We type the slot directly as
# ModuleBase rather than declaring an empty ``class MiddleboxModuleConfig:
# pass`` stub — that stub added a layer with zero behaviour. If middlebox
# ever grows tunables, the type below is the natural place to split it
# back out.


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
    middlebox: ModuleBase


# Protocols


class ProtocolsConfig(BaseModel):
    """Which VPN protocols to test in the listener+client phase.

    ``enabled`` is the operator-facing on/off list. Names not present
    in :data:`censprobe_core.protocol_registry.PROTOCOLS` are ignored
    with a warning, so a typo doesn't silently disable a real protocol.

    ``priority`` orders the recommendation list in scoring output —
    first protocol with verdict==OK wins. Same name policy as ``enabled``.

    ``ports`` is the per-protocol bind port the listener uses. Every
    protocol in ``enabled`` MUST have a corresponding entry — a missing
    key is a fatal validation error, not a fallback. Unknown protocol
    names in ``ports`` are also rejected so a typo can't silently route
    a port to nowhere.

    ``sni`` is the per-protocol SNI / server-name string for protocols
    that mimic an HTTPS handshake (VLESS+Reality, the two MTProto-proxy
    siblings). Same coverage rule as ``ports`` — every enabled
    SNI-using protocol needs an entry; entries for protocols that
    don't use SNI (OpenVPN/WG/AWG/Shadowsocks/Hysteria 2) are
    rejected. Lets the operator A/B different SNIs per port without
    code changes — the obvious use case is checking whether a TSPU
    block is keyed on the SNI string vs the underlying fakeTLS
    fingerprint.
    """

    # Protocols whose responder + probe accept an operator-supplied
    # SNI / server-name. Kept here (not in the registry) because the
    # registry is meant to be a pure-data module without config-shape
    # imports; this list is the authoritative source for the SNI
    # validator below.
    _SNI_USING_PROTOCOLS: ClassVar[frozenset[str]] = frozenset(
        {"vless_reality", "mtproto_proxy", "mtproto_proxy_alt"}
    )

    model_config = ConfigDict(extra="forbid")
    enabled: list[str]
    priority: list[str]
    ports: dict[str, int]
    sni: dict[str, str]

    @model_validator(mode="after")
    def _check_ports_cover_enabled(self) -> ProtocolsConfig:
        # Cross-check against the protocol registry. Done via a late
        # import to avoid the module-load cycle (config <-> registry):
        # protocol_registry imports nothing from config today, but the
        # local import keeps the contract explicit for future authors.
        # A typo in enabled/priority would otherwise silently disappear
        # at runtime (enabled_protocols() drops unknowns), so we surface
        # it here at startup with the offending names.
        from censprobe_core.protocol_registry import known_names

        known = set(known_names())
        unknown_enabled = [name for name in self.enabled if name not in known]
        if unknown_enabled:
            raise ValueError(
                f"protocols.enabled references protocols unknown to the "
                f"registry: {unknown_enabled}. Known: {sorted(known)}. "
                f"Fix the typo or add a ProtocolSpec entry."
            )
        unknown_priority = [name for name in self.priority if name not in known]
        if unknown_priority:
            raise ValueError(
                f"protocols.priority references protocols unknown to the "
                f"registry: {unknown_priority}. Known: {sorted(known)}."
            )

        # Cross-check ``ports`` against ``enabled`` so a half-edited yaml
        # (operator added a protocol to ``enabled`` but forgot to give it
        # a port) fails loudly at startup.
        missing = [name for name in self.enabled if name not in self.ports]
        if missing:
            raise ValueError(
                f"protocols.ports missing entries for enabled protocols: "
                f"{missing}. Every protocol in protocols.enabled must have "
                f"a port in protocols.ports — no fallback defaults exist."
            )
        # Reject port entries for protocols unknown to the registry —
        # caught here in addition to the enabled/priority check above
        # so a phantom ``ports:`` entry (typo'd protocol name) also
        # fails loudly. Combined with the registry cross-check above,
        # every protocols.* dict is now guaranteed to reference only
        # real protocols.
        unknown_ports = [name for name in self.ports if name not in known]
        if unknown_ports:
            raise ValueError(
                f"protocols.ports references protocols unknown to the "
                f"registry: {unknown_ports}. Known: {sorted(known)}."
            )
        bad_ports = [(name, p) for name, p in self.ports.items() if not (1 <= p <= 65535)]
        if bad_ports:
            raise ValueError(
                f"protocols.ports contains invalid port numbers (must be 1..65535): {bad_ports}"
            )

        # SNI map: only the protocols that mimic an HTTPS handshake
        # (vless_reality, mtproto_proxy*) accept an operator-supplied
        # SNI. Every such protocol that is also in ``enabled`` MUST
        # have an entry. An entry for a protocol that *doesn't* use
        # SNI (openvpn, wg, awg, shadowsocks, hysteria2) is rejected
        # as a config typo — letting it slide would silently accept
        # ``sni: { openvpn: ... }`` without affecting anything, which
        # is exactly the kind of "appears to work, doesn't" config
        # this validator exists to prevent.
        sni_required = self._SNI_USING_PROTOCOLS & set(self.enabled)
        sni_missing = [name for name in sorted(sni_required) if name not in self.sni]
        if sni_missing:
            raise ValueError(
                f"protocols.sni missing entries for enabled SNI-using "
                f"protocols: {sni_missing}. Every enabled protocol in "
                f"{sorted(self._SNI_USING_PROTOCOLS)} must have a string "
                f"in protocols.sni — no fallback defaults exist."
            )
        sni_orphan = [name for name in self.sni if name not in self._SNI_USING_PROTOCOLS]
        if sni_orphan:
            raise ValueError(
                f"protocols.sni contains entries for non-SNI-using "
                f"protocols: {sni_orphan}. SNI applies only to "
                f"{sorted(self._SNI_USING_PROTOCOLS)} — remove the entry."
            )
        bad_sni = [(name, v) for name, v in self.sni.items() if not v or not isinstance(v, str)]
        if bad_sni:
            raise ValueError(f"protocols.sni contains empty or non-string values: {bad_sni}")
        return self


# Throughput probe


class ThroughputConfig(BaseModel):
    """Sustained-data probe parameters for SOCKS-routed protocols.

    Only SS / VLESS+Reality / Hysteria 2 use the SOCKS+echo-server data
    path; OpenVPN / WireGuard / AmneziaWG use a single ICMP ping and
    ignore these knobs.

    Tuning math:
        target_bytes / timeout_sec = floor of "throttled" detection.
        8 MiB / 30 s ≈ 2.2 Mbps below which throughput_throttled fires.
        Bumped from 1 MiB after 100-500 Mbps cloud-to-cloud runs
        consistently collapsed listener-side measurement to <10 ms
        kernel-buffer-absorption windows.
    """

    model_config = ConfigDict(extra="forbid")
    enabled: bool
    target_bytes: int
    timeout_sec: float


# Score weights


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


# Targets discovery


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


# Top-level


class CensprobeConfig(BaseModel):
    """Root configuration object.

    Every section is required — censprobe.yaml must be fully populated.
    ``extra="forbid"`` matches the per-section sub-models so a typo'd
    top-level key (e.g. ``module:`` instead of ``modules:``) fails with
    a clear "extra fields not permitted" error rather than silently
    being ignored while the real ``modules:`` is absent and triggers a
    less actionable "field required" error. The previous ``extra="ignore"``
    was meant to leave room for future top-level sections; that's
    a soft trade-off the project's "fail loud on misconfiguration"
    invariant resolves in favour of strictness. When a new section is
    added later, the config schema bump is the natural surface to
    advertise it.
    """

    model_config = ConfigDict(extra="forbid")

    vantage: VantageConfig
    modules: ModulesConfig
    protocols: ProtocolsConfig
    throughput: ThroughputConfig
    scoring: ScoringConfig
    targets: TargetsConfig


# Loader

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
            f"{cfg_path} must be a YAML mapping at the top level (got {type(raw).__name__})"
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
            "Config not loaded. Call load_config(workspace) at startup before accessing config."
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
