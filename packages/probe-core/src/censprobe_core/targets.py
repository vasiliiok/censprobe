"""
targets.py — Pydantic models and auto-discovery for targets/*.yaml.

The runner used to keep a hard-coded list of target file basenames
(news / social / messengers / vpn / neutral). This module replaces
that with auto-discovery: every ``*.yaml`` under the configured
``targets`` directory is loaded and validated against :class:`TargetFile`,
which is intentionally permissive — it covers the union of shapes
across all current files.

Drop a new YAML in (matching the documented field set) and it shows
up on the next run with no Python edits.

Specialised modules (telegram, cloudflare) own their YAMLs through
:class:`censprobe_core.config.TargetsConfig.module_owned` — those files
are still loaded into the :class:`TargetSet` so the modules can fetch
them via ``targetset.files['telegram']``, but they are excluded from
the *generic* view returned by helpers like
:meth:`TargetSet.all_generic_targets` so dns/tcp/tls/http don't try to
probe Telegram's MTProto-shaped entries.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

logger = logging.getLogger(__name__)


# Per-entry models


class Target(BaseModel):
    """A generic HTTP / TLS / DNS endpoint.

    Used by news / social / messengers / vpn / neutral and any future
    drop-in YAML. ``probes`` is reserved for a future per-target probe
    selector; today every applicable module probes every target.
    """

    model_config = ConfigDict(extra="allow")
    domain: str | None = None
    ip: str | None = None
    port: int | None = None
    name: str | None = None
    category: str | None = None
    urls: list[str] = Field(default_factory=list)
    expected_status: int | None = None
    ech_advertised: bool = False
    notes: str | None = None
    probes: list[str] = Field(default_factory=list)


class TcpTarget(BaseModel):
    """A direct (ip, port) TCP reachability target — anycast DNS, etc."""

    model_config = ConfigDict(extra="allow")
    ip: str
    port: int
    name: str | None = None
    category: str | None = None
    notes: str | None = None


class CfQuicTarget(BaseModel):
    """Cloudflare/anycast UDP-443 QUIC probe target.

    Note: the existing cloudflare.yaml uses ``port`` (not ``port_udp``)
    for QUIC entries — kept that way to avoid churning the file.
    """

    model_config = ConfigDict(extra="allow")
    host: str
    port: int = 443
    name: str | None = None
    category: str | None = None
    notes: str | None = None


class CfWarpTcpTarget(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    port_tcp: int
    name: str | None = None
    category: str | None = None
    expected_status: int | None = None
    notes: str | None = None


class CfWarpUdpTarget(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str
    port_udp: int
    name: str | None = None
    category: str | None = None
    protocol: str | None = None
    notes: str | None = None


class CfHttpTarget(BaseModel):
    """Cloudflare HTTP probe target.

    Accepts either ``host`` (used by quic / warp tcp / warp udp targets)
    or ``domain`` (the convention in the http_targets section of
    cloudflare.yaml). The model validator below normalises the two onto
    ``host`` so consumers don't need to know which key the YAML used.
    """

    model_config = ConfigDict(extra="allow")
    host: str | None = None
    domain: str | None = None
    name: str | None = None
    expected_status: int = 200
    category: str | None = None
    notes: str | None = None

    @model_validator(mode="after")
    def _coerce_host_from_domain(self) -> CfHttpTarget:
        if self.host is None:
            self.host = self.domain
        if self.host is None:
            raise ValueError("CfHttpTarget needs either `host` or `domain`")
        return self


class TelegramDC(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: int
    location: str | None = None
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    # Required: every DC entry must enumerate the TCP ports it serves.
    # Silent-defaulting to [443] hid mistakes like an entry typo'd
    # `port: 443` (singular) — pydantic dropped it via extra="allow"
    # and the probe ran against the default with the operator unaware.
    ports: list[int] = Field(min_length=1)

    @field_validator("ipv4", "ipv6", mode="before")
    @classmethod
    def _coerce_ip_list(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return list(v)


# Per-file model


class TargetFile(BaseModel):
    """Union schema covering every shape used in current targets/*.yaml.

    A single file rarely populates every field — most fill exactly one
    or two. The union form means we can validate any file under the
    same model and pick out the relevant slice in the consuming module.
    ``extra="allow"`` gives forward-compat for fields a custom file
    might add for its own consumer.
    """

    model_config = ConfigDict(extra="allow")
    targets: list[Target] = Field(default_factory=list)
    tcp_targets: list[TcpTarget] = Field(default_factory=list)
    quic_targets: list[CfQuicTarget] = Field(default_factory=list)
    warp_targets: list[CfWarpTcpTarget] = Field(default_factory=list)
    warp_tunnel_udp_targets: list[CfWarpUdpTarget] = Field(default_factory=list)
    http_targets: list[CfHttpTarget] = Field(default_factory=list)
    api_datacenters: list[TelegramDC] = Field(default_factory=list)
    web: list[str] = Field(default_factory=list)
    auxiliary: list[str] = Field(default_factory=list)
    cdn: list[str] = Field(default_factory=list)
    owned_cert_patterns: list[str] = Field(default_factory=list)
    health_weights: dict[str, float] = Field(default_factory=dict)


# Aggregated set


class TargetSet(BaseModel):
    """Aggregated view across every targets/*.yaml file.

    ``files`` maps basename (without .yaml) to the parsed
    :class:`TargetFile`. ``module_owned`` lists basenames that belong to
    specialised modules — they are still in ``files`` (so their owner
    module can read them) but excluded from the *generic* views below
    consumed by dns / tcp / tls / http.
    """

    files: dict[str, TargetFile] = Field(default_factory=dict)
    module_owned: list[str] = Field(default_factory=list)

    # ── Generic views (consumed by dns / tcp / tls / http) ──────────────────

    def _generic_files(self) -> list[TargetFile]:
        return [f for name, f in self.files.items() if name not in self.module_owned]

    def all_generic_targets(self) -> list[Target]:
        return [t for f in self._generic_files() for t in f.targets]

    def domains(self) -> list[str]:
        """Sorted unique list of domains across all generic + telegram-web targets.

        Telegram web hostnames are folded in here because the DNS module
        wants to test them through the same resolver-comparison logic
        as the other generic targets — the dedicated telegram module
        only handles the DC ports, not DNS resolution.
        """
        seen: set[str] = set()
        out: list[str] = []
        for t in self.all_generic_targets():
            if t.domain and t.domain not in seen:
                seen.add(t.domain)
                out.append(t.domain)
        # Pull telegram web hosts in too (they're domains, not Targets).
        tg = self.files.get("telegram")
        if tg is not None:
            for d in tg.web:
                if d not in seen:
                    seen.add(d)
                    out.append(d)
        return sorted(out)

    def tcp_targets(self) -> list[tuple[str, int]]:
        seen: set[tuple[str, int]] = set()
        out: list[tuple[str, int]] = []
        for f in self.files.values():
            for t in f.tcp_targets:
                key = (t.ip, t.port)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
        return out

    def tls_targets(self) -> list[dict[str, Any]]:
        """Shape expected by :func:`censprobe_core.modules.tls.run_tls_tests`.

        Built from the generic Target list. The blocked-SNI defaults to
        the domain itself (matches historical behaviour); a
        future-target file can override by setting ``blocked_sni``
        explicitly via the ``extra="allow"`` escape hatch.
        """
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for t in self.all_generic_targets():
            if not t.domain or t.domain in seen:
                continue
            seen.add(t.domain)
            extra = t.model_extra or {}
            out.append(
                {
                    "domain": t.domain,
                    "blocked_sni": extra.get("blocked_sni", t.domain),
                    "url": (t.urls[0] if t.urls else f"https://{t.domain}"),
                    "ech_advertised": bool(t.ech_advertised),
                }
            )
        return out

    def http_targets(self) -> list[dict[str, Any]]:
        """Shape expected by :func:`censprobe_core.modules.http.run_http_tests`."""
        out: list[dict[str, Any]] = []
        for t in self.all_generic_targets():
            out.append(t.model_dump(exclude_none=False))
        return out

    # ── Module-owned views ──────────────────────────────────────────────────

    def file(self, basename: str) -> TargetFile | None:
        return self.files.get(basename)


# Loader


def load_targets(
    directory: Path,
    files: list[str] | None = None,
    module_owned: list[str] | None = None,
) -> TargetSet:
    """Discover and parse target YAMLs into a :class:`TargetSet`.

    ``files`` (optional): explicit list of basenames (without ``.yaml``).
    Overrides auto-discovery. Useful for tests or restricted runs.

    ``module_owned`` (optional): basenames excluded from the generic
    view. Files are still loaded into ``set.files`` so their owner
    modules can consume them.

    Fail-loud contract (matches :func:`load_config`): every discovered
    file MUST parse and validate against :class:`TargetFile`. A missing
    directory, an unreadable file, malformed YAML, or a Pydantic
    validation error all raise :class:`ValueError` with the offending
    path. The previous warn-and-skip behaviour silently dropped a
    typo'd ``news.yaml`` from the run; the dashboard then rendered the
    affected category empty without any error surface — opposite of
    the project's "fail loud at startup" invariant. Symlinks remain
    a silent-skip on purpose: they're explicitly rejected as a
    path-traversal guard, not an operator typo.

    ``module_owned`` entries that don't correspond to a discovered
    basename are also rejected — that is the most common source of a
    "module enabled but target file missing" runtime surprise.
    """
    out = TargetSet(module_owned=list(module_owned or []))
    if not directory.exists():
        raise ValueError(
            f"Targets directory {directory} does not exist. "
            f"censprobe.yaml::targets.directory points at a missing path — "
            f"fix the path or create the directory with at least one "
            f"*.yaml file."
        )

    candidates = (
        [directory / f"{name}.yaml" for name in files]
        if files
        else sorted(directory.glob("*.yaml"))
    )

    for path in candidates:
        loaded = _load_one_target_file(path, files_explicit=bool(files))
        if loaded is None:
            continue
        out.files[path.stem] = loaded

    _validate_module_owned(out, directory)
    return out


def _load_one_target_file(path: Path, *, files_explicit: bool) -> TargetFile | None:
    """Parse + validate a single ``targets/*.yaml`` file.

    Returns ``None`` to signal "skip this entry" (symlink guard, or
    auto-discovered path that doesn't exist). Raises ``ValueError`` for
    operator-visible failures (file requested explicitly but missing,
    read error, YAML syntax, schema validation, non-mapping top level).

    ``files_explicit=True`` tightens the missing-file path: when the
    operator listed a basename in ``censprobe.yaml::targets.files`` we
    refuse to silently shrink the run, while glob-discovered entries
    that vanish between ``glob`` and ``exists`` (rare, but possible on
    a CI cleanup race) are tolerated.
    """
    if path.is_symlink():
        # Symlink guard: importer/runner refuse to follow symlinks in
        # the targets tree (a malicious PR could ship a symlink at
        # targets/foo.yaml → /etc/passwd). Skip silently — not an
        # operator typo, so no actionable error to raise.
        logger.warning("Skipping symlink %s in targets/", path)
        return None
    if not path.exists():
        if files_explicit:
            raise ValueError(
                f"Target file {path} listed in censprobe.yaml::"
                f"targets.files does not exist on disk."
            )
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"Could not read target file {path}: {e}") from e
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in target file {path}: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError(
            f"Target file {path} must be a YAML mapping at the top level "
            f"(got {type(raw).__name__})."
        )
    try:
        tf = TargetFile.model_validate(raw)
    except Exception as e:
        raise ValueError(f"Invalid schema in target file {path}: {e}") from e
    logger.debug("Loaded target file: %s", path.stem)
    return tf


def _validate_module_owned(out: TargetSet, directory: Path) -> None:
    """Reject ``module_owned`` entries that point at no discovered file.

    A typo ``[telegrm]`` would otherwise silently leak Telegram's
    MTProto-shaped targets into the generic dns/tcp/tls/http view and
    produce spurious BLOCKED rows there. Fail-loud so the operator
    catches the typo at startup, not from a confused dashboard.
    """
    orphan_owned = [name for name in out.module_owned if name not in out.files]
    if orphan_owned:
        raise ValueError(
            f"censprobe.yaml::targets.module_owned references files that were "
            f"not discovered under {directory}: {orphan_owned}. "
            f"Either fix the typo, or create the file."
        )
