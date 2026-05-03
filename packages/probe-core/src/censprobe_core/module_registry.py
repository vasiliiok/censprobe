"""
module_registry.py — Reflective registry for measurement modules.

Each entry binds a module name to:
  * its execution phase (parallel / serial — see ProbeRunner),
  * a small adapter that pulls the right slice from the loaded
    :class:`~censprobe_core.targets.TargetSet` and config and calls the
    underlying ``run_*`` coroutine.

Adding a new module:
  1. Drop a ``modules/<name>.py`` with an async ``run_<name>_tests``.
  2. Append a :class:`ModuleSpec` below.
  3. (Optional) Add a config section to
     :class:`~censprobe_core.config.ModulesConfig`.

The runner consults this registry in declaration order — earlier
entries run first within their phase.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Awaitable, Callable

from censprobe_core.config import CensprobeConfig
from censprobe_core.models import TestResult
from censprobe_core.modules import (
    cloudflare,
    dns,
    http,
    middlebox,
    tcp,
    telegram,
    throttling,
    tls,
)
from censprobe_core.targets import TargetSet

logger = logging.getLogger(__name__)


class Phase(StrEnum):
    """When the module runs relative to others."""
    PARALLEL = "parallel"
    """Phase A — non-bandwidth-sensitive I/O. Many modules in flight at
    once (each module owns its own per-call concurrency)."""
    SERIAL = "serial"
    """Phase B — bandwidth or RTT measurement that must run on a quiet
    uplink. Serialised in declaration order."""


# Each adapter receives (config, targetset) and returns the coroutine
# to await. Wrapping the call inside the adapter (rather than passing
# bare callables + args) means the registry stays uniform even though
# the underlying ``run_*_tests`` functions all take different arguments.
ModuleAdapter = Callable[[CensprobeConfig, TargetSet], Awaitable[list[TestResult]]]


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    phase: Phase
    adapter: ModuleAdapter
    """The default-enabled flag is read from the config at runtime —
    never hardcoded here, so the operator can disable a built-in module
    by setting ``modules.<name>.enabled: false`` in censprobe.yaml."""


# ─────────────────────────────────────────────────────────────────────────────
# Adapters — one per module, each pulling its inputs from cfg + targetset.
# ─────────────────────────────────────────────────────────────────────────────

async def _run_dns(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    return await dns.run_dns_tests(ts.domains(), repeats=cfg.modules.dns.repeats)


async def _run_tcp(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    return await tcp.run_tcp_tests(ts.tcp_targets(), repeats=cfg.modules.tcp.repeats)


async def _run_tls(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    return await tls.run_tls_tests(ts.tls_targets(), repeats=cfg.modules.tls.repeats)


async def _run_http(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    return await http.run_http_tests(ts.http_targets(), repeats=cfg.modules.http.repeats)


async def _run_telegram(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    name = cfg.modules.telegram.targets_file
    tf = ts.file(name)
    if tf is None:
        logger.warning(
            "telegram module enabled but %s.yaml not found in targets/", name,
        )
        return []
    return await telegram.run_telegram_tests(tf.model_dump())


async def _run_cloudflare(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    name = cfg.modules.cloudflare.targets_file
    tf = ts.file(name)
    if tf is None:
        logger.warning(
            "cloudflare module enabled but %s.yaml not found in targets/", name,
        )
        return []
    return await cloudflare.run_cloudflare_tests(tf.model_dump())


async def _run_throttling(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    return await throttling.run_throttling_tests()


async def _run_middlebox(cfg: CensprobeConfig, ts: TargetSet) -> list[TestResult]:
    return await middlebox.run_middlebox_tests()


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

MODULES: tuple[ModuleSpec, ...] = (
    # Phase A — parallel I/O, each module self-throttled internally.
    ModuleSpec("dns", Phase.PARALLEL, _run_dns),
    ModuleSpec("tcp", Phase.PARALLEL, _run_tcp),
    ModuleSpec("tls", Phase.PARALLEL, _run_tls),
    ModuleSpec("http", Phase.PARALLEL, _run_http),
    ModuleSpec("telegram", Phase.PARALLEL, _run_telegram),
    ModuleSpec("cloudflare", Phase.PARALLEL, _run_cloudflare),

    # Phase B — bandwidth-sensitive, serial, must run on a quiet uplink.
    ModuleSpec("throttling", Phase.SERIAL, _run_throttling),
    ModuleSpec("middlebox", Phase.SERIAL, _run_middlebox),
)


def is_enabled(spec: ModuleSpec, cfg: CensprobeConfig) -> bool:
    """Lookup the per-module ``enabled`` flag from config.

    Reads the matching attribute on ``cfg.modules`` (e.g.
    ``cfg.modules.dns.enabled``) — module names mirror config field
    names by construction. Every module must have an explicit config
    section in censprobe.yaml with an ``enabled`` flag.
    """
    section = getattr(cfg.modules, spec.name, None)
    if section is None:
        raise RuntimeError(
            f"Module '{spec.name}' has no config section in cfg.modules. "
            f"All modules must be explicitly configured in censprobe.yaml."
        )
    return bool(section.enabled)


def enabled_modules(cfg: CensprobeConfig) -> list[ModuleSpec]:
    """Filter the registry by ``enabled`` flag, preserving declaration order."""
    return [m for m in MODULES if is_enabled(m, cfg)]
