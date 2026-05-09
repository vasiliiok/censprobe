"""
probe-core test fixtures.

Three responsibilities:
1. Reset module-level globals between tests — ``_CONFIG`` (config.py),
   ``_DOH_CLIENT``/``_ASN_CLIENT``/``_ASN_CACHE``/``_ASN_BACKOFF_UNTIL``
   (modules/dns.py). Without an autouse reset, one test's cached
   client/state leaks into the next.
2. Provide ``make_config`` — pure-python CensprobeConfig factory that
   doesn't read disk. Tests override only the fields they care about.
3. Provide ``loaded_config`` — autouse-style helper that installs a
   default config so any test calling ``compute_scores`` /
   ``_recommend_protocols`` (anything that touches ``get_config()``)
   has something to read.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from hypothesis import settings

# Force every property test in this package onto a derandomised profile so a
# CI runner can't generate a different example sequence than a local one. The
# profile is registered+loaded at conftest import time so it's active by the
# time the @settings decorators in tests/property/* execute. Documented in
# docs/TESTING.md ("Слой E — Property-based"). Re-registration is idempotent
# — listener/tests/conftest.py registers the same profile name; whichever
# loads last wins, both load the same value.
settings.register_profile("censprobe-deterministic", derandomize=True)
settings.load_profile("censprobe-deterministic")


@pytest.fixture(autouse=True)
def _reset_config_singleton() -> Iterator[None]:
    """Drop the loaded config between tests so leftover state from one test
    doesn't bleed into the next. ``set_config`` / ``reset_config`` are
    already exported by config.py — no monkeypatching of internals needed.
    """
    from censprobe_core.config import reset_config

    yield
    reset_config()


@pytest.fixture(autouse=True)
def _reset_dns_globals() -> Iterator[None]:
    """Reset the four module-level globals in ``modules.dns``: lazy httpx
    clients (``_DOH_CLIENT`` / ``_ASN_CLIENT``) and the ASN-lookup cache
    + backoff timer. Reset both before and after to be safe against tests
    that don't clean up after themselves.
    """
    from censprobe_core.modules import dns

    dns._DOH_CLIENT = None
    dns._ASN_CLIENT = None
    dns._ASN_CACHE.clear()
    dns._ASN_BACKOFF_UNTIL = 0.0

    yield

    dns._DOH_CLIENT = None
    dns._ASN_CLIENT = None
    dns._ASN_CACHE.clear()
    dns._ASN_BACKOFF_UNTIL = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# CensprobeConfig factory — no YAML on disk.
# ─────────────────────────────────────────────────────────────────────────────


_DEFAULT_CFG: dict[str, Any] = {
    "vantage": {"censoring_countries": ["RU", "BY"], "override": None},
    "modules": {
        "dns": {
            "enabled": True,
            "repeats": 1,
            "doh_resolvers": ["https://cloudflare-dns.com/dns-query"],
            "doh_timeout_sec": 5.0,
            "asn_lookup_backoff_sec": 60.0,
        },
        "tcp": {
            "enabled": True,
            "repeats": 1,
            "syn_timeout_sec": 5.0,
            "fast_rst_threshold_ms": 30,
            "max_parallel": 4,
        },
        "tls": {"enabled": True, "repeats": 1, "timeout_sec": 5.0, "max_parallel": 4},
        "http": {
            "enabled": True,
            "repeats": 1,
            "body_cap_bytes": 65536,
            "timeout_connect_sec": 5.0,
            "timeout_read_sec": 10.0,
            "max_parallel": 4,
        },
        "telegram": {"enabled": True, "targets_file": "telegram", "timeout_sec": 5.0},
        "throttling": {
            "enabled": True,
            "require_censoring_vantage": True,
            "target_url": "https://example.com/100MB",
            "correct_sni": "example.com",
            "typo_sni": "exaple.com",
            "trigger_sni": "trigger.example",
            "sequential_runs": 1,
            "bandwidth_ratio_threshold": 0.25,
            "curl_timeout_sec": 30.0,
        },
        "cloudflare": {"enabled": True, "targets_file": "cloudflare"},
        "middlebox": {"enabled": True},
    },
    "protocols": {
        "enabled": ["openvpn", "wireguard", "shadowsocks"],
        "priority": ["shadowsocks", "wireguard", "openvpn"],
        "ports": {"openvpn": 1194, "wireguard": 51820, "shadowsocks": 8388},
        # No SNI-using protocol in this default enabled set, so empty
        # map is the expected shape. Tests that override `enabled` to
        # include vless_reality / mtproto_proxy* must also override
        # this map (validator rejects missing entries).
        "sni": {},
    },
    "throughput": {"enabled": True, "target_bytes": 1048576, "timeout_sec": 30.0},
    "scoring": {
        "entry": {"protocol": 0.6, "uplink": 0.3, "latency": 0.1},
        "exit": {"uplink": 0.6, "censorship": 0.4},
        "relay": {"tcp": 0.7, "latency": 0.3},
    },
    "targets": {"directory": "targets", "files": [], "module_owned": ["telegram", "cloudflare"]},
}


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    out = dict(dst)
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@pytest.fixture
def make_config() -> Callable[..., Any]:
    """Return a factory that builds a ``CensprobeConfig`` with optional
    section overrides. Pure-python — no YAML parsing, no disk I/O.

        cfg = make_config()                       # defaults
        cfg = make_config(scoring={"entry": ...}) # override one section
        cfg = make_config(protocols={"enabled": [...], ...})
    """
    from censprobe_core.config import CensprobeConfig

    def _factory(**overrides: Any) -> Any:
        merged = _deep_merge(_DEFAULT_CFG, overrides)
        return CensprobeConfig.model_validate(merged)

    return _factory


@pytest.fixture
def loaded_config(make_config: Callable[..., Any]) -> Iterator[Any]:
    """Install a default ``CensprobeConfig`` for the duration of the test.

    Use this when a test exercises code that calls ``get_config()`` —
    ``compute_scores``, ``_recommend_protocols``, etc.
    """
    from censprobe_core.config import set_config

    cfg = make_config()
    set_config(cfg)
    yield cfg
