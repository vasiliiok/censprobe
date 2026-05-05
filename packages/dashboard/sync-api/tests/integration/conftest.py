"""
Integration-test fixtures for sync-api.

Two paths to a real Postgres:

  1. CI path. ``DATABASE_URL`` is preset to ``postgresql+asyncpg://...``
     pointing at the GitHub Actions ``services: postgres`` container.
     We connect directly — no testcontainers, no Docker socket needed.

  2. Local fallback. ``testcontainers[postgres]`` spins up a one-shot
     Postgres in Docker for the test session. If Docker is not available,
     the whole integration directory is skipped (collection-time) so
     unit-only contributors aren't blocked.

A real connection check at session start decides which path applies.
The ``sync_api.db`` module's globals (``engine``, ``async_session_factory``)
are replaced for the test session so every endpoint test uses the real
DB, and per-test TRUNCATE keeps state isolated.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

# ─────────────────────────────────────────────────────────────────────────────
# Pick the database URL for the session
# ─────────────────────────────────────────────────────────────────────────────


def _is_placeholder_url(url: str) -> bool:
    """Detect the placeholder URL the parent conftest sets for unit tests."""
    return "placeholder" in url


def _try_connect(url: str) -> bool:
    """Attempt a 2-second TCP connect to the URL's host:port."""
    import urllib.parse as up

    parsed = up.urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 5432
    import socket

    s = socket.socket()
    s.settimeout(2.0)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _resolve_database_url() -> str | None:
    """Return a usable Postgres URL, or None if neither path is available."""
    raw = os.environ.get("DATABASE_URL", "")
    # CI path — real URL preset and reachable.
    if raw and not _is_placeholder_url(raw) and _try_connect(raw):
        return raw

    # Local fallback — testcontainers (requires Docker).
    try:
        from testcontainers.postgres import PostgresContainer  # noqa: F401
    except Exception:
        return None
    try:
        # Lazy: only import when actually needed; the testcontainers
        # session below is started by the autouse fixture.
        return "DEFER_TO_TESTCONTAINERS"
    except Exception:
        return None


_DSN_OR_DEFER = _resolve_database_url()
if _DSN_OR_DEFER is None:
    pytest.skip(
        "Integration tests require a reachable Postgres "
        "(set DATABASE_URL or have Docker available for testcontainers)",
        allow_module_level=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Session-scoped engine + tables
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def _testcontainer_dsn() -> Iterator[str | None]:
    """Spin up a Postgres testcontainer if we need one.

    Local Docker environments occasionally have a broken overlay
    snapshotter or no postgres:16-alpine image cached. Catch the
    container-start failure and skip the integration session cleanly
    rather than dumping a docker stack-trace through every test.
    """
    if _DSN_OR_DEFER != "DEFER_TO_TESTCONTAINERS":
        yield None
        return
    try:
        from testcontainers.postgres import PostgresContainer

        pg = PostgresContainer("postgres:16-alpine")
        pg.start()
    except Exception as e:  # pragma: no cover — local-Docker failure path
        pytest.skip(
            f"Could not start Postgres testcontainer: {e!s}. "
            f"Set DATABASE_URL to a reachable Postgres or fix Docker.",
            allow_module_level=False,
        )
        yield None
        return
    try:
        # PostgresContainer.get_connection_url() returns a psycopg2 URL —
        # we want asyncpg so swap the driver scheme.
        raw = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql+asyncpg://")
        if raw.startswith("postgresql://"):
            raw = "postgresql+asyncpg://" + raw[len("postgresql://") :]
        yield raw
    finally:
        pg.stop()


@pytest.fixture(scope="session")
def pg_dsn(_testcontainer_dsn: str | None) -> str:
    """Return the DSN actually used by tests this session."""
    if _DSN_OR_DEFER == "DEFER_TO_TESTCONTAINERS":
        assert _testcontainer_dsn is not None
        return _testcontainer_dsn
    assert _DSN_OR_DEFER is not None
    return _DSN_OR_DEFER


@pytest.fixture(scope="session", autouse=True)
async def _patch_db_module(pg_dsn: str) -> AsyncIterator[None]:
    """Replace ``sync_api.db`` globals so every test uses the real DB.

    Session-scoped — every test shares one engine and one event loop
    (pytest-asyncio is configured with ``loop_scope = session`` in the
    repo-level pyproject.toml). NullPool keeps connection lifecycles
    short, which keeps state clean across tests without tearing down
    the engine itself.
    """
    from sync_api import db as db_mod

    new_engine = create_async_engine(pg_dsn, poolclass=NullPool)
    new_factory = async_sessionmaker(new_engine, expire_on_commit=False)

    old_engine = db_mod.engine
    old_factory = db_mod.async_session_factory

    db_mod.engine = new_engine
    db_mod.async_session_factory = new_factory

    await db_mod.init_db()

    try:
        yield
    finally:
        await new_engine.dispose()
        db_mod.engine = old_engine
        db_mod.async_session_factory = old_factory


# ─────────────────────────────────────────────────────────────────────────────
# probe-core config — _import_once → _apply_scores → compute_scores
# walks through ``censprobe_core.config.get_config()`` which raises if
# no config has been loaded. Install a minimal default.
# ─────────────────────────────────────────────────────────────────────────────


def _default_censprobe_cfg() -> Any:
    from censprobe_core.config import CensprobeConfig

    return CensprobeConfig.model_validate(
        {
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
            },
            "throughput": {"enabled": True, "target_bytes": 1048576, "timeout_sec": 30.0},
            "scoring": {
                "entry": {"protocol": 0.6, "uplink": 0.3, "latency": 0.1},
                "exit": {"uplink": 0.6, "censorship": 0.4},
                "relay": {"tcp": 0.7, "latency": 0.3},
            },
            "targets": {
                "directory": "targets",
                "files": [],
                "module_owned": ["telegram", "cloudflare"],
            },
        }
    )


@pytest.fixture(autouse=True)
def _loaded_censprobe_config() -> Iterator[None]:
    """Install a default censprobe config for the duration of the test.

    Function-scoped: ``compute_scores`` reads it, and tests that exercise
    the import pipeline rely on it being present. Reset after each test
    so we don't leak state between tests (mirrors probe-core's autouse
    reset).
    """
    from censprobe_core.config import reset_config, set_config

    set_config(_default_censprobe_cfg())
    try:
        yield
    finally:
        reset_config()


# ─────────────────────────────────────────────────────────────────────────────
# Per-test isolation
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def _clean_tables() -> AsyncIterator[None]:
    """TRUNCATE all sync-api tables before each integration test.

    We don't bother with nested transactions or rollback — the schema
    is small (4 tables) and TRUNCATE on an empty table is essentially
    free. Keeps every test starting from a known state without sharing
    a connection across tests.
    """
    from sqlalchemy import text
    from sync_api.db import async_session_factory

    async with async_session_factory() as s:
        # `RESTART IDENTITY` resets serial PK counters so deterministic
        # row IDs are easier to assert if a test ever needs them.
        await s.execute(
            text(
                "TRUNCATE TABLE protocol_results, listener_sessions, "
                "test_results, test_runs RESTART IDENTITY CASCADE"
            )
        )
        await s.commit()
    yield


# ─────────────────────────────────────────────────────────────────────────────
# DB session for direct DB interactions in tests
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
async def db_session() -> AsyncIterator[Any]:
    """Yield a fresh AsyncSession for direct ORM use in tests."""
    from sync_api.db import async_session_factory

    async with async_session_factory() as s:
        yield s


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app client
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
async def app_client() -> AsyncIterator[Any]:
    """Yield an httpx.AsyncClient bound to the FastAPI app.

    The real ``lifespan`` calls ``init_db`` (already done by the session
    fixture) AND starts a background importer task — for endpoint tests
    we don't want the loop running in the background. We use
    ``asgi_lifespan.LifespanManager`` only when explicitly needed
    (import-pipeline tests); regular endpoint tests bypass lifespan
    entirely by using ``httpx.ASGITransport`` directly.
    """
    import httpx
    from sync_api.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def app_client_with_lifespan() -> AsyncIterator[Any]:
    """Like ``app_client`` but exercises the lifespan handler.

    Lifespan starts the background importer; tests that need the
    importer running explicitly opt in. The IMPORT_INTERVAL_SEC parent
    conftest already pins to 60s — long enough that the loop never
    fires within a test.
    """
    import httpx
    from asgi_lifespan import LifespanManager
    from sync_api.main import app

    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
