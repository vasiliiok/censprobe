"""
db.py — SQLAlchemy async models and DB initialization.

Schema:
  test_runs — one row per test_id, tracks meta
  test_results — one row per TestResult (from .json reports)
  listener_sessions — one row per listener session
  protocol_results — one row per protocol per session
"""

from __future__ import annotations

import logging
import os
import urllib.parse as _urlparse
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

import asyncpg.exceptions
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Example: postgresql+asyncpg://censprobe:PASSWORD@postgres/censprobe"
    )

# Re-encode the password component so that special characters (e.g. "=", "+")
# that are valid in passwords but reserved in URLs don't break asyncpg's parser.
_parsed = _urlparse.urlparse(DATABASE_URL)
if _parsed.password and _parsed.password != _urlparse.quote(_parsed.password, safe=""):
    _encoded_password = _urlparse.quote(_parsed.password, safe="")
    DATABASE_URL = _parsed._replace(
        netloc=f"{_parsed.username}:{_encoded_password}@{_parsed.hostname}"
        + (f":{_parsed.port}" if _parsed.port else "")
    ).geturl()

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# Cascade rule applied to every parent → child relationship below.
# Hoisted to a constant — Sonar S1192 otherwise flags the literal duplicated
# across the three relationship() calls.
_CASCADE_DELETE_ORPHAN = "all, delete-orphan"


class TestRun(Base):
    """One row per test_id (a server being evaluated).

    Network identity is held in the JSONB `server_meta` column, mirroring
    the EndpointMeta shape produced by probe-core's server_meta.enrich_endpoint.
    Grafana queries it via `server_meta->'asn'->>'asn'` etc. Host-level
    fields (kernel/distro/ipv6) stay as separate columns because they're
    displayed and filtered individually rather than as a network-identity
    bundle. No IPv4 literal is stored.
    """

    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    test_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    server_meta: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ipv6_available: Mapped[bool] = mapped_column(Boolean, default=False)
    kernel: Mapped[str | None] = mapped_column(String(64), nullable=True)
    distro: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Scores (latest solo run)
    entry_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    exit_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    relay_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Number of listener-session reports that fed compute_scores. Lets
    # Grafana panels distinguish full runs (≥1 session) from partial /
    # solo-only runs where overall is the mean of (exit, relay) only and
    # entry_score is built on a neutral 0.5 protocol_reach fallback.
    listener_session_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    throttling_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    dns_integrity: Mapped[float | None] = mapped_column(Float, nullable=True)
    tls_integrity: Mapped[float | None] = mapped_column(Float, nullable=True)
    telegram_health: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Native Postgres text[] — lets Grafana use:
    #   WHERE 'sni_throttling' = ANY(detected_techniques)
    detected_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    recommended_protocols: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    results = relationship("TestResult", back_populates="test_run", cascade=_CASCADE_DELETE_ORPHAN)
    sessions = relationship(
        "ListenerSession", back_populates="test_run", cascade=_CASCADE_DELETE_ORPHAN
    )


class TestResult(Base):
    """One row per TestResult entry (from server-solo-*.json or server-listener-*.json)."""

    __tablename__ = "test_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Postgres does not auto-index foreign-key columns; every dashboard
    # JOIN/WHERE on test_run_id would otherwise sequential-scan this table
    # once it gets large.
    test_run_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("test_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_file: Mapped[str] = mapped_column(
        String(256), nullable=False
    )  # e.g. server-solo-2026-04-21.json
    test: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    # Stable family key auto-derived from ``test`` (and ``category`` as
    # a fallback) — see censprobe_core.subcategories. Grafana panels
    # filter on this column instead of fragile ``test LIKE '...'``
    # patterns; without it, a renamed test silently emptied a panel.
    subcategory: Mapped[str] = mapped_column(
        String(64), nullable=False, default="unknown", index=True
    )
    target: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), nullable=False)
    method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    # rtt_ms: protocol-/module-specific latency signal (TCP-connect for
    # tcp/tls probes, query-RTT for DNS, tunnel ICMP-ping for VPN
    # protocols). Semantics vary by module/protocol.
    rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    # elapsed_ms: total wall-clock time of the probe in ms. Uniform
    # semantics across all probes (added 2026-05). Display layers and
    # latency-distribution panels should prefer this over rtt_ms because
    # rtt_ms can be a sub-measurement (e.g. just TCP connect) that
    # under-reports actual probe duration on timeout-failing paths.
    elapsed_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="solo")  # solo | listener

    test_run = relationship("TestRun", back_populates="results")

    # Composite index keeps the per-refresh dedup query
    # (`SELECT DISTINCT report_file WHERE test_run_id = ?`) on an index-only
    # path: without it, Postgres uses the single-column test_run_id index and
    # then re-fetches every row to read report_file. We deduplicate hundreds
    # of rows per file every refresh.
    #
    # `(test_run_id, report_file, test, target)` UNIQUE: one logical
    # measurement = one row. Sibling ListenerSession already enforced
    # this; without the equivalent guard here, two sync-api passes (or
    # two replicas) racing on the same file produced duplicate rows
    # that silently inflated every COUNT(*) panel in Grafana. The tuple
    # adds (test, target) because a single solo report contains many
    # rows for the same report_file — the guard is per measurement
    # within the file.
    __table_args__ = (
        Index("ix_test_results_run_file", "test_run_id", "report_file"),
        UniqueConstraint(
            "test_run_id",
            "report_file",
            "test",
            "target",
            name="uq_test_results_run_file_test_target",
        ),
    )


class ListenerSession(Base):
    """One row per listener session (per SESSION_ID).

    `client_connected` is the strongest blocking signal: false means the
    client never reached the cred-endpoint and per-protocol BLOCKED
    verdicts are network-level, not protocol-level. `client_meta` mirrors
    EndpointMeta shape and is null when enrichment failed or the client
    never connected.
    """

    __tablename__ = "listener_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    test_run_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("test_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    report_file: Mapped[str] = mapped_column(String(256), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    client_connected: Mapped[bool] = mapped_column(Boolean, default=False)
    client_meta: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Operator-supplied network-context flags from listener CLI
    # ``--mobile`` / ``--white``. Indexed so Grafana template variables
    # populate quickly even at thousands of sessions; both flags can be
    # set together (mobile carrier with whitelisting in effect).
    is_mobile: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_whitelist: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    test_run = relationship("TestRun", back_populates="sessions")
    protocol_results = relationship(
        "ProtocolResult", back_populates="session", cascade=_CASCADE_DELETE_ORPHAN
    )

    # Hard guarantee that one listener report file produces exactly one row.
    # The importer's dedup query already filters by report_file, but a second
    # sync-api replica (or a partially-completed transaction that gets
    # committed twice) would otherwise dupe sessions and double-count
    # protocol_results in dashboards.
    __table_args__ = (
        UniqueConstraint(
            "test_run_id",
            "report_file",
            name="uq_listener_sessions_run_file",
        ),
    )


class ProtocolResult(Base):
    """One row per protocol per listener session.

    Client-network ASN is now on the parent ListenerSession.client_meta
    rather than duplicated on each protocol row.
    """

    __tablename__ = "protocol_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("listener_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), nullable=False)
    handshake_count: Mapped[int] = mapped_column(Integer, default=0)
    data_transfer_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    # Listener-side sustained-data measurement (only populated for SS /
    # VLESS / Hysteria2 — the three protocols that route through the
    # loopback echo server). NULL for OpenVPN / WireGuard / AmneziaWG
    # whose data-phase verification is a single ICMP ping. Surfaced in
    # dashboards as an operator signal; NEVER used by scoring.
    avg_throughput_mbps: Mapped[float | None] = mapped_column(Float, nullable=True)
    throughput_throttled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Free-text diagnostic from the listener's ProtocolResult.note. Two
    # producers populate it today: (a) the listener-side self-test
    # downgrade ("listener-side responder self-test failed at startup —
    # this BLOCKED-shape result is not a confirmed network block …"),
    # and (b) the per-vantage `_mtproto_orig_failure_note` ("mtproto-proxy
    # not launched: 0/19 …" vs "launched with K/N upstreams alive but the
    # listener-side loopback self-test still timed out …"). Surfacing
    # this in the dashboard turns a bare BLOCKED/ERROR tile into an
    # operator-actionable diagnosis without re-running the test.
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    session = relationship("ListenerSession", back_populates="protocol_results")


# Operator-facing hint surfaced when Postgres rejects our credentials.
# The most common cause in dev is a ``db_data`` named volume that was
# initialized with an older ``DB_PASSWORD`` and survived ``docker system
# prune`` (named volumes are kept while any container — even stopped —
# references them). ``initdb`` only runs on a *fresh* PGDATA, so editing
# ``.env`` later doesn't reset the on-disk password. Surfacing the fix in
# the first log line turns a five-minute traceback hunt into a copy-paste.
_DB_AUTH_FAILURE_HINT = (
    "Postgres rejected the password for user 'censprobe'. The db_data "
    "named volume likely predates the current DB_PASSWORD in .env "
    "(initdb only runs on a fresh PGDATA). To reset:\n"
    "    docker compose --profile dashboard down -v\n"
    "    docker compose --profile dashboard up -d"
)


def _is_invalid_password_error(exc: BaseException) -> bool:
    """True if `exc` (or its DBAPI ``.orig``) is asyncpg's password failure.

    SQLAlchemy 2.0 leaves connection-time pool errors *unwrapped* (the
    raw asyncpg exception bubbles out of ``engine.begin()``), but
    query-time errors are wrapped in ``DBAPIError`` with ``.orig`` set
    to the driver exception. We check both shapes so the hint fires
    regardless of when the credential rejection surfaces.
    """
    if isinstance(exc, asyncpg.exceptions.InvalidPasswordError):
        return True
    orig = getattr(exc, "orig", None)
    return isinstance(orig, asyncpg.exceptions.InvalidPasswordError)


async def init_db() -> None:
    """Create all tables (if missing).

    Schema is single-source-of-truth via the SQLAlchemy models above.
    create_all() is a no-op for tables that already exist with the
    declared shape; on a fresh DB it stamps the full schema in one shot.

    Schema migrations note: create_all() does NOT alter existing tables
    on column rename/drop. After a model change that removes columns
    (e.g. the IPv4 redaction refactor), drop the dev `db_data` volume
    and re-run import:

        docker compose --profile dashboard down -v
        docker compose --profile dashboard up -d

    Reports on disk are the source of truth and re-import populates
    every column from scratch.
    """
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:  # noqa: BLE001 - re-raised below; we only sniff for one type to log a hint
        if _is_invalid_password_error(exc):
            logger.error(_DB_AUTH_FAILURE_HINT)
        raise


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    async with async_session_factory() as session:
        yield session
