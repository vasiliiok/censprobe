"""
db.py — SQLAlchemy async models and DB initialization.

Schema:
  test_runs — one row per test_id, tracks meta
  test_results — one row per TestResult (from .json reports)
  listener_sessions — one row per listener session
  protocol_results — one row per protocol per session
"""
from __future__ import annotations

import os
from typing import AsyncGenerator

from sqlalchemy import (
    Boolean,
    Column,
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
from sqlalchemy.orm import DeclarativeBase, relationship

import urllib.parse as _urlparse

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

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_id = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    purpose = Column(String(64), default="vpn-entry")  # vpn-entry | vpn-exit | vpn-relay
    server_meta = Column(JSONB, nullable=True)
    ipv6_available = Column(Boolean, default=False)
    kernel = Column(String(64), nullable=True)
    distro = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)

    # Scores (latest solo run)
    entry_score = Column(Float, nullable=True)
    exit_score = Column(Float, nullable=True)
    relay_score = Column(Float, nullable=True)
    overall_score = Column(Float, nullable=True)
    throttling_detected = Column(Boolean, default=False)
    dns_integrity = Column(Float, nullable=True)
    tls_integrity = Column(Float, nullable=True)
    telegram_health = Column(Float, nullable=True)
    # Native Postgres text[] — lets Grafana use:
    #   WHERE 'sni_throttling' = ANY(detected_techniques)
    detected_techniques = Column(ARRAY(String), nullable=True)
    recommended_protocols = Column(ARRAY(String), nullable=True)

    results = relationship("TestResult", back_populates="test_run", cascade="all, delete-orphan")
    sessions = relationship("ListenerSession", back_populates="test_run", cascade="all, delete-orphan")


class TestResult(Base):
    """One row per TestResult entry (from server-solo-*.json or server-listener-*.json)."""
    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # Postgres does not auto-index foreign-key columns; every dashboard
    # JOIN/WHERE on test_run_id would otherwise sequential-scan this table
    # once it gets large.
    test_run_id = Column(
        Integer,
        ForeignKey("test_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_file = Column(String(256), nullable=False)  # e.g. server-solo-2026-04-21.json
    test = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False)
    # Stable family key auto-derived from ``test`` (and ``category`` as
    # a fallback) — see censprobe_core.subcategories. Grafana panels
    # filter on this column instead of fragile ``test LIKE '...'``
    # patterns; without it, a renamed test silently emptied a panel.
    subcategory = Column(String(64), nullable=False, default="unknown", index=True)
    target = Column(Text, nullable=False)
    verdict = Column(String(64), nullable=False)
    method = Column(String(64), nullable=True)
    confidence = Column(Float, default=1.0)
    rtt_ms = Column(Float, nullable=True)
    attempts = Column(Integer, default=1)
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True)
    source = Column(String(32), default="solo")  # solo | listener

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
            "test_run_id", "report_file", "test", "target",
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

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_run_id = Column(
        Integer,
        ForeignKey("test_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id = Column(String(128), nullable=False)
    report_file = Column(String(256), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    stopped_at = Column(DateTime(timezone=True), nullable=True)
    duration_sec = Column(Float, nullable=True)
    client_connected = Column(Boolean, default=False)
    client_meta = Column(JSONB, nullable=True)

    test_run = relationship("TestRun", back_populates="sessions")
    protocol_results = relationship(
        "ProtocolResult", back_populates="session", cascade="all, delete-orphan"
    )

    # Hard guarantee that one listener report file produces exactly one row.
    # The importer's dedup query already filters by report_file, but a second
    # sync-api replica (or a partially-completed transaction that gets
    # committed twice) would otherwise dupe sessions and double-count
    # protocol_results in dashboards.
    __table_args__ = (
        UniqueConstraint(
            "test_run_id", "report_file",
            name="uq_listener_sessions_run_file",
        ),
    )


class ProtocolResult(Base):
    """One row per protocol per listener session.

    Client-network ASN is now on the parent ListenerSession.client_meta
    rather than duplicated on each protocol row.
    """
    __tablename__ = "protocol_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(
        Integer,
        ForeignKey("listener_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    protocol = Column(String(64), nullable=False)
    verdict = Column(String(64), nullable=False)
    handshake_count = Column(Integer, default=0)
    data_transfer_ok = Column(Boolean, default=False)
    avg_rtt_ms = Column(Float, nullable=True)
    # Listener-side sustained-data measurement (only populated for SS /
    # VLESS / Hysteria2 — the three protocols that route through the
    # loopback echo server). NULL for OpenVPN / WireGuard / AmneziaWG
    # whose data-phase verification is a single ICMP ping. Surfaced in
    # dashboards as an operator signal; NEVER used by scoring.
    avg_throughput_mbps = Column(Float, nullable=True)
    throughput_throttled = Column(Boolean, default=False)

    session = relationship("ListenerSession", back_populates="protocol_results")


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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    async with async_session_factory() as session:
        yield session
