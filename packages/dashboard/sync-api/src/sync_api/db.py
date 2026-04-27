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
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Example: postgresql+asyncpg://censprobe:PASSWORD@postgres/censprobe"
    )

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
    """One row per test_id (a server being evaluated)."""
    __tablename__ = "test_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_id = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    purpose = Column(String(64), default="vpn-entry")  # vpn-entry | vpn-exit | vpn-relay
    asn = Column(String(32), nullable=True)
    as_name = Column(String(128), nullable=True)
    location = Column(String(128), nullable=True)
    ipv4_masked = Column(String(32), nullable=True)
    ipv6_available = Column(Boolean, default=False)
    provider = Column(String(64), nullable=True)
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
    target = Column(Text, nullable=False)
    verdict = Column(String(64), nullable=False)
    method = Column(String(64), nullable=True)
    confidence = Column(Float, default=1.0)
    rtt_ms = Column(Float, nullable=True)
    attempts = Column(Integer, default=1)
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True)
    source = Column(String(32), default="solo")  # solo | listener | control

    test_run = relationship("TestRun", back_populates="results")

    # Composite index keeps the per-refresh dedup query
    # (`SELECT DISTINCT report_file WHERE test_run_id = ?`) on an index-only
    # path: without it, Postgres uses the single-column test_run_id index and
    # then re-fetches every row to read report_file. We deduplicate hundreds
    # of rows per file every refresh.
    __table_args__ = (
        Index("ix_test_results_run_file", "test_run_id", "report_file"),
    )


class ListenerSession(Base):
    """One row per listener session (per SESSION_ID)."""
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
    """One row per protocol per listener session."""
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
    from_asn = Column(String(32), nullable=True)

    session = relationship("ListenerSession", back_populates="protocol_results")


# ─────────────────────────────────────────────────────────────────────────────
# Idempotent schema migrations
# ─────────────────────────────────────────────────────────────────────────────
#
# `Base.metadata.create_all` only creates *missing* tables — it never adds new
# columns or constraints to tables that already exist. We don't ship a full
# Alembic setup (overkill for ~4 tables, single writer), so we patch the live
# schema by hand using ``IF NOT EXISTS`` DDL. Every statement here MUST be
# idempotent: this function runs on every container start.
#
# When you add or rename a column in a model, append an ``ALTER TABLE``
# statement here so existing dashboard deployments pick it up without manual
# `psql` surgery.
_MIGRATIONS: tuple[str, ...] = (
    # test_runs: kernel/distro were added after v0.1; nullable so they're
    # safe to backfill as NULL on upgrade.
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS kernel VARCHAR(64)",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS distro VARCHAR(128)",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS detected_techniques TEXT[]",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS recommended_protocols TEXT[]",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS dns_integrity DOUBLE PRECISION",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS tls_integrity DOUBLE PRECISION",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS telegram_health DOUBLE PRECISION",
    "ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS throttling_detected BOOLEAN DEFAULT FALSE",
    # Composite dedup index (matches __table_args__ on TestResult).
    "CREATE INDEX IF NOT EXISTS ix_test_results_run_file "
    "ON test_results(test_run_id, report_file)",
)


async def _run_migrations(conn) -> None:
    """Apply additive, idempotent DDL on top of create_all.

    The unique constraint on listener_sessions(test_run_id, report_file) is
    handled separately because Postgres lacks an ``ADD CONSTRAINT IF NOT
    EXISTS`` form — we look it up in pg_catalog first.
    """
    for stmt in _MIGRATIONS:
        await conn.execute(text(stmt))

    # Add the unique constraint only if it isn't there yet, and only if the
    # existing data permits it (older deployments may have dupes from before
    # the constraint existed; in that case we log and skip rather than crash
    # the whole startup).
    exists = (
        await conn.execute(
            text(
                "SELECT 1 FROM pg_constraint "
                "WHERE conname = 'uq_listener_sessions_run_file'"
            )
        )
    ).scalar()
    if not exists:
        try:
            await conn.execute(
                text(
                    "ALTER TABLE listener_sessions "
                    "ADD CONSTRAINT uq_listener_sessions_run_file "
                    "UNIQUE (test_run_id, report_file)"
                )
            )
        except Exception as e:  # pragma: no cover — recovery path
            # Likely a duplicate row left over from a pre-constraint refresh.
            # Don't kill startup over this; surface it for the operator and
            # let dedupe-by-query keep doing its job.
            import logging
            logging.getLogger(__name__).warning(
                "Could not add uq_listener_sessions_run_file (duplicate rows?): %s", e
            )


async def init_db() -> None:
    """Create all tables (if missing), then patch any new columns/indexes."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _run_migrations(conn)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    async with async_session_factory() as session:
        yield session
