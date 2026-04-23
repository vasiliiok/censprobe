"""
db.py — SQLAlchemy async models and DB initialization.

Schema:
  test_runs — one row per test_id, tracks meta
  test_results — one row per TestResult (from .json.gz)
  listener_sessions — one row per listener session
  protocol_results — one row per protocol per session
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://censprobe:censprobe@postgres/censprobe",
)

engine = create_async_engine(DATABASE_URL, echo=False)
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
    detected_techniques = Column(Text, nullable=True)   # comma-separated
    recommended_protocols = Column(Text, nullable=True)  # comma-separated

    results = relationship("TestResult", back_populates="test_run", cascade="all, delete-orphan")
    sessions = relationship("ListenerSession", back_populates="test_run", cascade="all, delete-orphan")


class TestResult(Base):
    """One row per TestResult entry (from server-solo-*.json.gz or server-listener-*.json.gz)."""
    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_run_id = Column(Integer, ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False)
    report_file = Column(String(256), nullable=False)  # e.g. server-solo-2026-04-21.json.gz
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


class ListenerSession(Base):
    """One row per listener session (per SESSION_ID)."""
    __tablename__ = "listener_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    test_run_id = Column(Integer, ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(String(128), nullable=False)
    report_file = Column(String(256), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    stopped_at = Column(DateTime(timezone=True), nullable=True)
    duration_sec = Column(Float, nullable=True)

    test_run = relationship("TestRun", back_populates="sessions")
    protocol_results = relationship(
        "ProtocolResult", back_populates="session", cascade="all, delete-orphan"
    )


class ProtocolResult(Base):
    """One row per protocol per listener session."""
    __tablename__ = "protocol_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("listener_sessions.id", ondelete="CASCADE"), nullable=False)
    protocol = Column(String(64), nullable=False)
    verdict = Column(String(64), nullable=False)
    handshake_count = Column(Integer, default=0)
    data_transfer_ok = Column(Boolean, default=False)
    avg_rtt_ms = Column(Float, nullable=True)
    from_asn = Column(String(32), nullable=True)

    session = relationship("ListenerSession", back_populates="protocol_results")


async def init_db() -> None:
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    async with async_session_factory() as session:
        yield session
