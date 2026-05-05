"""
Schema round-trip tests against a real Postgres.

Pin three properties of the schema:

  * ``init_db`` creates all 4 tables on a fresh DB.
  * Unique constraints fire — ``uq_test_results_run_file_test_target``
    and ``uq_listener_sessions_run_file`` (sync-api integrity guards
    against double-import races).
  * Cascade delete works — removing a TestRun drops all its child
    TestResult, ListenerSession, and ProtocolResult rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError


@pytest.mark.integration
class TestSchema:
    async def test_all_four_tables_exist(self, db_session: Any) -> None:
        from sync_api.db import engine

        async with engine.connect() as conn:
            tables = await conn.run_sync(
                lambda sync_conn: sorted(inspect(sync_conn).get_table_names())
            )
        for required in (
            "test_runs",
            "test_results",
            "listener_sessions",
            "protocol_results",
        ):
            assert required in tables, f"missing table: {required}"

    async def test_indexes_present(self, db_session: Any) -> None:
        from sync_api.db import engine

        async with engine.connect() as conn:
            ix = await conn.run_sync(
                lambda sync_conn: [
                    i["name"] for i in inspect(sync_conn).get_indexes("test_results")
                ]
            )
        assert "ix_test_results_run_file" in ix


@pytest.mark.integration
class TestUniqueConstraints:
    async def test_test_results_uniqueness(self, db_session: Any) -> None:
        # Insert one row, then a second with identical (test_run_id,
        # report_file, test, target) — must raise IntegrityError.
        from sync_api.db import TestResult, TestRun

        run = TestRun(test_id="vu-1", created_at=datetime.now(UTC))
        db_session.add(run)
        await db_session.flush()

        db_session.add(
            TestResult(
                test_run_id=run.id,
                report_file="server-solo-x.json",
                test="dns_meduza_io_system",
                category="dns",
                subcategory="dns",
                target="meduza.io",
                verdict="OK",
            )
        )
        await db_session.flush()

        db_session.add(
            TestResult(
                test_run_id=run.id,
                report_file="server-solo-x.json",
                test="dns_meduza_io_system",
                category="dns",
                subcategory="dns",
                target="meduza.io",
                verdict="BLOCKED",  # value differs, but key tuple is the same
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()

    async def test_listener_sessions_uniqueness(self, db_session: Any) -> None:
        from sync_api.db import ListenerSession, TestRun

        run = TestRun(test_id="vu-2", created_at=datetime.now(UTC))
        db_session.add(run)
        await db_session.flush()

        db_session.add(
            ListenerSession(
                test_run_id=run.id,
                session_id="sess-1",
                report_file="server-listener-1.json",
            )
        )
        await db_session.flush()
        db_session.add(
            ListenerSession(
                test_run_id=run.id,
                session_id="sess-2",  # different session_id, same report_file
                report_file="server-listener-1.json",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()

    async def test_test_run_unique_test_id(self, db_session: Any) -> None:
        from sync_api.db import TestRun

        db_session.add(TestRun(test_id="vu-3", created_at=datetime.now(UTC)))
        await db_session.flush()
        db_session.add(TestRun(test_id="vu-3", created_at=datetime.now(UTC)))
        with pytest.raises(IntegrityError):
            await db_session.flush()
        await db_session.rollback()


@pytest.mark.integration
class TestCascadeDelete:
    async def test_delete_test_run_drops_children(self, db_session: Any) -> None:
        from sync_api.db import (
            ListenerSession,
            ProtocolResult,
            TestResult,
            TestRun,
        )

        run = TestRun(test_id="cas-1", created_at=datetime.now(UTC))
        db_session.add(run)
        await db_session.flush()

        # One child of each kind.
        db_session.add(
            TestResult(
                test_run_id=run.id,
                report_file="rf.json",
                test="t",
                category="c",
                subcategory="s",
                target="x",
                verdict="OK",
            )
        )
        sess = ListenerSession(
            test_run_id=run.id,
            session_id="sid",
            report_file="lr.json",
        )
        db_session.add(sess)
        await db_session.flush()
        db_session.add(
            ProtocolResult(
                session_id=sess.id,
                protocol="wireguard",
                verdict="OK",
            )
        )
        await db_session.commit()

        # Sanity — children present before delete.
        assert len((await db_session.execute(select(TestResult))).scalars().all()) == 1
        assert len((await db_session.execute(select(ListenerSession))).scalars().all()) == 1
        assert len((await db_session.execute(select(ProtocolResult))).scalars().all()) == 1

        # Delete via ORM so SQLAlchemy issues the cascade.
        await db_session.delete(run)
        await db_session.commit()

        assert (await db_session.execute(select(TestRun))).first() is None
        assert (await db_session.execute(select(TestResult))).first() is None
        assert (await db_session.execute(select(ListenerSession))).first() is None
        assert (await db_session.execute(select(ProtocolResult))).first() is None

    async def test_delete_session_drops_protocol_results_only(self, db_session: Any) -> None:
        # Removing a single ListenerSession must NOT cascade up to its
        # parent TestRun — only down to ProtocolResult.
        from sync_api.db import (
            ListenerSession,
            ProtocolResult,
            TestRun,
        )

        run = TestRun(test_id="cas-2", created_at=datetime.now(UTC))
        db_session.add(run)
        await db_session.flush()
        sess = ListenerSession(test_run_id=run.id, session_id="s", report_file="lr.json")
        db_session.add(sess)
        await db_session.flush()
        db_session.add(ProtocolResult(session_id=sess.id, protocol="wireguard", verdict="OK"))
        await db_session.commit()

        await db_session.delete(sess)
        await db_session.commit()

        assert (await db_session.execute(select(TestRun))).first() is not None
        assert (await db_session.execute(select(ProtocolResult))).first() is None
