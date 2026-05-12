"""
Tests for the ``_import_once`` pipeline.

This is where disk-side report files become DB rows. Cover:
  * Parsing solo + listener reports → TestResult / ListenerSession /
    ProtocolResult rows (round-trip via the pipeline, not direct ORM).
  * UPSERT-by-session-id behaviour: a NEWER listener report replaces
    an older one for the same SID; an OLDER one is skipped.
  * Path-traversal guard: a test_id directory with a name that fails
    the SAFE_ID regex must not surface as a row.
  * Symlink rejection: symlinked test_id directory or report file is
    skipped at enumeration time.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select


def _solo_payload(*, test_id: str = "vu-1") -> dict:
    return {
        "report_type": "solo",
        "test_id": test_id,
        "generated_at": "2026-05-04T12:00:00Z",
        "results": [
            {
                "test": "dns_meduza_io_system",
                "category": "dns",
                "target": "meduza.io",
                "verdict": "OK",
                "rtt_ms": 11.0,
                "timestamp": "2026-05-04T12:00:01Z",
            },
            {
                "test": "tls_meduza_io_sni_blocked",
                "category": "tls",
                "target": "meduza.io",
                "verdict": "BLOCKED",
                "rtt_ms": 5.0,
                "timestamp": "2026-05-04T12:00:02Z",
            },
        ],
    }


def _listener_payload(
    *,
    session_id: str = "client-mts-msk",
    started_at: str = "2026-05-04T13:00:00Z",
) -> dict:
    return {
        "test_id": "vu-1",
        "session_id": session_id,
        "listener_started_at": started_at,
        "client_connected": True,
        "client": {"location": {"country_code": "RU"}},
        "results": {
            "wireguard": {
                "verdict": "OK",
                "handshake_count": 1,
                "data_transfer_ok": True,
            },
            "openvpn": {"verdict": "BLOCKED", "handshake_count": 0},
        },
    }


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Create a fake workspace with a reports/ subtree and pin
    ``main.WORKSPACE`` + ``_is_file_stable`` so the importer doesn't
    sleep 1 second per file.
    """
    from sync_api import main as main_mod

    monkeypatch.setattr(main_mod, "WORKSPACE", tmp_path)
    # Bypass the 1s settle wait — irrelevant in tests.
    monkeypatch.setattr(main_mod, "_is_file_stable", lambda _p, **_kw: True)
    (tmp_path / "reports").mkdir()
    yield tmp_path


def _write_report(workspace: Path, test_id: str, name: str, payload: dict) -> Path:
    test_dir = workspace / "reports" / test_id
    test_dir.mkdir(exist_ok=True)
    path = test_dir / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.integration
class TestImportOnce:
    async def test_solo_report_creates_run_and_results(
        self, workspace: Path, db_session: Any
    ) -> None:
        from sync_api.db import TestResult, TestRun
        from sync_api.main import _import_once

        _write_report(workspace, "vu-1", "server-solo-2026-05-04.json", _solo_payload())

        await _import_once()

        runs = (await db_session.execute(select(TestRun))).scalars().all()
        assert len(runs) == 1
        assert runs[0].test_id == "vu-1"

        results = (await db_session.execute(select(TestResult))).scalars().all()
        assert len(results) == 2
        verdicts = {r.verdict for r in results}
        assert verdicts == {"OK", "BLOCKED"}
        # subcategory is auto-derived from test names.
        subs = {r.subcategory for r in results}
        assert subs == {"dns", "tls_sni_blocked"}

    async def test_listener_report_creates_session_and_proto_rows(
        self, workspace: Path, db_session: Any
    ) -> None:
        from sync_api.db import ListenerSession, ProtocolResult
        from sync_api.main import _import_once

        # A solo report is required first because score recompute
        # needs at least one solo result; but the import_once pipeline
        # actually doesn't enforce that — listener-only run should work.
        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-msk-2026-05-04T13-00-00Z.json",
            _listener_payload(),
        )
        await _import_once()

        sessions = (await db_session.execute(select(ListenerSession))).scalars().all()
        assert len(sessions) == 1
        assert sessions[0].session_id == "client-mts-msk"
        assert sessions[0].client_connected is True

        protos = (await db_session.execute(select(ProtocolResult))).scalars().all()
        assert {p.protocol for p in protos} == {"wireguard", "openvpn"}

    async def test_solo_plus_listener_recomputes_scores(
        self, workspace: Path, db_session: Any
    ) -> None:
        # Both files present → after _import_once, the run's scores
        # should reflect the listener's protocol reachability (not the
        # neutral 0.5 default that solo-only would produce).
        from sync_api.db import TestRun
        from sync_api.main import _import_once

        _write_report(workspace, "vu-1", "server-solo-1.json", _solo_payload())
        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-msk-2026-05-04T13-00-00Z.json",
            _listener_payload(),
        )
        await _import_once()

        run = (
            await db_session.execute(select(TestRun).where(TestRun.test_id == "vu-1"))
        ).scalar_one()
        # entry_score is computed; with default cfg + this listener
        # output it must be non-zero (1 OK, 1 BLOCKED → 0.5 reach).
        assert run.entry_score is not None
        assert run.entry_score > 0
        # listener_session_count must reflect the one listener report
        # we wrote — lets dashboard panels distinguish full from partial
        # runs without re-deriving the signal at query time.
        assert run.listener_session_count == 1
        # detected_techniques surfaces TLS_HANDSHAKE_FAILURE-style entries
        # only when method is set on the result; this fixture has no
        # method, so the field stays empty.
        assert run.detected_techniques in (None, [])

    async def test_dedup_does_not_reimport(self, workspace: Path, db_session: Any) -> None:
        # Run twice with the same files — the dedup query must skip
        # the second pass entirely.
        from sync_api.db import TestResult
        from sync_api.main import _import_once

        _write_report(workspace, "vu-1", "server-solo-1.json", _solo_payload())
        await _import_once()
        first = len((await db_session.execute(select(TestResult))).scalars().all())

        await _import_once()  # second pass — no new files
        second = len((await db_session.execute(select(TestResult))).scalars().all())
        assert first == second

    async def test_unsafe_test_id_dropped(self, workspace: Path, db_session: Any) -> None:
        # SAFE_ID_RE only allows ``[A-Za-z0-9_.-]`` so spaces, slashes,
        # NULLs, etc. are rejected. ``_list_report_files`` filters by
        # this regex. Use a space (the simplest non-regex char that
        # is still a legal filesystem name on Linux).
        from sync_api.db import TestRun
        from sync_api.main import _import_once

        bad_dir = workspace / "reports" / "bad name"
        bad_dir.mkdir()
        (bad_dir / "server-solo-x.json").write_text(
            json.dumps(_solo_payload(test_id="bad name")), encoding="utf-8"
        )
        await _import_once()
        assert (await db_session.execute(select(TestRun))).first() is None

    async def test_symlinked_directory_skipped(self, workspace: Path, db_session: Any) -> None:
        # A symlinked test_id dir must not be followed.
        from sync_api.db import TestRun
        from sync_api.main import _import_once

        real = workspace / "elsewhere" / "vu-real"
        real.mkdir(parents=True)
        (real / "server-solo-x.json").write_text(json.dumps(_solo_payload()), encoding="utf-8")
        link = workspace / "reports" / "vu-1"
        link.symlink_to(real)

        await _import_once()
        assert (await db_session.execute(select(TestRun))).first() is None


@pytest.mark.integration
class TestUpsertBySessionId:
    """The freshness rule on listener reports: same (run, SID), newer
    report_file replaces older; older report_file is silently skipped."""

    async def test_newer_replaces_older(self, workspace: Path, db_session: Any) -> None:
        from sync_api.db import ListenerSession, ProtocolResult
        from sync_api.main import _import_once

        # Older report
        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-2026-05-04T10-00-00Z.json",
            _listener_payload(started_at="2026-05-04T10:00:00Z"),
        )
        await _import_once()
        first = (await db_session.execute(select(ListenerSession))).scalars().all()
        assert len(first) == 1
        old_file = first[0].report_file

        # Newer report — same SID, lexicographically later filename.
        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-2026-05-04T11-00-00Z.json",
            _listener_payload(started_at="2026-05-04T11:00:00Z"),
        )
        await _import_once()
        sessions = (await db_session.execute(select(ListenerSession))).scalars().all()
        assert len(sessions) == 1, "expected exactly one row after replacement"
        assert sessions[0].report_file > old_file

        # ProtocolResult cascade: the old row's children must be gone,
        # the new row's children must be present (count == 2).
        protos = (await db_session.execute(select(ProtocolResult))).scalars().all()
        assert len(protos) == 2

    async def test_older_skipped_when_newer_already_in_db(
        self, workspace: Path, db_session: Any
    ) -> None:
        # Insert the newer file first; importing an older file should
        # be a no-op (same SID, but report_file < existing.report_file).
        from sync_api.db import ListenerSession
        from sync_api.main import _import_once

        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-2026-05-04T11-00-00Z.json",
            _listener_payload(),
        )
        await _import_once()

        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-2026-05-04T09-00-00Z.json",
            _listener_payload(),
        )
        await _import_once()
        sessions = (await db_session.execute(select(ListenerSession))).scalars().all()
        assert len(sessions) == 1
        # The newer file (T11) survives in DB.
        assert "T11" in sessions[0].report_file


@pytest.mark.integration
class TestReconciliation:
    """Workspace-is-source-of-truth: removing report files from disk must
    propagate to DB deletions on the next ``_import_once`` pass.

    Three reconciliation modes (in increasing scope):
      * file-level — one report removed, others remain
      * empty-folder — every JSON gone from the test_id dir
      * folder-removed — whole test_id directory gone
    Plus a safety guard: a missing ``reports/`` root must NOT trigger a
    mass-delete (we treat that as operator error, not intent).
    """

    async def test_deleted_solo_file_removes_db_rows(
        self, workspace: Path, db_session: Any
    ) -> None:
        from sync_api.db import TestResult
        from sync_api.main import _import_once

        path = _write_report(workspace, "vu-1", "server-solo-2026-05-04.json", _solo_payload())
        await _import_once()
        assert len((await db_session.execute(select(TestResult))).scalars().all()) == 2

        # Operator removed the file. After the next pass the rows must
        # be gone — the workspace is the source of truth.
        path.unlink()
        await _import_once()
        assert (await db_session.execute(select(TestResult))).first() is None

    async def test_deleted_listener_file_removes_session_and_cascades(
        self, workspace: Path, db_session: Any
    ) -> None:
        from sync_api.db import ListenerSession, ProtocolResult
        from sync_api.main import _import_once

        path = _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-2026-05-04T10-00-00Z.json",
            _listener_payload(),
        )
        await _import_once()
        assert len((await db_session.execute(select(ListenerSession))).scalars().all()) == 1
        assert len((await db_session.execute(select(ProtocolResult))).scalars().all()) == 2

        path.unlink()
        await _import_once()
        assert (await db_session.execute(select(ListenerSession))).first() is None
        # Cascade on ListenerSession.id → protocol_results.session_id.
        assert (await db_session.execute(select(ProtocolResult))).first() is None

    async def test_empty_folder_drops_test_run(self, workspace: Path, db_session: Any) -> None:
        from sync_api.db import TestRun
        from sync_api.main import _import_once

        path = _write_report(workspace, "vu-1", "server-solo-2026-05-04.json", _solo_payload())
        await _import_once()
        assert len((await db_session.execute(select(TestRun))).scalars().all()) == 1

        # Remove all reports but keep the (now empty) directory. The
        # workspace says "no data here" — Grafana must agree.
        path.unlink()
        assert (workspace / "reports" / "vu-1").exists()
        await _import_once()
        assert (await db_session.execute(select(TestRun))).first() is None

    async def test_removed_folder_drops_test_run(self, workspace: Path, db_session: Any) -> None:
        import shutil

        from sync_api.db import TestRun
        from sync_api.main import _import_once

        _write_report(workspace, "vu-1", "server-solo-2026-05-04.json", _solo_payload())
        _write_report(workspace, "vu-2", "server-solo-2026-05-04.json", _solo_payload())
        await _import_once()
        assert len((await db_session.execute(select(TestRun))).scalars().all()) == 2

        # rm -rf reports/vu-1 — top-level reconciliation must drop the row.
        shutil.rmtree(workspace / "reports" / "vu-1")
        await _import_once()
        rows = (await db_session.execute(select(TestRun))).scalars().all()
        assert len(rows) == 1
        assert rows[0].test_id == "vu-2"

    async def test_partial_solo_delete_clears_scores(
        self, workspace: Path, db_session: Any
    ) -> None:
        """If solo is removed but listener stays, scores must be cleared.

        Otherwise the run shows stale ``entry_score`` etc. computed from
        the deleted solo data — a worse UX than the "no data" state."""
        from sync_api.db import TestRun
        from sync_api.main import _import_once

        solo_path = _write_report(workspace, "vu-1", "server-solo-1.json", _solo_payload())
        _write_report(
            workspace,
            "vu-1",
            "server-listener-mts-2026-05-04T10-00-00Z.json",
            _listener_payload(),
        )
        await _import_once()
        run = (
            await db_session.execute(select(TestRun).where(TestRun.test_id == "vu-1"))
        ).scalar_one()
        assert run.entry_score is not None

        solo_path.unlink()
        await _import_once()
        await db_session.refresh(run)
        assert run.entry_score is None
        assert run.overall_score is None
        assert run.listener_session_count == 0

    async def test_missing_reports_root_is_safe(self, workspace: Path, db_session: Any) -> None:
        """Safety guard: a missing ``reports/`` directory must NOT trigger
        a mass-delete. Operator might have unmounted the volume by mistake.
        """
        import shutil

        from sync_api.db import TestRun
        from sync_api.main import _import_once

        _write_report(workspace, "vu-1", "server-solo-1.json", _solo_payload())
        await _import_once()
        assert len((await db_session.execute(select(TestRun))).scalars().all()) == 1

        # Remove the entire reports/ root. Importer must short-circuit.
        shutil.rmtree(workspace / "reports")
        await _import_once()
        # The row must still be there — workspace gone ≠ workspace empty.
        assert len((await db_session.execute(select(TestRun))).scalars().all()) == 1
