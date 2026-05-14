"""
sync_api/main.py — FastAPI service for Grafana data sync.

Endpoints:
  GET  /health             — liveness check
  GET  /test-runs          — list all test_ids with latest scores
  GET  /test-runs/{id}     — single test run details
  GET  /results/{id}       — paginated test results for a test_id
  GET  /protocols/{id}     — protocol reachability matrix for a test_id

Update flow: an operator runs ``git pull`` on the workspace manually.
A background task scans the reports tree every IMPORT_INTERVAL seconds
and imports any new .json reports into Postgres. There is no HTTP
trigger and no Grafana button — pulling is fast enough to do by hand.

Grafana connects to Postgres directly via the Postgres datasource plugin.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from censprobe_core.config import load_config
from censprobe_core.models import (
    ListenerReport as CoreListenerReport,
)
from censprobe_core.models import (
    TestResult as CoreTestResult,
)
from censprobe_core.scoring import compute_scores
from censprobe_core.utils import SAFE_ID_RE
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi import Path as PathParam
from sqlalchemy import delete, distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from sync_api.db import (
    ListenerSession,
    ProtocolResult,
    TestResult,
    TestRun,
    async_session_factory,
    get_session,
    init_db,
)
from sync_api.parser import (
    is_listener_report,
    is_solo_report,
    load_json,
    parse_listener_report,
    parse_solo_report,
)

# Annotated dependency / query / path aliases. Sonar S8410 prefers
# ``Annotated[T, Depends(...)]`` over the legacy positional-default form;
# defining each alias once keeps the endpoint signatures short.
SessionDep = Annotated[AsyncSession, Depends(get_session)]
OptionalCategoryQuery = Annotated[str | None, Query()]
OptionalVerdictQuery = Annotated[str | None, Query()]
LimitQuery = Annotated[int, Query(ge=1, le=2000)]
OffsetQuery = Annotated[int, Query(ge=0)]
# Mirror of probe-core's SAFE_ID_RE — keep the producers (listener / solo
# CLI ``--test-id``) and the API consumers in lockstep so anything that
# would slip past the producer-side validator can't sneak in here as a
# path-traversal-looking string in logs / responses. FastAPI rejects
# non-matching values with 422 before the handler runs, so no SQL or
# disk-path code ever sees a malformed ID.
TestIdPath = Annotated[str, PathParam(pattern=r"^[A-Za-z0-9_.-]{1,64}$")]

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Single source of truth for the API/version metadata. Used in both the FastAPI
# constructor and /health, and surfaced in pyproject.toml. Bumping here is the
# only change required to keep them in lockstep.
SERVICE_VERSION = "0.5.0"

WORKSPACE = Path("/workspace")
# Single source of truth: .env (committed) + docker-compose env injection.
# No code-side fallback — a missing key surfaces as an explicit KeyError
# at startup rather than a silent "60s by accident" deployment.
IMPORT_INTERVAL_SEC = float(os.environ["CENSPROBE_IMPORT_INTERVAL_SEC"])

# No HTTP-level authentication. sync-api is bound to 127.0.0.1:8080
# inside ``docker-compose.yml`` (loopback only — external network
# cannot reach it), the only in-cluster Grafana consumer reads via
# the Postgres datasource (NOT this HTTP API), and the data exposed
# is read-only network-measurement results with no credentials or
# PII. The single-tenant deployment model assumes the operator owns
# the host. If you ever need to expose port 8080 beyond loopback,
# put a reverse proxy with auth in front of it — the API itself
# is not designed to face the internet.


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize DB tables and start the background importer."""
    # Load censprobe.yaml at startup so ``compute_scores`` (called per
    # imported run) can read ScoringConfig weights without raising
    # "Config not loaded" — without this, every TestRun's score columns
    # end up NULL and every score-driven dashboard panel renders empty.
    # The config file is the same one solo/listener/client read; sync-api
    # mounts ./:/workspace so the on-disk path matches.
    load_config(WORKSPACE)
    await init_db()
    logger.info("DB tables initialized")
    importer_task = asyncio.create_task(_import_loop())
    try:
        yield
    finally:
        importer_task.cancel()
        # We cancelled the inner task ourselves; suppress its CancelledError.
        # ``contextlib.suppress`` instead of try/except so Sonar S7497
        # doesn't flag this as missing a re-raise.
        with contextlib.suppress(asyncio.CancelledError):
            await importer_task


app = FastAPI(
    title="censprobe-sync-api",
    version=SERVICE_VERSION,
    description="Sync censprobe git reports into Postgres for Grafana",
    lifespan=lifespan,
)
# No CORS middleware: sync-api isn't called from a browser. Grafana
# reaches censprobe data via its Postgres datasource (back-end → DB,
# no browser involvement), and the HTTP endpoints below are for the
# same-host operator's ``curl`` / future tooling. Adding ``Access-
# Control-Allow-Origin`` headers for a non-existent cross-origin
# consumer would only obscure the real access pattern.


# Health


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": SERVICE_VERSION, "workspace": str(WORKSPACE)}


# Background importer — scans /workspace/reports and ingests new .json files.


async def _import_loop() -> None:
    """Periodically scan the reports tree and import any new files."""
    logger.info("Background importer started (every %.0fs)", IMPORT_INTERVAL_SEC)
    while True:
        try:
            await _import_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Background importer iteration failed")
        await asyncio.sleep(IMPORT_INTERVAL_SEC)


def _list_report_files(reports_root: Path) -> list[tuple[str, Path, list[Path]]]:
    """Enumerate (test_id, meta_path, [report_files]) tuples on disk.

    Refuses to descend into symlinked directories or load symlinked
    files — see parser.load_json. The reports tree is whatever an
    operator ``git pull``s; in a multi-contributor workflow a malicious
    PR can ship a symlink, and this importer must not follow it.

    A test_id directory is only kept if its name passes the same
    [A-Za-z0-9_.-] guard the producers enforce — which prevents a stray
    "../something" entry from materialising as a Postgres test_id.
    """
    out: list[tuple[str, Path, list[Path]]] = []
    if not reports_root.exists():
        return out
    for test_dir in sorted(reports_root.iterdir()):
        if test_dir.is_symlink() or not test_dir.is_dir():
            continue
        # Mirror the producer-side path-traversal guard.
        if not SAFE_ID_RE.match(test_dir.name):
            continue
        # Filter symlinks at file enumeration time — load_json checks
        # again on read but doing it here keeps the work list clean.
        report_files = sorted(p for p in test_dir.glob("*.json") if not p.is_symlink())
        out.append((test_dir.name, test_dir / "meta.yaml", report_files))
    return out


def _is_file_stable(path: Path, settle_sec: float = 1.0) -> bool:
    """Return True iff `path`'s mtime+size are unchanged after `settle_sec`.

    Solo and listener write reports with a single ``write_text`` call,
    which is atomic at the filesystem level. But on a workspace that's
    being ``git pull``ed concurrently, the importer could observe a file
    mid-write (git uses staged-rename for tracked files but the
    intermediate state can still leak through specific filesystems). A
    valid-but-truncated JSON would otherwise be imported as partial
    data, then dedup-filtered on the next pass — silently undercounting
    rows. Stat → wait → re-stat catches that race.
    """
    try:
        s1 = path.stat()
    except OSError:
        return False
    time.sleep(settle_sec)
    try:
        s2 = path.stat()
    except OSError:
        return False
    return s1.st_size == s2.st_size and s1.st_mtime == s2.st_mtime


async def _fetch_imported_filenames(
    session: AsyncSession,
    run: TestRun,
) -> tuple[set[str], set[str]]:
    """Return ``(test_result_filenames, listener_session_filenames)`` already in DB."""
    imported_results = {
        fn
        for (fn,) in (
            await session.execute(
                select(distinct(TestResult.report_file)).where(TestResult.test_run_id == run.id)
            )
        ).all()
    }
    imported_sessions = {
        fn
        for (fn,) in (
            await session.execute(
                select(ListenerSession.report_file).where(ListenerSession.test_run_id == run.id)
            )
        ).all()
    }
    return imported_results, imported_sessions


async def _try_import_one_file(
    session: AsyncSession,
    run: TestRun,
    report_file: Path,
) -> bool:
    """Import a single file; return True iff anything was added.

    Wraps the per-file try/except + savepoint so :func:`_import_once`
    stays under the cognitive-complexity cap.
    """
    fn = report_file.name
    try:
        async with session.begin_nested():
            if is_solo_report(fn):
                n_r, _ = await _import_solo_report(session, run, report_file)
                return bool(n_r)
            if is_listener_report(fn):
                n_s = await _import_listener_report(session, run, report_file)
                return bool(n_s)
    except Exception:
        # ``logger.exception`` includes the traceback automatically —
        # no need to pass the exception value through ``%s`` (S8572).
        logger.exception("Error importing %s", fn)
    return False


async def _recompute_scores_if_touched(
    session: AsyncSession,
    run: TestRun,
    test_id: str,
    report_files: list[Path],
    touched: bool,
) -> None:
    """If anything was added, re-blend solo + listener scores onto ``run``.

    No savepoint wrap: the body only does file I/O (in a thread) plus
    in-memory attribute writes on ``run``. There are no DB statements
    here whose effect would need rolling back. If ``_apply_scores``
    raises mid-way the outer ``session.refresh(run)`` re-reads the
    server-side state so a partial mutation can't sneak into the
    outer commit.
    """
    if not touched:
        return
    try:
        loaded = await asyncio.to_thread(_load_reports_for_scoring, report_files)
        _apply_scores(run, *loaded)
    except Exception as e:
        logger.warning("score recompute failed for %s: %s", test_id, e)
        await session.refresh(run)


async def _delete_orphaned_files(
    session: AsyncSession,
    run: TestRun,
    orphaned_results: set[str],
    orphaned_sessions: set[str],
) -> int:
    """Delete DB rows for report files no longer on disk.

    Returns the total number of report-file names removed (sum across
    ``test_results`` and ``listener_sessions``). The caller uses this
    to decide whether to recompute scores — same trigger as a successful
    import.
    """
    deleted = 0
    if orphaned_results:
        await session.execute(
            delete(TestResult).where(
                TestResult.test_run_id == run.id,
                TestResult.report_file.in_(orphaned_results),
            )
        )
        deleted += len(orphaned_results)
        logger.info(
            "Removed %d solo report file(s) from %r: %s",
            len(orphaned_results),
            run.test_id,
            sorted(orphaned_results),
        )
    if orphaned_sessions:
        # Cascade-delete on ListenerSession clears ProtocolResult rows.
        await session.execute(
            delete(ListenerSession).where(
                ListenerSession.test_run_id == run.id,
                ListenerSession.report_file.in_(orphaned_sessions),
            )
        )
        deleted += len(orphaned_sessions)
        logger.info(
            "Removed %d listener report file(s) from %r: %s",
            len(orphaned_sessions),
            run.test_id,
            sorted(orphaned_sessions),
        )
    if deleted:
        # Flush so subsequent queries in the same session see the
        # deletions (the per-test-dir dedup set used the pre-delete
        # snapshot, and the score recompute reads from disk anyway).
        await session.flush()
    return deleted


async def _import_one_test_dir(
    session: AsyncSession,
    test_id: str,
    meta_path: Path,
    report_files: list[Path],
) -> None:
    """Import all new files for one test_id and rescore the run if touched.

    Also acts as the per-test_id reconciliation step: report files that
    were once imported but have since been removed from the workspace
    are deleted from the DB. An empty directory (or one with only
    ``meta.yaml``) drops the entire ``TestRun`` row — mirrors the
    dashboard provisioning's ``disableDeletion: false`` so the workspace
    stays the single source of truth for what Grafana renders.
    """
    if not report_files:
        # No report files on disk → ensure nothing for this test_id lingers
        # in the DB. Cascade clears TestResult / ListenerSession /
        # ProtocolResult rows in one shot. No-op when the TestRun doesn't
        # exist (delete-where on a missing row is silent).
        await session.execute(delete(TestRun).where(TestRun.test_id == test_id))
        return

    try:
        async with session.begin_nested():
            run = await _get_or_create_test_run(session, test_id, meta_path)
    except Exception:
        # ``logger.exception`` carries the traceback for free (S8572).
        logger.exception("Could not get/create test_run %s", test_id)
        return
    if run is None:
        return

    imported_results, imported_sessions = await _fetch_imported_filenames(session, run)

    on_disk_filenames = {p.name for p in report_files}
    orphaned_results = imported_results - on_disk_filenames
    orphaned_sessions = imported_sessions - on_disk_filenames
    deleted = await _delete_orphaned_files(session, run, orphaned_results, orphaned_sessions)
    # A reconciliation deletion is a state change just like a new import —
    # the score recompute below must re-read the post-delete world.
    run_touched = deleted > 0

    for report_file in report_files:
        fn = report_file.name
        if fn in imported_results or fn in imported_sessions:
            continue
        # Skip files that may still be mid-write. A valid-but-truncated
        # JSON would otherwise be imported partially, then the dedup
        # query on the next pass would skip it (the filename is now in
        # ``imported_results``), silently under-counting rows for this run.
        if not await asyncio.to_thread(_is_file_stable, report_file):
            logger.debug("File %s still changing; will retry next cycle", fn)
            continue
        if await _try_import_one_file(session, run, report_file):
            run_touched = True

    # Solo's own scores were computed before any listener report was on
    # disk, so protocol reachability sat at the neutral 0.5 default.
    # Re-blend solo + listener whenever a side adds new data — or when a
    # reconciliation pass removed stale data.
    await _recompute_scores_if_touched(session, run, test_id, report_files, run_touched)


async def _reconcile_missing_test_runs(session: AsyncSession, on_disk_test_ids: set[str]) -> int:
    """Delete TestRun rows whose source directory is gone from the workspace.

    Whole-folder cleanup: ``rm -rf reports/<test_id>/`` → cascade clears
    ``test_results`` / ``listener_sessions`` / ``protocol_results``.
    Returns the number of TestRun rows deleted.
    """
    rows = (await session.execute(select(TestRun))).scalars().all()
    deleted = 0
    for run in rows:
        if run.test_id in on_disk_test_ids:
            continue
        logger.info("Removing TestRun %r (source directory gone)", run.test_id)
        await session.delete(run)
        deleted += 1
    if deleted:
        await session.flush()
    return deleted


async def _import_once() -> None:
    """One pass over the reports directory: import new files, reconcile
    deletions, and rescore touched runs.

    Workspace is the single source of truth. Three reconciliation
    triggers (in increasing severity):

      * a report file was removed from a test_id directory → that row(s)
        deleted from DB; scores recomputed from the remaining files.
      * a test_id directory is now empty (no JSON) → the TestRun and all
        its children dropped.
      * a test_id directory is gone entirely → handled at the top-level
        via ``_reconcile_missing_test_runs``.

    Safety guard: if ``reports/`` itself is missing (e.g. workspace
    bind-mount stale or operator moved the directory), do nothing. We
    only reconcile against an *intentionally* empty workspace, not a
    *missing* one.
    """
    reports_root = WORKSPACE / "reports"
    if not reports_root.exists():
        return

    test_dirs = await asyncio.to_thread(_list_report_files, reports_root)
    on_disk_test_ids = {test_id for test_id, _, _ in test_dirs}

    async with async_session_factory() as session:
        for test_id, meta_path, report_files in test_dirs:
            await _import_one_test_dir(session, test_id, meta_path, report_files)
        await _reconcile_missing_test_runs(session, on_disk_test_ids)
        await session.commit()


def _apply_scores(
    run: TestRun,
    solo_results: list[CoreTestResult],
    listener_reports: list[CoreListenerReport],
) -> None:
    """Rebuild server scores and write them onto `run`."""
    if not solo_results:
        # No solo data left for this run — clear derived score columns so
        # stale values from a previous import don't survive after the
        # source files are removed from the workspace. The
        # reconciliation path in ``_import_one_test_dir`` can land here
        # if every solo report was deleted while listener reports remain.
        # ``listener_session_count`` is NOT derived from solo data — it's
        # the count of listener_sessions joined to this run — so keep it
        # in sync even when solo data is absent.
        run.entry_score = None
        run.exit_score = None
        run.relay_score = None
        run.overall_score = None
        run.listener_session_count = len(listener_reports)
        run.throttling_detected = False
        run.dns_integrity = None
        run.tls_integrity = None
        run.telegram_health = None
        run.detected_techniques = None
        run.recommended_protocols = None
        return
    scores = compute_scores(
        solo_results=solo_results,
        listener_reports=listener_reports or None,
    )
    run.entry_score = scores.entry_score
    run.exit_score = scores.exit_score
    run.relay_score = scores.relay_score
    run.overall_score = scores.overall
    run.listener_session_count = scores.listener_session_count
    run.throttling_detected = scores.throttling_detected
    run.dns_integrity = scores.dns_integrity
    run.tls_integrity = scores.tls_integrity
    run.telegram_health = scores.telegram_health
    run.detected_techniques = (
        list(scores.detected_techniques) if scores.detected_techniques else None
    )
    run.recommended_protocols = (
        list(scores.recommended_protocols) if scores.recommended_protocols else None
    )


def _load_latest_solo_results(solo_files: list[Path]) -> list[CoreTestResult]:
    """Pydantic-validate the rows in the latest solo file, skipping drifted ones."""
    if not solo_files:
        return []
    raw = load_json(solo_files[-1])
    if not isinstance(raw, dict):
        return []
    raw_results = raw.get("results", []) or []
    if not isinstance(raw_results, list):
        return []
    out: list[CoreTestResult] = []
    for r in raw_results:
        try:
            out.append(CoreTestResult.model_validate(r))
        except Exception:  # noqa: S112  # NOSONAR — skip schema-drifted rows, keep importing the rest
            continue
    return out


def _load_listener_reports(listener_files: list[Path]) -> list[CoreListenerReport]:
    """Pydantic-validate listener reports, skipping any that fail validation."""
    out: list[CoreListenerReport] = []
    for path in listener_files:
        raw = load_json(path)
        if not isinstance(raw, dict):
            continue
        try:
            out.append(CoreListenerReport.model_validate(raw))
        except Exception:  # noqa: S112  # NOSONAR — skip schema-drifted reports, keep importing the rest
            continue
    return out


def _load_reports_for_scoring(
    report_files: list[Path],
) -> tuple[list[CoreTestResult], list[CoreListenerReport]]:
    """Load the latest solo report + all listener reports as core pydantic models."""
    solo_files = sorted(
        (p for p in report_files if is_solo_report(p.name)),
        key=lambda p: p.name,
    )
    listener_files = sorted(
        (p for p in report_files if is_listener_report(p.name)),
        key=lambda p: p.name,
    )
    return _load_latest_solo_results(solo_files), _load_listener_reports(listener_files)


# Test runs


_NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "test_id not found"},
}


@app.get("/test-runs")
async def list_test_runs(session: SessionDep) -> list[dict[str, Any]]:
    """List all test_ids with their latest scores."""
    rows = await session.execute(select(TestRun).order_by(TestRun.created_at.desc()))
    return [_run_to_dict(r) for r in rows.scalars().all()]


@app.get("/test-runs/{test_id}", responses=_NOT_FOUND_RESPONSES)
async def get_test_run(test_id: TestIdPath, session: SessionDep) -> dict[str, Any]:
    run = await _fetch_run(session, test_id)
    return _run_to_dict(run)


# Results


@app.get("/results/{test_id}", responses=_NOT_FOUND_RESPONSES)
async def get_results(
    test_id: TestIdPath,
    session: SessionDep,
    category: OptionalCategoryQuery = None,
    verdict: OptionalVerdictQuery = None,
    limit: LimitQuery = 500,
    offset: OffsetQuery = 0,
) -> list[dict[str, Any]]:
    """Paginated test results for a test_id, optionally filtered by category or verdict."""
    run = await _fetch_run(session, test_id)
    q = select(TestResult).where(TestResult.test_run_id == run.id)
    if category:
        q = q.where(TestResult.category == category)
    if verdict:
        q = q.where(TestResult.verdict == verdict)
    q = q.order_by(TestResult.timestamp.desc()).limit(limit).offset(offset)
    rows = await session.execute(q)
    return [_result_to_dict(r) for r in rows.scalars().all()]


# Protocol reachability matrix


@app.get("/protocols/{test_id}", responses=_NOT_FOUND_RESPONSES)
async def get_protocol_matrix(test_id: TestIdPath, session: SessionDep) -> dict[str, Any]:
    """
    Returns protocol reachability matrix per session:
    {session_id: {protocol: verdict}}
    """
    run = await _fetch_run(session, test_id)
    q = select(ListenerSession).where(ListenerSession.test_run_id == run.id)
    sessions = (await session.execute(q)).scalars().all()

    matrix: dict[str, dict[str, str]] = {}
    for sess in sessions:
        q2 = select(ProtocolResult).where(ProtocolResult.session_id == sess.id)
        protos = (await session.execute(q2)).scalars().all()
        matrix[sess.session_id] = {p.protocol: p.verdict for p in protos}

    return {"test_id": test_id, "matrix": matrix}


# Internal helpers


def _read_meta_yaml(meta_path: Path) -> dict[str, Any]:
    """Blocking: read meta.yaml. Called via asyncio.to_thread."""
    if not meta_path.exists():
        return {}
    try:
        import yaml

        return yaml.safe_load(meta_path.read_text()) or {}
    except Exception:
        return {}


async def _get_or_create_test_run(
    session: AsyncSession, test_id: str, meta_path: Path
) -> TestRun | None:
    """Find or create a TestRun row for a test_id."""
    row = (
        await session.execute(select(TestRun).where(TestRun.test_id == test_id))
    ).scalar_one_or_none()
    if row:
        return row

    meta_data = await asyncio.to_thread(_read_meta_yaml, meta_path)

    server = meta_data.get("server") or {}
    # New schema: server.endpoint is a serialized EndpointMeta dict.
    # Stored verbatim in JSONB so Grafana can reach asn/company/datacenter
    # without flattening at this boundary. Host fields stay flat.
    endpoint = server.get("endpoint") if isinstance(server, dict) else None
    if not isinstance(endpoint, dict):
        endpoint = None

    run = TestRun(
        test_id=test_id,
        server_meta=endpoint,
        ipv6_available=bool(server.get("ipv6_available", False))
        if isinstance(server, dict)
        else False,
        kernel=server.get("kernel") if isinstance(server, dict) else None,
        distro=server.get("distro") if isinstance(server, dict) else None,
        created_at=datetime.now(tz=UTC),
    )
    session.add(run)
    await session.flush()
    return run


async def _import_solo_report(session: AsyncSession, run: TestRun, path: Path) -> tuple[int, bool]:
    """Import a solo report. Returns (n_results_added, is_new_run)."""
    _meta, results = await asyncio.to_thread(parse_solo_report, path)
    if not results:
        return 0, False

    for r in results:
        row = TestResult(test_run_id=run.id, **r)
        session.add(row)

    return len(results), True


async def _import_listener_report(session: AsyncSession, run: TestRun, path: Path) -> int:
    """Import a listener report. Returns number of sessions added."""
    sess_meta, proto_results = await asyncio.to_thread(parse_listener_report, path)
    if not sess_meta:
        return 0

    session_id = sess_meta.get("session_id", "")
    current_file = sess_meta.get("report_file", "") or path.name

    # UPSERT-by-session_id: a re-run of the listener with the same TID
    # and SID semantically replaces the previous attempt of "this client
    # network probing this server". Without this, both rows survive in
    # the DB and Grafana panel 04 shows duplicated tiles, while score
    # recompute averages the two attempts instead of taking the latest.
    #
    # Freshness comparator: prefer ``started_at`` (typed timestamp in DB
    # and in the new report), fall back to lexicographic filename compare
    # for legacy reports where one side lacks ``started_at``. Filename
    # compare only works because listener writes the timestamp suffix in
    # ISO-8601 fixed-width form (`...-2026-04-21T10-30-00Z.json`), which
    # sorts chronologically as plain ASCII — that's a producer-side
    # convention this importer must not silently depend on as the only
    # source of truth.
    if session_id:
        existing = (
            await session.execute(
                select(ListenerSession).where(
                    ListenerSession.test_run_id == run.id,
                    ListenerSession.session_id == session_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            new_started_at = sess_meta.get("started_at")
            if existing.started_at is not None and new_started_at is not None:
                # Typed-timestamp compare: robust against any filename
                # convention change on the producer side.
                existing_is_newer = existing.started_at >= new_started_at
            else:
                # Legacy fallback for reports missing ``started_at``.
                existing_is_newer = existing.report_file >= current_file
            if existing_is_newer:
                logger.info(
                    "Skipping %s: SID %r already represented by newer report %s",
                    current_file,
                    session_id,
                    existing.report_file,
                )
                return 0
            await session.execute(delete(ListenerSession).where(ListenerSession.id == existing.id))
            # Flush so the (test_run_id, report_file) UNIQUE constraint
            # sees the DELETE before the INSERT lands in the same batch.
            await session.flush()
            logger.info(
                "Replacing SID %r: %s ← %s",
                session_id,
                current_file,
                existing.report_file,
            )

    listener_sess = ListenerSession(
        test_run_id=run.id,
        session_id=session_id,
        report_file=current_file,
        started_at=sess_meta.get("started_at"),
        stopped_at=sess_meta.get("stopped_at"),
        duration_sec=sess_meta.get("duration_sec"),
        client_connected=bool(sess_meta.get("client_connected", False)),
        client_meta=sess_meta.get("client_meta"),
        is_mobile=bool(sess_meta.get("is_mobile", False)),
        is_whitelist=bool(sess_meta.get("is_whitelist", False)),
    )
    session.add(listener_sess)
    await session.flush()

    for pr in proto_results:
        row = ProtocolResult(session_id=listener_sess.id, **pr)
        session.add(row)

    return 1


async def _fetch_run(session: AsyncSession, test_id: str) -> TestRun:
    row = (
        await session.execute(select(TestRun).where(TestRun.test_id == test_id))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"test_id '{test_id}' not found")
    return row


def _run_to_dict(run: TestRun) -> dict[str, Any]:
    return {
        "test_id": run.test_id,
        "server_meta": run.server_meta,
        "ipv6_available": run.ipv6_available,
        "kernel": run.kernel,
        "distro": run.distro,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "scores": {
            "entry": run.entry_score,
            "exit": run.exit_score,
            "relay": run.relay_score,
            "overall": run.overall_score,
            # 0 ⇒ partial run (overall = mean(exit, relay) only, entry
            # axis is built on a neutral 0.5 fallback). Lets dashboards
            # render a "partial" badge without re-deriving the signal.
            "listener_session_count": run.listener_session_count,
        },
        "throttling_detected": run.throttling_detected,
        "dns_integrity": run.dns_integrity,
        "tls_integrity": run.tls_integrity,
        "telegram_health": run.telegram_health,
        "detected_techniques": list(run.detected_techniques or []),
        "recommended_protocols": list(run.recommended_protocols or []),
    }


def _result_to_dict(r: TestResult) -> dict[str, Any]:
    return {
        "test": r.test,
        "category": r.category,
        "subcategory": r.subcategory,
        "target": r.target,
        "verdict": r.verdict,
        "method": r.method,
        "confidence": r.confidence,
        "rtt_ms": r.rtt_ms,
        "elapsed_ms": r.elapsed_ms,
        "attempts": r.attempts,
        "notes": r.notes,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "source": r.source,
    }
