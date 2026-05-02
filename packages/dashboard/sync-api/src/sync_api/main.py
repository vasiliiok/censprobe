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
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from censprobe_core.models import (
    ListenerReport as CoreListenerReport,
    TestResult as CoreTestResult,
)
from censprobe_core.scoring import compute_scores
from censprobe_core.utils import SAFE_ID_RE
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

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Single source of truth for the API/version metadata. Used in both the FastAPI
# constructor and /health, and surfaced in pyproject.toml. Bumping here is the
# only change required to keep them in lockstep.
SERVICE_VERSION = "0.4.0"

WORKSPACE = Path("/workspace")
# Single source of truth: .env (committed) + docker-compose env injection.
# No code-side fallback — a missing key surfaces as an explicit KeyError
# at startup rather than a silent "60s by accident" deployment.
IMPORT_INTERVAL_SEC = float(os.environ["CENSPROBE_IMPORT_INTERVAL_SEC"])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize DB tables and start the background importer."""
    await init_db()
    logger.info("DB tables initialized")
    importer_task = asyncio.create_task(_import_loop())
    try:
        yield
    finally:
        importer_task.cancel()
        try:
            await importer_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="censprobe-sync-api",
    version=SERVICE_VERSION,
    description="Sync censprobe git reports into Postgres for Grafana",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": SERVICE_VERSION, "workspace": str(WORKSPACE)}


# ─────────────────────────────────────────────────────────────────────────────
# Background importer — scans /workspace/reports and ingests new .json files.
# ─────────────────────────────────────────────────────────────────────────────

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
        report_files = sorted(
            p for p in test_dir.glob("*.json") if not p.is_symlink()
        )
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


async def _import_once() -> None:
    """One pass over the reports directory: import new files and rescore touched runs."""
    reports_root = WORKSPACE / "reports"
    test_dirs = await asyncio.to_thread(_list_report_files, reports_root)
    if not test_dirs:
        return

    async with async_session_factory() as session:
        for test_id, meta_path, report_files in test_dirs:
            try:
                async with session.begin_nested():
                    run = await _get_or_create_test_run(session, test_id, meta_path)
            except Exception as e:
                logger.error("Could not get/create test_run %s: %s", test_id, e)
                continue
            if run is None:
                continue

            imported_results = {
                fn
                for (fn,) in (
                    await session.execute(
                        select(distinct(TestResult.report_file))
                        .where(TestResult.test_run_id == run.id)
                    )
                ).all()
            }
            imported_sessions = {
                fn
                for (fn,) in (
                    await session.execute(
                        select(ListenerSession.report_file).where(
                            ListenerSession.test_run_id == run.id
                        )
                    )
                ).all()
            }

            run_touched = False
            for report_file in report_files:
                fn = report_file.name
                if fn in imported_results or fn in imported_sessions:
                    continue
                # Skip files that may still be mid-write. A valid-but-
                # truncated JSON would otherwise be imported partially,
                # then the dedup query on the next pass would skip it
                # (the filename is now in `imported_results`), silently
                # under-counting rows for this run.
                if not await asyncio.to_thread(_is_file_stable, report_file):
                    logger.debug("File %s still changing; will retry next cycle", fn)
                    continue
                try:
                    async with session.begin_nested():
                        if is_solo_report(fn):
                            n_r, _ = await _import_solo_report(session, run, report_file)
                            if n_r:
                                run_touched = True
                        elif is_listener_report(fn):
                            n_s = await _import_listener_report(session, run, report_file)
                            if n_s:
                                run_touched = True
                except Exception as e:
                    logger.error("Error importing %s: %s", fn, e)

            # Solo's own scores were computed before any listener report
            # was on disk, so protocol reachability sat at the neutral 0.5
            # default. Re-blend solo + listener whenever a side adds new data.
            if run_touched:
                try:
                    async with session.begin_nested():
                        loaded = await asyncio.to_thread(
                            _load_reports_for_scoring, report_files
                        )
                        _apply_scores(run, *loaded)
                except Exception as e:
                    logger.warning("score recompute failed for %s: %s", test_id, e)

        await session.commit()


def _apply_scores(
    run: TestRun,
    solo_results: list[CoreTestResult],
    listener_reports: list[CoreListenerReport],
) -> None:
    """Rebuild server scores and write them onto `run`."""
    if not solo_results:
        return
    scores = compute_scores(
        solo_results=solo_results,
        listener_reports=listener_reports or None,
    )
    run.entry_score = scores.entry_score
    run.exit_score = scores.exit_score
    run.relay_score = scores.relay_score
    run.overall_score = scores.overall
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

    solo_results: list[CoreTestResult] = []
    if solo_files:
        raw = load_json(solo_files[-1])
        if isinstance(raw, dict):
            raw_results = raw.get("results", []) or []
            if isinstance(raw_results, list):
                for r in raw_results:
                    try:
                        solo_results.append(CoreTestResult.model_validate(r))
                    except Exception:
                        continue

    listener_reports: list[CoreListenerReport] = []
    for path in listener_files:
        raw = load_json(path)
        if not isinstance(raw, dict):
            continue
        try:
            listener_reports.append(CoreListenerReport.model_validate(raw))
        except Exception:
            continue

    return solo_results, listener_reports


# ─────────────────────────────────────────────────────────────────────────────
# Test runs
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/test-runs")
async def list_test_runs(
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """List all test_ids with their latest scores."""
    rows = await session.execute(select(TestRun).order_by(TestRun.created_at.desc()))
    return [_run_to_dict(r) for r in rows.scalars().all()]


@app.get("/test-runs/{test_id}")
async def get_test_run(
    test_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
    run = await _fetch_run(session, test_id)
    return _run_to_dict(run)


# ─────────────────────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/results/{test_id}")
async def get_results(
    test_id: str,
    category: str | None = Query(None),
    verdict: str | None = Query(None),
    limit: int = Query(500, le=2000),
    offset: int = Query(0),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
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


# ─────────────────────────────────────────────────────────────────────────────
# Protocol reachability matrix
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/protocols/{test_id}")
async def get_protocol_matrix(
    test_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
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


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_meta_yaml(meta_path: Path) -> dict:
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
        description=meta_data.get("description"),
        purpose=meta_data.get("purpose", "vpn-entry"),
        server_meta=endpoint,
        ipv6_available=bool(server.get("ipv6_available", False)) if isinstance(server, dict) else False,
        kernel=server.get("kernel") if isinstance(server, dict) else None,
        distro=server.get("distro") if isinstance(server, dict) else None,
        created_at=datetime.now(tz=timezone.utc),
    )
    session.add(run)
    await session.flush()
    return run


async def _import_solo_report(
    session: AsyncSession, run: TestRun, path: Path
) -> tuple[int, bool]:
    """Import a solo report. Returns (n_results_added, is_new_run)."""
    _meta, results = await asyncio.to_thread(parse_solo_report, path)
    if not results:
        return 0, False

    run.last_synced_at = datetime.now(tz=timezone.utc)

    for r in results:
        row = TestResult(test_run_id=run.id, **r)
        session.add(row)

    return len(results), True


async def _import_listener_report(
    session: AsyncSession, run: TestRun, path: Path
) -> int:
    """Import a listener report. Returns number of sessions added."""
    sess_meta, proto_results = await asyncio.to_thread(parse_listener_report, path)
    if not sess_meta:
        return 0

    listener_sess = ListenerSession(
        test_run_id=run.id,
        session_id=sess_meta.get("session_id", ""),
        report_file=sess_meta.get("report_file", ""),
        started_at=sess_meta.get("started_at"),
        stopped_at=sess_meta.get("stopped_at"),
        duration_sec=sess_meta.get("duration_sec"),
        client_connected=bool(sess_meta.get("client_connected", False)),
        client_meta=sess_meta.get("client_meta"),
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


def _run_to_dict(run: TestRun) -> dict:
    return {
        "test_id": run.test_id,
        "description": run.description,
        "purpose": run.purpose,
        "server_meta": run.server_meta,
        "ipv6_available": run.ipv6_available,
        "kernel": run.kernel,
        "distro": run.distro,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "last_synced_at": run.last_synced_at.isoformat() if run.last_synced_at else None,
        "scores": {
            "entry": run.entry_score,
            "exit": run.exit_score,
            "relay": run.relay_score,
            "overall": run.overall_score,
        },
        "throttling_detected": run.throttling_detected,
        "dns_integrity": run.dns_integrity,
        "tls_integrity": run.tls_integrity,
        "telegram_health": run.telegram_health,
        "detected_techniques": list(run.detected_techniques or []),
        "recommended_protocols": list(run.recommended_protocols or []),
    }


def _result_to_dict(r: TestResult) -> dict:
    return {
        "test": r.test,
        "category": r.category,
        "target": r.target,
        "verdict": r.verdict,
        "method": r.method,
        "confidence": r.confidence,
        "rtt_ms": r.rtt_ms,
        "attempts": r.attempts,
        "notes": r.notes,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "source": r.source,
    }
