"""
sync_api/main.py — FastAPI service for Grafana data sync.

Endpoints:
  GET  /health             — liveness check
  POST /refresh            — git pull + parse new reports → Postgres
  GET  /test-runs          — list all test_ids with latest scores
  GET  /test-runs/{id}     — single test run details
  GET  /results/{id}       — paginated test results for a test_id
  GET  /protocols/{id}     — protocol reachability matrix for a test_id
  GET  /baseline           — current baseline metadata

Grafana connects to Postgres directly via the Postgres datasource plugin.
The /refresh endpoint is called via Grafana button or manual curl.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from censprobe_core.git_io import _git_lock  # reuse the shared fcntl lock
from censprobe_core.models import (
    ListenerReport as CoreListenerReport,
    TestResult as CoreTestResult,
)
from censprobe_core.scoring import compute_scores
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
    _load_gz,
    is_listener_report,
    is_solo_report,
    parse_listener_report,
    parse_solo_report,
)

logger = logging.getLogger("censprobe.sync_api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

WORKSPACE = Path(os.environ.get("WORKSPACE", "/workspace"))

# Serialize /refresh calls: the endpoint runs `git pull --rebase` which
# takes an exclusive .git/index.lock, and a second concurrent call
# (Grafana double-click on "Pull & Refresh") collides and aborts with a
# 500. One global lock is enough — refresh is a single-writer op, and
# we want later callers to wait for, and share the result of, the in-
# flight run rather than racing.
_REFRESH_LOCK = asyncio.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize database tables on startup."""
    await init_db()
    logger.info("DB tables initialized")
    yield


app = FastAPI(
    title="censprobe-sync-api",
    version="0.3.0",
    description="Sync censprobe git reports into Postgres for Grafana",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "0.3.0", "workspace": str(WORKSPACE)}


# ─────────────────────────────────────────────────────────────────────────────
# Refresh — git pull + parse new reports
# ─────────────────────────────────────────────────────────────────────────────

class RefreshResponse(BaseModel):
    status: str
    new_runs: int
    new_results: int
    new_sessions: int
    errors: list[str]


def _git_pull_sync(workspace: Path) -> None:
    """Run `git pull --rebase` synchronously in a worker thread.

    Held under the process-global fcntl lock so we never race a concurrent
    solo / listener commit on .git/index.lock.
    """
    with _git_lock():
        subprocess.run(
            ["git", "pull", "--rebase"],
            cwd=workspace,
            capture_output=True,
            check=True,
        )


def _list_report_files(reports_root: Path) -> list[tuple[str, Path, list[Path]]]:
    """
    Enumerate report files on disk in a worker thread.

    Returns a list of (test_id, meta_path, report_files) tuples. Doing
    this in a single blocking pass (then dispatching async DB work) keeps
    the event loop responsive on large trees.
    """
    out: list[tuple[str, Path, list[Path]]] = []
    if not reports_root.exists():
        return out
    for test_dir in sorted(reports_root.iterdir()):
        if not test_dir.is_dir():
            continue
        report_files = sorted(
            list(test_dir.glob("*.json")) + list(test_dir.glob("*.json.gz"))
        )
        out.append((test_dir.name, test_dir / "meta.yaml", report_files))
    return out


@app.post("/refresh", response_model=RefreshResponse)
async def refresh() -> RefreshResponse:
    """Pull latest from git and sync new reports into Postgres.

    Git I/O, directory enumeration, and .json(.gz) parsing are all blocking;
    they are dispatched to the default thread pool so the event loop keeps
    serving /health and read endpoints during a refresh.
    """
    async with _REFRESH_LOCK:
        return await _do_refresh()


async def _do_refresh() -> RefreshResponse:
    errors: list[str] = []

    # 1. Git pull (blocking — run off-loop).
    try:
        await asyncio.to_thread(_git_pull_sync, WORKSPACE)
        logger.info("git pull done")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="replace") if e.stderr else ""
        logger.warning("git pull failed: %s", stderr or e)
        errors.append(f"git pull: {stderr or e}")
    except Exception as e:
        logger.warning("git pull failed: %s", e)
        errors.append(f"git pull: {e}")

    # 2. Enumerate report files off-loop.
    reports_root = WORKSPACE / "reports"
    test_dirs = await asyncio.to_thread(_list_report_files, reports_root)
    if not test_dirs:
        return RefreshResponse(
            status="ok", new_runs=0, new_results=0, new_sessions=0, errors=errors
        )

    new_runs = 0
    new_results = 0
    new_sessions = 0

    async with async_session_factory() as session:
        for test_id, meta_path, report_files in test_dirs:
            run = await _get_or_create_test_run(session, test_id, meta_path)
            if run is None:
                continue

            # Pull all already-imported filenames for this run in ONE query
            # each (vs. N+1 point lookups per file). Fits fine in memory —
            # one short string per report.
            imported_results = {
                fn
                for (fn,) in (
                    await session.execute(
                        select(TestResult.report_file).where(TestResult.test_run_id == run.id)
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

                # Wrap each report in a savepoint so that a single bad
                # file (oversize string, DB constraint violation, ...)
                # aborts only its own import, not the whole batch. Without
                # this, any failure poisons the outer transaction and
                # every subsequent add()/commit() raises
                # PendingRollbackError.
                try:
                    async with session.begin_nested():
                        if is_solo_report(fn):
                            n_r, n_run = await _import_solo_report(session, run, report_file)
                            new_results += n_r
                            if n_run:
                                new_runs += 1
                                run_touched = True

                        elif is_listener_report(fn):
                            n_s = await _import_listener_report(session, run, report_file)
                            new_sessions += n_s
                            if n_s:
                                run_touched = True
                except Exception as e:
                    logger.error("Error importing %s: %s", fn, e)
                    errors.append(f"{fn}: {e}")

            # Once we've consumed everything new for this test_id,
            # recompute scores from raw report files on disk so the
            # dashboard reflects the latest listener data. Solo's own
            # scoring ran without any listener signal, leaving protocol
            # reachability at the neutral 0.5 default.
            if run_touched:
                try:
                    async with session.begin_nested():
                        loaded = await asyncio.to_thread(
                            _load_reports_for_scoring, report_files
                        )
                        _apply_scores(run, *loaded)
                except Exception as e:
                    logger.warning("score recompute failed for %s: %s", test_id, e)
                    errors.append(f"scores[{test_id}]: {e}")

        await session.commit()

    return RefreshResponse(
        status="ok",
        new_runs=new_runs,
        new_results=new_results,
        new_sessions=new_sessions,
        errors=errors,
    )


def _apply_scores(
    run: TestRun,
    solo_results: list[CoreTestResult],
    listener_reports: list[CoreListenerReport],
) -> None:
    """Rebuild server scores and write them onto `run`.

    Authoritative scoring lives here rather than in the solo container:
    solo runs BEFORE listener, so any numbers it bakes into its own
    report miss the real protocol-reachability signal. We re-blend the
    latest solo run's raw TestResults with every listener session on
    disk whenever either side adds a new report.
    """
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
        p for p in report_files if is_listener_report(p.name)
    )

    solo_results: list[CoreTestResult] = []
    if solo_files:
        raw = _load_gz(solo_files[-1])
        if raw:
            for r in raw.get("results", []):
                try:
                    solo_results.append(CoreTestResult.model_validate(r))
                except Exception:
                    continue

    listener_reports: list[CoreListenerReport] = []
    for path in listener_files:
        raw = _load_gz(path)
        if not raw:
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
    category: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
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
# Baseline metadata
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/baseline")
async def get_baseline() -> dict:
    """Return current baseline metadata (not the full data, just meta)."""
    import json as _json
    baseline_path = WORKSPACE / "baseline" / "latest.json"
    if not baseline_path.exists():
        return {"status": "missing"}
    try:
        raw = _json.loads(baseline_path.read_text())
        return {
            "status": "ok",
            "version": raw.get("version", "unknown"),
            "generated_at": raw.get("generated_at"),
            "validity_until": raw.get("validity_until"),
            "runs_count": raw.get("runs_count", 0),
            "generated_from": raw.get("generated_from", {}),
            "dns_count": len(raw.get("dns", {})),
            "http_count": len(raw.get("http", {})),
            "telegram_count": len(raw.get("telegram", {})),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


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
) -> Optional[TestRun]:
    """Find or create a TestRun row for a test_id."""
    row = (
        await session.execute(select(TestRun).where(TestRun.test_id == test_id))
    ).scalar_one_or_none()
    if row:
        return row

    meta_data = await asyncio.to_thread(_read_meta_yaml, meta_path)

    server = meta_data.get("server", {})
    run = TestRun(
        test_id=test_id,
        description=meta_data.get("description"),
        purpose=meta_data.get("purpose", "vpn-entry"),
        asn=server.get("asn"),
        as_name=server.get("as_name"),
        location=server.get("location"),
        ipv4_masked=server.get("ipv4_masked"),
        ipv6_available=bool(server.get("ipv6_available", False)),
        provider=server.get("provider"),
        kernel=server.get("kernel"),
        distro=server.get("distro"),
        created_at=datetime.now(tz=timezone.utc),
    )
    session.add(run)
    await session.flush()
    return run


async def _import_solo_report(
    session: AsyncSession, run: TestRun, path: Path
) -> tuple[int, bool]:
    """Import a solo report. Returns (n_results_added, is_new_run).

    Scores are NOT written here anymore — the solo report's meta.scores
    were computed before any listener data was available, so using them
    would permanently freeze recommended_protocols and entry_score at
    their neutral defaults. `_apply_scores` recomputes them below once
    per touched run.
    """
    # parse_solo_report does disk I/O + gzip + JSON decoding — block off-loop.
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
        "asn": run.asn,
        "as_name": run.as_name,
        "location": run.location,
        "ipv4_masked": run.ipv4_masked,
        "ipv6_available": run.ipv6_available,
        "provider": run.provider,
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
