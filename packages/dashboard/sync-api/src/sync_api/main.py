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

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import git
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select, text
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
    parse_listener_report,
    parse_solo_report,
)

logger = logging.getLogger("censprobe.sync_api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

WORKSPACE = Path(os.environ.get("WORKSPACE", "/workspace"))

app = FastAPI(
    title="censprobe-sync-api",
    version="0.3.0",
    description="Sync censprobe git reports into Postgres for Grafana",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup() -> None:
    await init_db()
    logger.info("DB tables initialized")


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


@app.post("/refresh", response_model=RefreshResponse)
async def refresh(background_tasks: BackgroundTasks) -> RefreshResponse:
    """Pull latest from git and sync new reports into Postgres."""
    errors: list[str] = []

    # 1. Git pull
    try:
        repo = git.Repo(WORKSPACE)
        origin = repo.remotes.origin
        origin.pull(rebase=True)
        logger.info("git pull done")
    except Exception as e:
        logger.warning("git pull failed: %s", e)
        errors.append(f"git pull: {e}")

    # 2. Parse all reports
    new_runs = 0
    new_results = 0
    new_sessions = 0

    reports_root = WORKSPACE / "reports"
    if not reports_root.exists():
        return RefreshResponse(
            status="ok", new_runs=0, new_results=0, new_sessions=0, errors=errors
        )

    async with async_session_factory() as session:
        for test_dir in sorted(reports_root.iterdir()):
            if not test_dir.is_dir():
                continue
            test_id = test_dir.name
            meta_path = test_dir / "meta.yaml"

            # Ensure test run row exists
            run = await _get_or_create_test_run(session, test_id, meta_path)
            if run is None:
                continue
            if run not in session.new:
                pass  # existing run

            # Process all report files
            for report_file in sorted(test_dir.glob("*.json.gz")):
                fn = report_file.name

                # Check if already imported
                existing = await session.execute(
                    select(TestResult).where(
                        TestResult.test_run_id == run.id,
                        TestResult.report_file == fn,
                    ).limit(1)
                )
                if existing.scalar_one_or_none() is not None:
                    continue  # already imported

                existing_sess = await session.execute(
                    select(ListenerSession).where(
                        ListenerSession.test_run_id == run.id,
                        ListenerSession.report_file == fn,
                    ).limit(1)
                )
                if existing_sess.scalar_one_or_none() is not None:
                    continue  # already imported

                try:
                    if is_solo_report(fn):
                        n_r, n_run = await _import_solo_report(session, run, report_file)
                        new_results += n_r
                        if n_run:
                            new_runs += 1

                    elif is_listener_report(fn):
                        n_s = await _import_listener_report(session, run, report_file)
                        new_sessions += n_s
                except Exception as e:
                    logger.error("Error importing %s: %s", fn, e)
                    errors.append(f"{fn}: {e}")

        await session.commit()

    return RefreshResponse(
        status="ok",
        new_runs=new_runs,
        new_results=new_results,
        new_sessions=new_sessions,
        errors=errors,
    )


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

async def _get_or_create_test_run(
    session: AsyncSession, test_id: str, meta_path: Path
) -> Optional[TestRun]:
    """Find or create a TestRun row for a test_id."""
    row = (
        await session.execute(select(TestRun).where(TestRun.test_id == test_id))
    ).scalar_one_or_none()
    if row:
        return row

    # Try to read meta.yaml
    meta_data: dict = {}
    if meta_path.exists():
        try:
            import yaml
            meta_data = yaml.safe_load(meta_path.read_text()) or {}
        except Exception:
            pass

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
    """Import a solo report. Returns (n_results_added, is_new_run)."""
    meta, results = parse_solo_report(path)
    if not results:
        return 0, False

    # Update scores on the run from latest solo
    scores = meta.get("scores", {})
    if scores:
        run.entry_score = scores.get("entry_score")
        run.exit_score = scores.get("exit_score")
        run.relay_score = scores.get("relay_score")
        run.overall_score = scores.get("overall")
        run.throttling_detected = scores.get("throttling_detected", False)
        run.dns_integrity = scores.get("dns_integrity")
        run.tls_integrity = scores.get("tls_integrity")
        run.telegram_health = scores.get("telegram_health")
        techniques = scores.get("detected_techniques", [])
        run.detected_techniques = ",".join(techniques) if techniques else None
        protocols = scores.get("recommended_protocols", [])
        run.recommended_protocols = ",".join(protocols) if protocols else None

    run.last_synced_at = datetime.now(tz=timezone.utc)

    for r in results:
        row = TestResult(test_run_id=run.id, **r)
        session.add(row)

    return len(results), True


async def _import_listener_report(
    session: AsyncSession, run: TestRun, path: Path
) -> int:
    """Import a listener report. Returns number of sessions added."""
    sess_meta, proto_results = parse_listener_report(path)
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
        "detected_techniques": run.detected_techniques.split(",") if run.detected_techniques else [],
        "recommended_protocols": run.recommended_protocols.split(",") if run.recommended_protocols else [],
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
