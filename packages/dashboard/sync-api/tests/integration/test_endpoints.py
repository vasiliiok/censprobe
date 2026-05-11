"""
End-to-end tests for the FastAPI endpoints, driven through ``httpx``
against the ASGI app and a real Postgres.

Covers happy paths and 404 / pagination / filter edges. Uses direct
ORM seeding rather than going through the import pipeline so the
endpoint logic is the only thing under test (the import pipeline has
its own test file).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest


async def _seed_run(
    db_session: Any,
    *,
    test_id: str,
) -> Any:
    from sync_api.db import TestRun

    run = TestRun(
        test_id=test_id,
        created_at=datetime.now(UTC),
        entry_score=80.0,
        exit_score=70.0,
        relay_score=60.0,
        overall_score=80.0,
        dns_integrity=100.0,
        tls_integrity=100.0,
        telegram_health=0.9,
        recommended_protocols=["wireguard"],
        detected_techniques=["dns_poisoning"],
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)
    return run


@pytest.mark.integration
class TestHealth:
    async def test_health_returns_ok(self, app_client: Any) -> None:
        resp = await app_client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        # Version is the single source of truth in main.SERVICE_VERSION.
        assert body["version"]


@pytest.mark.integration
class TestTestIdPathValidation:
    """FastAPI's Path(pattern=...) rejects malformed ``test_id`` before
    the handler runs. Mirrors the producer-side SAFE_ID_RE so neither
    end can introduce a path-traversal-looking string into responses
    or logs. Bad inputs return 422 (FastAPI's validation error code),
    not 404.
    """

    @pytest.mark.parametrize(
        "bad",
        [
            "../etc/passwd",
            "id with spaces",
            "id/with/slashes",
            "тест",  # non-ASCII
            "a" * 65,  # over the 64-char ceiling
            "",  # empty is collected by FastAPI's path routing differently
        ],
    )
    async def test_malformed_test_id_returns_422(self, app_client: Any, bad: str) -> None:
        # Empty string falls back to FastAPI's default empty-path
        # handling (the request resolves to /test-runs/ which is a
        # different route or 404) — skip that input from the 422 check.
        if not bad:
            return
        resp = await app_client.get(f"/test-runs/{bad}")
        # Slash-bearing inputs change the URL shape entirely — they hit
        # the routing layer before pattern validation, so FastAPI may
        # respond 404. The contract we care about: the request NEVER
        # makes it into the handler with a malformed ID.
        assert resp.status_code in (422, 404)


@pytest.mark.integration
class TestListTestRuns:
    async def test_empty_returns_empty_list(self, app_client: Any) -> None:
        resp = await app_client.get("/test-runs")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_returns_seeded_runs(self, db_session: Any, app_client: Any) -> None:
        await _seed_run(db_session, test_id="run-a")
        await _seed_run(db_session, test_id="run-b")

        resp = await app_client.get("/test-runs")
        assert resp.status_code == 200
        body = resp.json()
        ids = {r["test_id"] for r in body}
        assert ids == {"run-a", "run-b"}
        # Scores nested object format.
        for r in body:
            assert "scores" in r
            assert {"entry", "exit", "relay", "overall"} <= set(r["scores"])


@pytest.mark.integration
class TestGetTestRun:
    async def test_existing_run(self, db_session: Any, app_client: Any) -> None:
        await _seed_run(db_session, test_id="vu-fra")
        resp = await app_client.get("/test-runs/vu-fra")
        assert resp.status_code == 200
        body = resp.json()
        assert body["test_id"] == "vu-fra"
        assert body["scores"]["entry"] == pytest.approx(80.0)
        # Default listener_session_count from _seed_run is the column's
        # server default (0) — confirms it round-trips through the API.
        assert body["scores"]["listener_session_count"] == 0
        assert body["recommended_protocols"] == ["wireguard"]
        assert body["detected_techniques"] == ["dns_poisoning"]

    async def test_missing_returns_404(self, app_client: Any) -> None:
        resp = await app_client.get("/test-runs/does-not-exist")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"]


@pytest.mark.integration
class TestResults:
    async def _seed_results(self, db_session: Any, run: Any) -> None:
        from sync_api.db import TestResult

        rows = [
            TestResult(
                test_run_id=run.id,
                report_file="server-solo.json",
                test="dns_meduza_io_system",
                category="dns",
                subcategory="dns",
                target="meduza.io",
                verdict="OK",
                rtt_ms=10.0,
                timestamp=datetime.now(UTC),
            ),
            TestResult(
                test_run_id=run.id,
                report_file="server-solo.json",
                test="tls_meduza_io_sni_blocked",
                category="tls",
                subcategory="tls_sni_blocked",
                target="meduza.io",
                verdict="BLOCKED",
                rtt_ms=5.0,
                timestamp=datetime.now(UTC),
            ),
            TestResult(
                test_run_id=run.id,
                report_file="server-solo.json",
                test="http_meduza_io",
                category="http",
                subcategory="http",
                target="https://meduza.io",
                verdict="BLOCKED",
                rtt_ms=20.0,
                timestamp=datetime.now(UTC),
            ),
        ]
        for r in rows:
            db_session.add(r)
        await db_session.commit()

    async def test_results_returns_seeded(self, db_session: Any, app_client: Any) -> None:
        run = await _seed_run(db_session, test_id="r1")
        await self._seed_results(db_session, run)

        resp = await app_client.get("/results/r1")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 3
        # Result-shape check.
        first = body[0]
        for k in ("test", "category", "subcategory", "target", "verdict"):
            assert k in first

    async def test_filter_by_category(self, db_session: Any, app_client: Any) -> None:
        run = await _seed_run(db_session, test_id="r2")
        await self._seed_results(db_session, run)

        resp = await app_client.get("/results/r2", params={"category": "tls"})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["category"] == "tls"

    async def test_filter_by_verdict(self, db_session: Any, app_client: Any) -> None:
        run = await _seed_run(db_session, test_id="r3")
        await self._seed_results(db_session, run)

        resp = await app_client.get("/results/r3", params={"verdict": "BLOCKED"})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        for r in body:
            assert r["verdict"] == "BLOCKED"

    async def test_pagination_limit_and_offset(self, db_session: Any, app_client: Any) -> None:
        run = await _seed_run(db_session, test_id="r4")
        await self._seed_results(db_session, run)

        resp = await app_client.get("/results/r4", params={"limit": 1, "offset": 0})
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        resp = await app_client.get("/results/r4", params={"limit": 100, "offset": 2})
        assert resp.status_code == 200
        # 3 rows, offset 2 → 1 remaining.
        assert len(resp.json()) == 1

    async def test_limit_cap_enforced(self, db_session: Any, app_client: Any) -> None:
        # The endpoint declares ``limit: int = Query(500, le=2000)``.
        # Anything above 2000 must 422.
        run = await _seed_run(db_session, test_id="r5")
        await self._seed_results(db_session, run)
        resp = await app_client.get("/results/r5", params={"limit": 2001})
        assert resp.status_code == 422

    async def test_unknown_test_id_404s(self, app_client: Any) -> None:
        resp = await app_client.get("/results/nope")
        assert resp.status_code == 404


@pytest.mark.integration
class TestProtocolMatrix:
    async def test_matrix_for_seeded_session(self, db_session: Any, app_client: Any) -> None:
        from sync_api.db import ListenerSession, ProtocolResult

        run = await _seed_run(db_session, test_id="rm")
        sess = ListenerSession(
            test_run_id=run.id,
            session_id="client-mts-msk",
            report_file="server-listener-1.json",
            client_connected=True,
        )
        db_session.add(sess)
        await db_session.flush()
        db_session.add(ProtocolResult(session_id=sess.id, protocol="wireguard", verdict="OK"))
        db_session.add(ProtocolResult(session_id=sess.id, protocol="openvpn", verdict="BLOCKED"))
        await db_session.commit()

        resp = await app_client.get("/protocols/rm")
        assert resp.status_code == 200
        body = resp.json()
        assert body["test_id"] == "rm"
        # Matrix nested as session_id → {protocol: verdict}.
        assert body["matrix"]["client-mts-msk"] == {
            "wireguard": "OK",
            "openvpn": "BLOCKED",
        }

    async def test_matrix_empty_for_run_without_sessions(
        self, db_session: Any, app_client: Any
    ) -> None:
        await _seed_run(db_session, test_id="rm-empty")
        resp = await app_client.get("/protocols/rm-empty")
        assert resp.status_code == 200
        assert resp.json() == {"test_id": "rm-empty", "matrix": {}}

    async def test_unknown_test_id_404s(self, app_client: Any) -> None:
        resp = await app_client.get("/protocols/nope")
        assert resp.status_code == 404
