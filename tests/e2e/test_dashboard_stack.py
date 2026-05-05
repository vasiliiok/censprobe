"""
Dashboard E2E: spin up the dashboard stack (postgres + sync-api) and
verify the wire-level contract operators rely on:

  * /health returns 200 within 60s of `up`
  * the schema migrates cleanly on a fresh database
  * /test-runs/ returns an empty list (no reports imported yet)

Runs in the `e2e-dashboard` CI job on every push/PR. The job builds the
sync-api image locally (so the test exercises the PR's own code, not
yesterday's published `:main`) and tags it under the env-pinned
`${DOCKERHUB_USERNAME}/...:${DOCKERHUB_TAG}` slot that docker-compose.yml
interpolates. Postgres is digest-pinned in the base compose file.

This is intentionally narrow — full client/listener handshake testing
is its own (much larger) E2E because of host-networking and capability
requirements. The dashboard stack is the easiest piece to exercise on
a stock GitHub Actions runner and catches the most painful regressions
(Postgres driver mismatch, FastAPI lifespan failure, Alembic-style
schema drift after a model edit).
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE = REPO_ROOT / "docker-compose.yml"
OVERLAY_COMPOSE = REPO_ROOT / "tests" / "e2e" / "compose.test.yml"
SYNC_API_PORT = int(os.environ.get("CENSPROBE_E2E_SYNC_API_PORT", "18080"))


pytestmark = pytest.mark.e2e


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    """Wrapper around `docker compose` with both the production manifest
    and the test overlay applied. We surface stderr in failures so the
    e2e log makes the root cause obvious without chasing the run."""
    cmd = [
        "docker",
        "compose",
        "-f",
        str(BASE_COMPOSE),
        "-f",
        str(OVERLAY_COMPOSE),
        "--profile",
        "dashboard",
        *args,
    ]
    return subprocess.run(  # noqa: S603 - args is a fixed argv list, not a shell string.
        cmd,
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def dashboard_stack() -> None:
    """Bring up postgres + sync-api, tear down on teardown.

    `docker compose down -v` removes the named volumes so a re-run
    starts from an empty database — otherwise a stale schema from
    last night's failed run would mask schema-migration bugs."""
    up = _compose("up", "-d", "--wait", "--wait-timeout", "60", "postgres", "sync-api")
    if up.returncode != 0:
        # `down -v` even on failure so we don't leak containers.
        _compose("down", "-v")
        pytest.fail(
            f"docker compose up failed (rc={up.returncode}):\n"
            f"--- stdout ---\n{up.stdout}\n--- stderr ---\n{up.stderr}"
        )
    yield
    _compose("down", "-v")


def _wait_for_health(url: str, timeout_s: float = 60.0) -> httpx.Response:
    """Poll /health until it returns 200 or `timeout_s` elapses.

    `--wait` on `compose up` already waits for the container's own
    healthcheck, but a healthy container is not yet a healthy app —
    init_db() can throw on FastAPI startup *after* uvicorn binds.
    Polling once more from the test's perspective closes that gap."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code == 200:
                return r
        except httpx.HTTPError as exc:
            last_exc = exc
        time.sleep(1.0)
    raise AssertionError(
        f"GET {url} did not return 200 within {timeout_s:.0f}s; last error: {last_exc!r}"
    )


def test_sync_api_health(dashboard_stack: None) -> None:
    r = _wait_for_health(f"http://127.0.0.1:{SYNC_API_PORT}/health")
    body = r.json()
    assert body.get("status") == "ok", body


def test_sync_api_test_runs_empty_on_fresh_db(dashboard_stack: None) -> None:
    """A freshly-migrated database has no test runs imported yet — the
    endpoint must return an empty list, not 500. Catches the regression
    where a missing table or column propagates to JSON serialization.

    Path has no trailing slash — sync-api defines `@app.get("/test-runs")`
    and a trailing slash triggers FastAPI's default 307 redirect, which
    httpx does not follow unless explicitly told to."""
    r = httpx.get(f"http://127.0.0.1:{SYNC_API_PORT}/test-runs", timeout=5.0)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert isinstance(payload, list), payload
    assert payload == [], f"expected empty list on fresh DB, got {payload!r}"
