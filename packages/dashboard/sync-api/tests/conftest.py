"""
sync-api test fixtures.

CRITICAL: ``sync_api.db`` reads ``DATABASE_URL`` and ``sync_api.main`` reads
``CENSPROBE_IMPORT_INTERVAL_SEC`` at *import time*. We must set both env
vars before any test (or smoke-import test) imports sync_api modules.
pytest imports conftest.py before any sibling test file, so module-level
env-var assignment here happens early enough.

The placeholder DATABASE_URL is enough to construct an SQLAlchemy
``AsyncEngine`` (engine creation is lazy — no connection attempt). Real
integration tests (Phase 4) override this via the ``postgres_container``
fixture or a CI-side ``services: postgres``.
"""

from __future__ import annotations

import os

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://placeholder:placeholder@localhost:5432/placeholder",
)
os.environ.setdefault("CENSPROBE_IMPORT_INTERVAL_SEC", "60")
