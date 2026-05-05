"""
Smoke-import: every sync_api submodule imports cleanly.

DATABASE_URL + CENSPROBE_IMPORT_INTERVAL_SEC are set in tests/conftest.py
before this module is imported.
"""

from __future__ import annotations

import importlib
import pkgutil

import sync_api


def test_every_submodule_imports() -> None:
    failed: list[tuple[str, BaseException]] = []
    for module_info in pkgutil.walk_packages(sync_api.__path__, prefix="sync_api."):
        try:
            importlib.import_module(module_info.name)
        except BaseException as exc:  # noqa: BLE001  # NOSONAR — intentional broad catch, failures are surfaced via assert below
            failed.append((module_info.name, exc))

    assert not failed, "import failures:\n" + "\n".join(
        f"  {name}: {type(exc).__name__}: {exc}" for name, exc in failed
    )
