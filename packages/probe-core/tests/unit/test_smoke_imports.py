"""
Smoke-import test: every submodule of censprobe_core imports cleanly.

Catches: circular imports introduced by a refactor, top-level typos,
side-effects on import that need an env var the production runtime
provides but the test environment doesn't.
"""

from __future__ import annotations

import importlib
import pkgutil

import censprobe_core


def test_every_submodule_imports() -> None:
    failed: list[tuple[str, BaseException]] = []
    for module_info in pkgutil.walk_packages(censprobe_core.__path__, prefix="censprobe_core."):
        try:
            importlib.import_module(module_info.name)
        except BaseException as exc:  # noqa: BLE001  # NOSONAR — intentional broad catch, failures are surfaced via assert below
            failed.append((module_info.name, exc))

    assert not failed, "import failures:\n" + "\n".join(
        f"  {name}: {type(exc).__name__}: {exc}" for name, exc in failed
    )
