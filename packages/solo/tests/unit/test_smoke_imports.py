"""Smoke-import: every censprobe_solo submodule imports cleanly."""

from __future__ import annotations

import importlib
import pkgutil

import censprobe_solo


def test_every_submodule_imports() -> None:
    failed: list[tuple[str, BaseException]] = []
    for module_info in pkgutil.walk_packages(censprobe_solo.__path__, prefix="censprobe_solo."):
        try:
            importlib.import_module(module_info.name)
        except BaseException as exc:  # noqa: BLE001  # NOSONAR — intentional broad catch, failures are surfaced via assert below
            failed.append((module_info.name, exc))

    assert not failed, "import failures:\n" + "\n".join(
        f"  {name}: {type(exc).__name__}: {exc}" for name, exc in failed
    )
