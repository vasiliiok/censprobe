"""
Contract test — every targets/*.yaml validates against TargetFile and
load_targets does not warn-skip any of them.

``load_targets`` is intentionally warn-only at runtime (one corrupt file
must not poison a whole probe run). But CI promotes that warning to a
failure so a half-edited YAML never reaches production.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml
from censprobe_core.targets import TargetFile, load_targets

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGETS_DIR = REPO_ROOT / "targets"


def test_targets_directory_exists() -> None:
    assert TARGETS_DIR.is_dir(), f"targets/ missing at {TARGETS_DIR}"


def test_each_yaml_validates_against_targetfile() -> None:
    """Pydantic-validate each file individually so the assertion message
    points at the offending file when one of them is broken."""
    yamls = sorted(TARGETS_DIR.glob("*.yaml"))
    assert yamls, f"No *.yaml under {TARGETS_DIR}"
    failures: list[str] = []
    for path in yamls:
        text = path.read_text(encoding="utf-8")
        try:
            raw = yaml.safe_load(text) or {}
            TargetFile.model_validate(raw)
        except Exception as e:
            failures.append(f"{path.name}: {e}")
    assert not failures, "Target YAMLs failed validation:\n  " + "\n  ".join(failures)


def test_load_targets_emits_no_warnings(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """load_targets emits a WARNING for any file it has to skip — this
    test fails when even one file is malformed enough to be dropped."""
    with caplog.at_level(logging.WARNING, logger="censprobe_core.targets"):
        ts = load_targets(TARGETS_DIR)
    assert ts.files, "load_targets discovered nothing under targets/"
    skip_warnings = [
        r
        for r in caplog.records
        if r.levelno >= logging.WARNING
        and (
            "Failed to read" in r.message
            or "Invalid target file" in r.message
            or "is not a YAML mapping" in r.message
        )
    ]
    assert not skip_warnings, "load_targets warn-skipped one or more files:\n  " + "\n  ".join(
        r.message for r in skip_warnings
    )
