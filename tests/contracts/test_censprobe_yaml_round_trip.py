"""
Contract test — censprobe.yaml round-trips losslessly through the
pydantic model.

Operators edit censprobe.yaml directly; if a model change ever causes
``model_dump → yaml.safe_dump → yaml.safe_load → model_validate`` to
drift, the next operator edit is at risk of silently dropping fields.
Catch the drift in CI before it ships.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from censprobe_core.config import CensprobeConfig

REPO_ROOT = Path(__file__).resolve().parents[2]
CFG_PATH = REPO_ROOT / "censprobe.yaml"


def test_censprobe_yaml_loads() -> None:
    assert CFG_PATH.is_file(), f"censprobe.yaml missing at {CFG_PATH}"
    raw = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8"))
    cfg = CensprobeConfig.model_validate(raw)
    # Some sanity probes — every section must exist.
    assert cfg.scoring.entry.protocol > 0
    assert cfg.protocols.enabled
    assert cfg.modules.dns.enabled in (True, False)


def test_round_trip_idempotent() -> None:
    raw = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8"))
    cfg1 = CensprobeConfig.model_validate(raw)

    # dump → re-dump via yaml → re-load → re-validate. Both sides should
    # agree on the model representation.
    dumped = yaml.safe_dump(
        cfg1.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=True,
    )
    reloaded = yaml.safe_load(dumped)
    cfg2 = CensprobeConfig.model_validate(reloaded)

    # Compare via model_dump rather than direct equality — pydantic
    # dataclasses include some private state we don't care about.
    assert cfg1.model_dump() == cfg2.model_dump(), (
        "censprobe.yaml does not round-trip cleanly through "
        "CensprobeConfig — a field is lost or re-typed on dump/load."
    )
