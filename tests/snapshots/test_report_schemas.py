"""
JSON-Schema snapshot tests for solo + listener report shapes.

Two layers of assurance:

  1. ``model_json_schema()`` of the relevant pydantic models is checked
     into ``schemas/`` and re-asserted by this test. A backwards-
     incompatible model change fails CI; intentional changes regenerate
     the schema and surface in the diff for human review (run with
     ``--regenerate`` env var).

  2. The committed fixture files validate against the schemas via
     ``jsonschema.validate``. This is what guards the contract between
     producer (probe-core) and consumer (sync-api parser): a fixture
     that round-trips through both sides means parser and producer
     speak the same dialect.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from censprobe_core.models import ListenerReport, TestResult

SNAPSHOT_DIR = Path(__file__).resolve().parent
SCHEMA_DIR = SNAPSHOT_DIR / "schemas"
FIXTURE_DIR = SNAPSHOT_DIR / "fixtures"


def _schema_path(name: str) -> Path:
    return SCHEMA_DIR / f"{name}.schema.json"


def _maybe_regenerate(name: str, schema: dict[str, Any]) -> None:
    """If CENSPROBE_REGENERATE_SCHEMAS=1 is set, write the schema and
    skip the diff assertion. Operators do this once after an
    intentional model change."""
    if os.environ.get("CENSPROBE_REGENERATE_SCHEMAS") == "1":
        SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
        _schema_path(name).write_text(
            json.dumps(schema, indent=2, sort_keys=True), encoding="utf-8"
        )
        pytest.skip(f"Regenerated {name}.schema.json")


@pytest.mark.parametrize(
    ("model", "name"),
    [
        (TestResult, "test_result"),
        (ListenerReport, "listener_report"),
    ],
)
def test_pydantic_schema_matches_committed(model: type, name: str) -> None:
    """The committed schema in ``schemas/`` must equal the current
    ``model.model_json_schema()`` output.

    A model change without re-generating the schema → diff → CI fails.
    A schema change without a model change → diff → CI fails.
    """
    schema = model.model_json_schema()
    _maybe_regenerate(name, schema)
    path = _schema_path(name)
    assert path.exists(), (
        f"Schema not committed: {path}. Run with "
        f"CENSPROBE_REGENERATE_SCHEMAS=1 to generate it once."
    )
    committed = json.loads(path.read_text(encoding="utf-8"))
    assert committed == schema, (
        f"{name} pydantic schema drifted from committed snapshot. "
        f"If intentional, re-run with CENSPROBE_REGENERATE_SCHEMAS=1."
    )


def test_test_result_fixture_validates() -> None:
    """``test_result_minimal.json`` is a hand-written reference shape;
    must validate against the current pydantic schema, ensuring the
    fixture stays in step with the model."""
    schema = TestResult.model_json_schema()
    fixture = json.loads((FIXTURE_DIR / "test_result_minimal.json").read_text(encoding="utf-8"))
    jsonschema.validate(fixture, schema)
    # And round-trips through the parser-equivalent path.
    obj = TestResult.model_validate(fixture)
    assert obj.test == fixture["test"]
    assert str(obj.verdict) == fixture["verdict"]


def test_listener_report_fixture_validates() -> None:
    schema = ListenerReport.model_json_schema()
    fixture = json.loads((FIXTURE_DIR / "listener_report_minimal.json").read_text(encoding="utf-8"))
    jsonschema.validate(fixture, schema)
    obj = ListenerReport.model_validate(fixture)
    assert obj.test_id == fixture["test_id"]
    assert obj.session_id == fixture["session_id"]
