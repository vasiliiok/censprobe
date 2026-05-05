"""
Tests for parse_solo_report.

These guard the bridge from disk JSON to DB row — schema drift, missing
keys, wrong-typed fields, and explicit-vs-derived subcategory must all
land on a known row shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sync_api.parser import parse_solo_report


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestParseSoloReport:
    def test_minimal_well_formed(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "server-solo-x.json",
            {
                "report_type": "solo",
                "test_id": "vultr-fra-01",
                "generated_at": "2026-05-04T12:00:00Z",
                "results": [
                    {
                        "test": "dns_meduza_io_system",
                        "category": "dns",
                        "target": "meduza.io",
                        "verdict": "OK",
                        "confidence": 0.9,
                        "rtt_ms": 25.4,
                        "attempts": 1,
                        "timestamp": "2026-05-04T12:01:00Z",
                    }
                ],
            },
        )
        meta, results = parse_solo_report(path)
        assert meta["test_id"] == "vultr-fra-01"
        assert meta["report_type"] == "solo"
        assert len(results) == 1
        r = results[0]
        assert r["test"] == "dns_meduza_io_system"
        assert r["category"] == "dns"
        assert r["target"] == "meduza.io"
        assert r["verdict"] == "OK"
        assert r["rtt_ms"] == pytest.approx(25.4)
        assert r["confidence"] == pytest.approx(0.9)
        assert r["attempts"] == 1
        assert r["report_file"] == "server-solo-x.json"
        assert r["source"] == "solo"
        # Subcategory is derived from "dns_*" prefix.
        assert r["subcategory"] == "dns"

    def test_missing_subcategory_is_derived(self, tmp_path: Path) -> None:
        # Old reports written before the field existed must still land
        # with a populated subcategory so dashboards filter correctly.
        path = _write(
            tmp_path / "server-solo-x.json",
            {
                "results": [
                    {
                        "test": "doh_access_cloudflare",
                        "category": "dns",
                        "target": "x",
                        "verdict": "OK",
                    }
                ]
            },
        )
        _, results = parse_solo_report(path)
        assert results[0]["subcategory"] == "doh"

    def test_explicit_subcategory_preserved(self, tmp_path: Path) -> None:
        # Producer's explicit subcategory wins over the derive-from-name
        # fallback. (Used when a probe family wants to control the bucket
        # on its own terms.)
        path = _write(
            tmp_path / "server-solo-x.json",
            {
                "results": [
                    {
                        "test": "dns_x",
                        "category": "dns",
                        "target": "x",
                        "verdict": "OK",
                        "subcategory": "custom_bucket",
                    }
                ]
            },
        )
        _, results = parse_solo_report(path)
        assert results[0]["subcategory"] == "custom_bucket"

    def test_empty_subcategory_is_redrived(self, tmp_path: Path) -> None:
        # Empty string === missing for the purposes of subcategory.
        path = _write(
            tmp_path / "server-solo-x.json",
            {
                "results": [
                    {
                        "test": "dns_x",
                        "category": "dns",
                        "target": "x",
                        "verdict": "OK",
                        "subcategory": "",
                    }
                ]
            },
        )
        _, results = parse_solo_report(path)
        assert results[0]["subcategory"] == "dns"

    def test_string_typed_numeric_fields_coerced(self, tmp_path: Path) -> None:
        # If a future writer accidentally serialises numbers as strings
        # the importer must still produce numeric DB columns.
        path = _write(
            tmp_path / "server-solo-x.json",
            {
                "results": [
                    {
                        "test": "dns_x",
                        "category": "dns",
                        "target": "x",
                        "verdict": "OK",
                        "rtt_ms": "12.5",
                        "attempts": "3",
                        "confidence": "0.7",
                    }
                ]
            },
        )
        _, results = parse_solo_report(path)
        r = results[0]
        assert r["rtt_ms"] == pytest.approx(12.5)
        assert r["attempts"] == 3
        assert r["confidence"] == pytest.approx(0.7)

    def test_results_not_a_list_returns_empty(self, tmp_path: Path) -> None:
        # A future writer accidentally stores results as a dict — we
        # must drop the body, not crash.
        path = _write(
            tmp_path / "server-solo-x.json",
            {"test_id": "x", "results": {"oops": "wrong shape"}},
        )
        meta, results = parse_solo_report(path)
        assert meta["test_id"] == "x"
        assert results == []

    def test_non_dict_result_skipped(self, tmp_path: Path) -> None:
        # A stray scalar in the results array must be skipped silently;
        # the rest of the body still imports.
        path = _write(
            tmp_path / "server-solo-x.json",
            {
                "results": [
                    "garbage",
                    {
                        "test": "dns_x",
                        "category": "dns",
                        "target": "x",
                        "verdict": "OK",
                    },
                ]
            },
        )
        _, results = parse_solo_report(path)
        assert len(results) == 1

    def test_missing_verdict_falls_back_to_inconclusive(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "server-solo-x.json",
            {"results": [{"test": "x", "category": "dns", "target": "y"}]},
        )
        _, results = parse_solo_report(path)
        assert results[0]["verdict"] == "INCONCLUSIVE"

    def test_corrupt_json_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "server-solo-x.json"
        path.write_text("{this is not json", encoding="utf-8")
        meta, results = parse_solo_report(path)
        assert meta == {}
        assert results == []

    def test_top_level_array_returns_empty(self, tmp_path: Path) -> None:
        # parser short-circuits on non-dict top level.
        path = tmp_path / "server-solo-x.json"
        path.write_text("[]", encoding="utf-8")
        meta, results = parse_solo_report(path)
        assert meta == {}
        assert results == []
