"""
Security tests for sync_api.parser.load_json.

The reports tree is whatever an operator ``git pull``s. A malicious PR
could ship a symlink at ``reports/<test_id>/foo.json → /etc/passwd``,
or a sparse 10 GB file that would OOM the importer. ``load_json`` must
defend against both without aborting the whole import.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from sync_api.parser import _MAX_REPORT_BYTES, load_json


class TestLoadJsonHappyPath:
    def test_well_formed_dict_returns_dict(self, tmp_path: Path) -> None:
        path = tmp_path / "ok.json"
        path.write_text(json.dumps({"a": 1, "b": [1, 2]}), encoding="utf-8")
        assert load_json(path) == {"a": 1, "b": [1, 2]}

    def test_non_object_top_level_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Reports are always JSON objects. Anything else (top-level array,
        # number, string) is malformed — refuse to load so the importer's
        # downstream typed contract isn't violated.
        path = tmp_path / "list.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            assert load_json(path) is None
        assert any("not an object" in r.message.lower() for r in caplog.records)


class TestLoadJsonSymlinkRejection:
    def test_symlink_to_real_json_rejected(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The reports tree must not follow symlinks even when the target
        # is benign — a malicious PR could replace the target later.
        real = tmp_path / "real.json"
        real.write_text(json.dumps({"a": 1}), encoding="utf-8")
        link = tmp_path / "link.json"
        link.symlink_to(real)
        with caplog.at_level(logging.WARNING):
            assert load_json(link) is None
        assert any("symlink" in r.message.lower() for r in caplog.records)


class TestLoadJsonSizeCap:
    def test_oversize_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        # Use a sparse file so the test stays fast — write nothing, just
        # truncate to 51 MB. The cap is 50 MiB.
        path = tmp_path / "huge.json"
        with path.open("wb") as f:
            f.truncate(_MAX_REPORT_BYTES + 1)
        with caplog.at_level(logging.ERROR):
            assert load_json(path) is None
        assert any("cap" in r.message.lower() for r in caplog.records)

    def test_at_cap_size_not_rejected_for_size(self, tmp_path: Path) -> None:
        # File exactly at cap is allowed (boundary is strictly >cap).
        # But we still need valid JSON in it; pad with whitespace.
        path = tmp_path / "ok.json"
        body = b'{"a":1}'
        padding = b" " * (_MAX_REPORT_BYTES - len(body))
        path.write_bytes(body + padding)
        assert load_json(path) == {"a": 1}


class TestLoadJsonMalformed:
    def test_empty_file_returns_none(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "empty.json"
        path.write_text("", encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            assert load_json(path) is None
        assert any("empty" in r.message.lower() for r in caplog.records)

    def test_invalid_json_returns_none(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{this is invalid", encoding="utf-8")
        with caplog.at_level(logging.ERROR):
            assert load_json(path) is None
        # Error message should name the file so operators can find it.
        assert any("bad.json" in r.message for r in caplog.records)

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        # The "file vanished mid-import" case — common when a concurrent
        # `git pull` rewrites the tree.
        path = tmp_path / "missing.json"
        assert load_json(path) is None
