"""
Tests for parse_listener_report — listener-side report → ListenerSession +
ProtocolResult rows.

Key contract here: ``client_connected`` and ``client_meta`` carry three
distinct states that must round-trip cleanly through the parser, because
each one is a different signal in the dashboard:
  1. connected=True, client=dict          → enrichment OK
  2. connected=True, client=None           → enrichment failed
  3. connected=False, client=None          → strongest blocking signal
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sync_api.parser import parse_listener_report


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestParseListenerReport:
    def test_minimal_well_formed(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "server-listener-sess-x.json",
            {
                "session_id": "client-mts-msk",
                "listener_started_at": "2026-05-04T10:00:00Z",
                "listener_stopped_at": "2026-05-04T10:30:00Z",
                "duration_sec": 1800,
                "client_connected": True,
                "client": {"location": {"country_code": "RU"}},
                "results": {
                    "wireguard": {
                        "verdict": "OK",
                        "handshake_count": 1,
                        "data_transfer_ok": True,
                    },
                    "openvpn": {
                        "verdict": "BLOCKED",
                        "handshake_count": 0,
                        "data_transfer_ok": False,
                    },
                },
            },
        )
        meta, protos = parse_listener_report(path)
        assert meta["session_id"] == "client-mts-msk"
        assert meta["client_connected"] is True
        assert meta["client_meta"] == {"location": {"country_code": "RU"}}
        assert len(protos) == 2

        wg = next(p for p in protos if p["protocol"] == "wireguard")
        assert wg["verdict"] == "OK"
        assert wg["handshake_count"] == 1
        assert wg["data_transfer_ok"] is True

    def test_throughput_fields_optional(self, tmp_path: Path) -> None:
        # Older listener reports predate avg_throughput_mbps and
        # throughput_throttled — _to_float(None, default=None) must
        # leave the column NULL, not 0.0.
        path = _write(
            tmp_path / "server-listener-x.json",
            {
                "results": {
                    "openvpn": {"verdict": "BLOCKED", "handshake_count": 0},
                }
            },
        )
        _, protos = parse_listener_report(path)
        assert protos[0]["avg_throughput_mbps"] is None
        assert protos[0]["throughput_throttled"] is False

    def test_throughput_present(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "server-listener-x.json",
            {
                "results": {
                    "shadowsocks": {
                        "verdict": "OK",
                        "handshake_count": 1,
                        "data_transfer_ok": True,
                        "avg_throughput_mbps": 5.6,
                        "throughput_throttled": True,
                    }
                }
            },
        )
        _, protos = parse_listener_report(path)
        assert protos[0]["avg_throughput_mbps"] == pytest.approx(5.6)
        assert protos[0]["throughput_throttled"] is True

    def test_note_field_threaded_through(self, tmp_path: Path) -> None:
        # Listener writes ProtocolResult.note for two real producers
        # (self-test downgrade and mtproto_orig prune/wedged branches).
        # The parser must surface it so the dashboard's Diagnostic column
        # actually has the per-vantage text — without this, the operator
        # sees a bare BLOCKED/ERROR tile with no clue why.
        note_text = (
            "mtproto-proxy not launched: 0/19 proxy-multi.conf upstreams reachable on TCP/8888"
        )
        path = _write(
            tmp_path / "server-listener-x.json",
            {
                "results": {
                    "mtproto_orig": {
                        "verdict": "ERROR",
                        "handshake_count": 0,
                        "data_transfer_ok": False,
                        "note": note_text,
                    }
                }
            },
        )
        _, protos = parse_listener_report(path)
        assert protos[0]["note"] == note_text

    def test_note_missing_falls_back_to_none(self, tmp_path: Path) -> None:
        # Older listener reports predate ``note`` — column must be NULL,
        # not an empty string, so the dashboard's noValue placeholder
        # (`—`) renders instead of a blank cell.
        path = _write(
            tmp_path / "server-listener-x.json",
            {
                "results": {
                    "wireguard": {
                        "verdict": "OK",
                        "handshake_count": 1,
                        "data_transfer_ok": True,
                    }
                }
            },
        )
        _, protos = parse_listener_report(path)
        assert protos[0]["note"] is None

    def test_note_wrong_type_coerced_to_none(self, tmp_path: Path) -> None:
        # A defensive guard against future schema drift — if a producer
        # somehow writes a non-string into ``note`` it must NOT crash
        # the importer or land as a stringified dict in the DB.
        path = _write(
            tmp_path / "server-listener-x.json",
            {
                "results": {
                    "openvpn": {
                        "verdict": "BLOCKED",
                        "handshake_count": 0,
                        "data_transfer_ok": False,
                        "note": {"unexpected": "object"},
                    }
                }
            },
        )
        _, protos = parse_listener_report(path)
        assert protos[0]["note"] is None

    def test_client_connected_inferred_from_client_meta(self, tmp_path: Path) -> None:
        # Older reports predate client_connected — fall back to
        # "did the listener produce any client meta?".
        path = _write(
            tmp_path / "server-listener-x.json",
            {"client": {"location": {"country_code": "RU"}}, "results": {}},
        )
        meta, _ = parse_listener_report(path)
        assert meta["client_connected"] is True
        assert meta["client_meta"] is not None

    def test_client_not_connected_state(self, tmp_path: Path) -> None:
        # State 3: client never reached the cred-server endpoint.
        path = _write(
            tmp_path / "server-listener-x.json",
            {"client_connected": False, "client": None, "results": {}},
        )
        meta, _ = parse_listener_report(path)
        assert meta["client_connected"] is False
        assert meta["client_meta"] is None

    def test_client_connected_but_no_enrichment(self, tmp_path: Path) -> None:
        # State 2: connected, but ipapi.is enrichment failed → client=None.
        path = _write(
            tmp_path / "server-listener-x.json",
            {"client_connected": True, "client": None, "results": {}},
        )
        meta, _ = parse_listener_report(path)
        assert meta["client_connected"] is True
        assert meta["client_meta"] is None

    def test_results_not_a_dict_skips_body(self, tmp_path: Path) -> None:
        # A future writer that accidentally stores results as a list
        # must not crash the importer — log + drop body.
        path = _write(
            tmp_path / "server-listener-x.json",
            {"session_id": "x", "results": [{"protocol": "wireguard"}]},
        )
        meta, protos = parse_listener_report(path)
        assert meta["session_id"] == "x"
        assert protos == []

    def test_non_dict_protocol_value_skipped(self, tmp_path: Path) -> None:
        # If one protocol entry has a scalar value, skip just that one
        # — the rest of the protocols still import.
        path = _write(
            tmp_path / "server-listener-x.json",
            {
                "results": {
                    "broken": "not a dict",
                    "wireguard": {"verdict": "OK", "handshake_count": 1},
                }
            },
        )
        _, protos = parse_listener_report(path)
        assert {p["protocol"] for p in protos} == {"wireguard"}

    def test_missing_verdict_falls_back_to_blocked(self, tmp_path: Path) -> None:
        # Listener default is BLOCKED (most pessimistic) — if a future
        # writer omits the field, we err on the side of "did not work".
        path = _write(
            tmp_path / "server-listener-x.json",
            {"results": {"wireguard": {}}},
        )
        _, protos = parse_listener_report(path)
        assert protos[0]["verdict"] == "BLOCKED"

    def test_corrupt_json_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "server-listener-x.json"
        path.write_text("not json", encoding="utf-8")
        meta, protos = parse_listener_report(path)
        assert meta == {}
        assert protos == []
