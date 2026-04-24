"""
parser.py — Parse censprobe report files (.json or legacy .json.gz) into DB models.

Handles:
  - server-solo-<ts>.json[.gz]            → TestRun + TestResult rows
  - server-listener-<session>-<ts>.json[.gz] → ListenerSession + ProtocolResult rows
"""
from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def parse_report_meta(data: dict) -> dict[str, Any]:
    """Extract common metadata from a report dict."""
    return {
        "report_type": data.get("report_type", "solo"),
        "test_id": data.get("test_id", ""),
        "generated_at": _parse_dt(data.get("generated_at")),
        "server_meta": data.get("server_meta") or {},
        "scores": data.get("scores") or {},
        "results": data.get("results", []),
        "summary": data.get("summary", {}),
    }


def parse_solo_report(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Parse a server-solo-*.json[.gz] report.

    Returns:
        (meta_dict, list_of_result_dicts)
    """
    raw = _load_gz(path)
    if not raw:
        return {}, []

    meta = parse_report_meta(raw)
    results = []
    for r in raw.get("results", []):
        results.append({
            "report_file": path.name,
            "test": r.get("test", ""),
            "category": r.get("category", ""),
            "target": r.get("target", ""),
            "verdict": r.get("verdict", "INCONCLUSIVE"),
            "method": r.get("method"),
            "confidence": float(r.get("confidence", 1.0)),
            "rtt_ms": r.get("rtt_ms"),
            "attempts": int(r.get("attempts", 1)),
            "notes": r.get("notes"),
            "timestamp": _parse_dt(r.get("timestamp")),
            "source": "solo",
        })

    return meta, results


def parse_listener_report(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Parse a server-listener-<session>-*.json[.gz] report.

    Returns:
        (session_dict, list_of_protocol_result_dicts)
    """
    raw = _load_gz(path)
    if not raw:
        return {}, []

    session_meta = {
        "report_file": path.name,
        "session_id": raw.get("session_id", ""),
        "started_at": _parse_dt(raw.get("listener_started_at")),
        "stopped_at": _parse_dt(raw.get("listener_stopped_at")),
        "duration_sec": raw.get("duration_sec"),
    }

    protocol_results = []
    for protocol, pr in raw.get("results", {}).items():
        protocol_results.append({
            "protocol": protocol,
            "verdict": pr.get("verdict", "BLOCKED"),
            "handshake_count": int(pr.get("handshake_count", 0)),
            "data_transfer_ok": bool(pr.get("data_transfer_ok", False)),
            "avg_rtt_ms": pr.get("avg_rtt_ms"),
            "from_asn": pr.get("from_asn"),
        })

    return session_meta, protocol_results


def is_solo_report(filename: str) -> bool:
    return filename.startswith("server-solo-")


def is_listener_report(filename: str) -> bool:
    return filename.startswith("server-listener-")


def _load_gz(path: Path) -> Optional[dict]:
    """Load a .json.gz or .json file into a dict."""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as f:
                return json.loads(f.read())
        else:
            return json.loads(path.read_text())
    except Exception as e:
        logger.error("Failed to parse report %s: %s", path.name, e)
        return None


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse an ISO datetime string into a timezone-aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None
