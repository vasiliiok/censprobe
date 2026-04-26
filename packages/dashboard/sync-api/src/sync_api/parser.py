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
    """Extract common metadata from a report dict.

    Defensive: every field falls back to a typed empty value so a partially
    written report (or a future schema change) can't surface a TypeError
    deep inside the importer.
    """
    return {
        "report_type": data.get("report_type", "solo"),
        "test_id": data.get("test_id", ""),
        "generated_at": _parse_dt(data.get("generated_at")),
        "server_meta": data.get("server_meta") or {},
        "scores": data.get("scores") or {},
        "results": data.get("results") or [],
        "summary": data.get("summary") or {},
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
    if not raw or not isinstance(raw, dict):
        return {}, []

    meta = parse_report_meta(raw)
    results: list[dict[str, Any]] = []
    raw_results = raw.get("results", [])
    if not isinstance(raw_results, list):
        logger.warning("Report %s: 'results' is not a list (%s); skipping body",
                       path.name, type(raw_results).__name__)
        return meta, []

    for r in raw_results:
        if not isinstance(r, dict):
            continue
        results.append({
            "report_file": path.name,
            "test": str(r.get("test") or ""),
            "category": str(r.get("category") or ""),
            "target": str(r.get("target") or ""),
            "verdict": str(r.get("verdict") or "INCONCLUSIVE"),
            "method": r.get("method"),
            "confidence": _to_float(r.get("confidence"), default=1.0),
            "rtt_ms": _to_float(r.get("rtt_ms"), default=None),
            "attempts": _to_int(r.get("attempts"), default=1),
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
    if not raw or not isinstance(raw, dict):
        return {}, []

    session_meta = {
        "report_file": path.name,
        "session_id": str(raw.get("session_id") or ""),
        "started_at": _parse_dt(raw.get("listener_started_at")),
        "stopped_at": _parse_dt(raw.get("listener_stopped_at")),
        "duration_sec": _to_float(raw.get("duration_sec"), default=None),
    }

    protocol_results: list[dict[str, Any]] = []
    raw_proto = raw.get("results", {})
    # Listener writes results as a mapping of protocol → ProtocolResult; defensively
    # accept absence (empty mapping) but skip any other shape so a corrupt file
    # can't crash the importer.
    if not isinstance(raw_proto, dict):
        logger.warning("Listener report %s: 'results' is not a dict (%s); skipping",
                       path.name, type(raw_proto).__name__)
        return session_meta, []

    for protocol, pr in raw_proto.items():
        if not isinstance(pr, dict):
            continue
        protocol_results.append({
            "protocol": str(protocol),
            "verdict": str(pr.get("verdict") or "BLOCKED"),
            "handshake_count": _to_int(pr.get("handshake_count"), default=0),
            "data_transfer_ok": bool(pr.get("data_transfer_ok") or False),
            "avg_rtt_ms": _to_float(pr.get("avg_rtt_ms"), default=None),
            "from_asn": pr.get("from_asn"),
        })

    return session_meta, protocol_results


# Filename predicates: prefix + extension. We only match the canonical
# .json / .json.gz suffixes so a stray editor swap-file ("server-solo-…json~")
# or a tarball ("server-solo-…tar.gz") never gets handed to the JSON loader.
def is_solo_report(filename: str) -> bool:
    return filename.startswith("server-solo-") and (
        filename.endswith(".json") or filename.endswith(".json.gz")
    )


def is_listener_report(filename: str) -> bool:
    return filename.startswith("server-listener-") and (
        filename.endswith(".json") or filename.endswith(".json.gz")
    )


def _load_gz(path: Path) -> Optional[dict]:
    """Load a .json.gz or .json file into a dict.

    Returns None on any I/O / decode failure so callers can short-circuit
    cleanly (a half-written report on disk during a concurrent push is the
    common case — log it and let the next /refresh re-try).
    """
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as f:
                payload = f.read()
        else:
            payload = path.read_bytes()
        if not payload:
            logger.warning("Report %s is empty; skipping", path.name)
            return None
        return json.loads(payload)
    except gzip.BadGzipFile as e:
        logger.error("Report %s: corrupt gzip (%s); skipping", path.name, e)
        return None
    except json.JSONDecodeError as e:
        logger.error("Report %s: invalid JSON at line %d col %d: %s",
                     path.name, e.lineno, e.colno, e.msg)
        return None
    except OSError as e:
        logger.error("Report %s: I/O error: %s", path.name, e)
        return None
    except Exception as e:
        # Last-ditch guard so one weird file never aborts the whole refresh.
        logger.error("Report %s: unexpected parse error: %s", path.name, e)
        return None


def _to_float(value: Any, default: Optional[float]) -> Optional[float]:
    """Coerce a JSON value to float, accepting None/strings/missing."""
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int) -> int:
    """Coerce a JSON value to int, accepting None/strings/missing."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


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
