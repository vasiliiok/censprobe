"""
parser.py — Parse censprobe report files (.json) into DB models.

Handles:
  - server-solo-<ts>.json            → TestRun + TestResult rows
  - server-listener-<session>-<ts>.json → ListenerSession + ProtocolResult rows
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from censprobe_core.subcategories import derive as _derive_subcategory

logger = logging.getLogger(__name__)


def parse_report_meta(data: dict[str, Any]) -> dict[str, Any]:
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
    Parse a server-solo-*.json report.

    Returns:
        (meta_dict, list_of_result_dicts)
    """
    raw = load_json(path)
    if not raw or not isinstance(raw, dict):
        return {}, []

    meta = parse_report_meta(raw)
    results: list[dict[str, Any]] = []
    raw_results = raw.get("results", [])
    if not isinstance(raw_results, list):
        logger.warning(
            "Report %s: 'results' is not a list (%s); skipping body",
            path.name,
            type(raw_results).__name__,
        )
        return meta, []

    for r in raw_results:
        if not isinstance(r, dict):
            continue
        test_name = str(r.get("test") or "")
        category = str(r.get("category") or "")
        # Trust the producer's subcategory if present, otherwise derive
        # it here. Older reports written before the field existed
        # quietly pick up the right subcategory on re-import.
        subcategory = r.get("subcategory")
        if not isinstance(subcategory, str) or not subcategory:
            subcategory = _derive_subcategory(test_name, category)
        results.append(
            {
                "report_file": path.name,
                "test": test_name,
                "category": category,
                "subcategory": subcategory,
                "target": str(r.get("target") or ""),
                "verdict": str(r.get("verdict") or "INCONCLUSIVE"),
                "method": r.get("method"),
                "confidence": _to_float(r.get("confidence"), default=1.0),
                "rtt_ms": _to_float(r.get("rtt_ms"), default=None),
                "elapsed_ms": _to_float(r.get("elapsed_ms"), default=None),
                "attempts": _to_int(r.get("attempts"), default=1),
                "notes": r.get("notes"),
                "timestamp": _parse_dt(r.get("timestamp")),
                "source": "solo",
            }
        )

    return meta, results


def parse_listener_report(
    path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Parse a server-listener-<session>-*.json report.

    Returns:
        (session_dict, list_of_protocol_result_dicts)
    """
    raw = load_json(path)
    if not raw or not isinstance(raw, dict):
        return {}, []

    # client_meta is whatever the listener wrote (a serialized
    # EndpointMeta dict) or None — defensive isinstance check guards
    # against a future schema migration handing us a list/scalar in
    # this slot. client_connected falls back to "did the listener
    # produce any client meta?" for older reports that predate the
    # explicit flag.
    raw_client = raw.get("client")
    client_meta = raw_client if isinstance(raw_client, dict) else None
    raw_connected = raw.get("client_connected")
    if isinstance(raw_connected, bool):
        client_connected = raw_connected
    else:
        client_connected = client_meta is not None

    # session_id is the dedup key for the UPSERT-by-SID path in the
    # importer. Reports written by listener after commit 959a12b (May 2026,
    # auto-gen session_id) always carry a non-empty SID. Older historical
    # reports (re-imported from a backup) may have an empty SID — in that
    # case the importer's UPSERT-by-SID branch is skipped entirely and
    # each empty-SID report lands as its own ListenerSession row (still
    # deduped on the `(test_run_id, report_file)` UNIQUE constraint, so a
    # single file can't double-import). Producers MUST emit a non-empty
    # session_id; this is a defensive read, not a contract relaxation.
    session_meta = {
        "report_file": path.name,
        "session_id": str(raw.get("session_id") or ""),
        "started_at": _parse_dt(raw.get("listener_started_at")),
        "stopped_at": _parse_dt(raw.get("listener_stopped_at")),
        "duration_sec": _to_float(raw.get("duration_sec"), default=None),
        "client_connected": client_connected,
        "client_meta": client_meta,
        # Listener writes these as top-level booleans from its CLI flags.
        # Older reports predate the field — default False keeps them on
        # the "regular network" axis.
        "is_mobile": bool(raw.get("is_mobile", False)),
        "is_whitelist": bool(raw.get("is_whitelist", False)),
    }

    protocol_results: list[dict[str, Any]] = []
    raw_proto = raw.get("results", {})
    # Listener writes results as a mapping of protocol → ProtocolResult; defensively
    # accept absence (empty mapping) but skip any other shape so a corrupt file
    # can't crash the importer.
    if not isinstance(raw_proto, dict):
        logger.warning(
            "Listener report %s: 'results' is not a dict (%s); skipping",
            path.name,
            type(raw_proto).__name__,
        )
        return session_meta, []

    for protocol, pr in raw_proto.items():
        if not isinstance(pr, dict):
            continue
        protocol_results.append(
            {
                "protocol": str(protocol),
                "verdict": str(pr.get("verdict") or "BLOCKED"),
                "handshake_count": _to_int(pr.get("handshake_count"), default=0),
                "data_transfer_ok": bool(pr.get("data_transfer_ok")),
                # Listener-measured sustained throughput. Older listener
                # reports predate the field — `_to_float(None, default=None)`
                # quietly leaves the column NULL, which is exactly what the
                # dashboard expects for "not measured".
                "avg_throughput_mbps": _to_float(
                    pr.get("avg_throughput_mbps"),
                    default=None,
                ),
                "throughput_throttled": bool(pr.get("throughput_throttled", False)),
            }
        )

    return session_meta, protocol_results


# Filename predicates: only the canonical .json suffix. Stray editor swap
# files ("server-solo-…json~") or tarballs ("server-solo-…tar.gz") are
# never handed to the JSON loader.
def is_solo_report(filename: str) -> bool:
    return filename.startswith("server-solo-") and filename.endswith(".json")


def is_listener_report(filename: str) -> bool:
    return filename.startswith("server-listener-") and filename.endswith(".json")


# Cap individual report payloads to 50 MB. Real censprobe reports are
# under 1 MB; anything an order of magnitude beyond that is either a
# disk-fill mistake or a malicious symlink-target. read_bytes() reads
# the whole file at once and a 10 GB file would OOM the importer.
_MAX_REPORT_BYTES = 50 * 1024 * 1024


def load_json(path: Path) -> dict[str, Any] | None:
    """Load a .json file into a dict.

    Returns None on any I/O / decode failure so callers can short-circuit
    cleanly (a half-written report on disk during a concurrent push is the
    common case — log it and let the next import re-try).

    Defensive guards:
      * Skip symlinks. The reports tree is whatever an operator
        ``git pull``s — a malicious PR can ship a symlink at
        ``reports/<test_id>/foo.json → /etc/passwd`` which would
        otherwise be read into memory and JSON-parsed. Files reach
        here only when produced by solo/listener (their ``write_text``
        creates regular files), so any symlink in this position is
        suspect.
      * Cap file size at _MAX_REPORT_BYTES.
    """
    try:
        if path.is_symlink():
            logger.warning("Report %s is a symlink; refusing to follow", path.name)
            return None
        try:
            size = path.stat().st_size
        except OSError:
            # ``logger.exception`` auto-attaches the traceback so we
            # don't have to format the exception ourselves (S8572).
            logger.exception("Report %s: stat failed", path.name)
            return None
        if size > _MAX_REPORT_BYTES:
            logger.error(
                "Report %s is %d bytes (>%d cap); refusing to load",
                path.name,
                size,
                _MAX_REPORT_BYTES,
            )
            return None
        payload = path.read_bytes()
        if not payload:
            logger.warning("Report %s is empty; skipping", path.name)
            return None
        result = json.loads(payload)
        if not isinstance(result, dict):
            logger.warning("Report %s: top-level JSON is not an object; skipping", path.name)
            return None
        return result
    except json.JSONDecodeError as e:
        # Keep the structured lineno/colno/msg fields — operators
        # parsing logs grep on the line+col, and the traceback alone
        # doesn't surface them at the top of the log line. Switching
        # to ``logger.exception`` keeps the same structured prefix
        # and appends the traceback automatically (S8572).
        logger.exception(
            "Report %s: invalid JSON at line %d col %d: %s",
            path.name,
            e.lineno,
            e.colno,
            e.msg,
        )
        return None
    except OSError:
        logger.exception("Report %s: I/O error", path.name)
        return None
    except Exception:
        # Last-ditch guard so one weird file never aborts the whole import.
        logger.exception("Report %s: unexpected parse error", path.name)
        return None


def _to_float(value: Any, default: float | None) -> float | None:
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


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO datetime string into a timezone-aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except Exception:
        return None
