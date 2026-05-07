"""Shared helpers for building TestResult evidence dictionaries."""

from __future__ import annotations


def describe_exception(e: BaseException) -> str:
    """Render an exception so the resulting string is never empty.

    ``str(httpx.ConnectError())`` is empty when the underlying httpcore
    chain produced no message — that surfaced historically as
    ``evidence: {"error": ""}`` in saved reports (e.g. the May 2026
    ya-zone-a run for ``cloudflare_http_pages_dev`` and the prior run
    for ``http_currenttime_tv``) and gave the dashboard nothing to
    display. Fall back to the cause/context chain and finally the
    class name so the evidence always carries a useful token.

    Used by every module path that previously did ``str(e)`` directly.
    """
    msg = str(e).strip()
    if msg:
        return msg
    cause = getattr(e, "__cause__", None) or getattr(e, "__context__", None)
    if cause is not None:
        cause_msg = str(cause).strip()
        if cause_msg:
            return f"{type(e).__name__}: {cause_msg}"
    return f"{type(e).__name__} (no message)"
