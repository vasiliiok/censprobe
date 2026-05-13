"""
utils.py — Cross-package helpers that don't belong to a single domain.

Kept intentionally narrow: anything here must have at least two unrelated
callers. Single-use helpers stay in their owning module.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
import re
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

if TYPE_CHECKING:
    from censprobe_core.models import TestResult


_P_TEST = ParamSpec("_P_TEST")
_TR = TypeVar("_TR", bound="TestResult | None")


def stamp_test_elapsed(
    fn: Callable[_P_TEST, Coroutine[Any, Any, _TR]],
) -> Callable[_P_TEST, Coroutine[Any, Any, _TR]]:
    """Wrap a solo-module ``_test_*`` coroutine so its returned
    :class:`TestResult` always carries ``elapsed_ms`` set to the
    coroutine's total wall-clock runtime.

    Mirrors ``protocol_probes._stamp_elapsed`` but for the
    ``TestResult``/Pydantic side (solo modules: tcp/dns/tls/http/
    telegram/cloudflare/throttling/middlebox).

    No-op when the wrapped coroutine returned ``None`` (some helpers
    skip cleanly with no result), or when it already populated
    ``elapsed_ms`` itself (preserve any more nuanced measurement).

    Return type is ``Coroutine`` (not the broader ``Awaitable``) so
    callers wrapping the result in ``asyncio.create_task`` typecheck
    cleanly — ``create_task`` rejects bare ``Awaitable`` because it
    needs a real coroutine object.
    """

    @functools.wraps(fn)
    async def wrapper(*args: _P_TEST.args, **kwargs: _P_TEST.kwargs) -> _TR:
        t0 = time.monotonic()
        result = await fn(*args, **kwargs)
        if result is not None and result.elapsed_ms is None:
            result.elapsed_ms = (time.monotonic() - t0) * 1000
        return result

    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Identifier validation
# ─────────────────────────────────────────────────────────────────────────────

# `test_id` and `session_id` flow into filesystem paths (`reports/<id>/...`)
# and into Postgres row keys. The regex accepts the documented naming
# conventions (`<provider>-<city>-<NN>` / `client-<type>-<provider>-<city>`)
# and rejects everything that could path-traverse, smuggle a NULL byte,
# or break SQL/Grafana templating downstream.
# `\A` and `\Z` anchor against the absolute start / end of the string.
# `^` and `$` would silently allow a trailing `\n` (Python regex default),
# letting "vu-fra-01\n" smuggle a control character into a filesystem
# path or SQL row key. Property test exhibits the case explicitly.
SAFE_ID_RE: re.Pattern[str] = re.compile(r"\A[A-Za-z0-9_.-]{1,64}\Z")


def validate_id(field: str, value: str) -> str:
    """Return ``value`` if it matches :data:`SAFE_ID_RE`, else raise ValueError.

    Raises ValueError so callers in different frameworks can re-wrap the
    failure however they like (click.BadParameter, FastAPI HTTPException,
    plain CLI sys.exit, etc.). The message names the offending field so
    operators do not have to guess which CLI flag to fix.
    """
    if not SAFE_ID_RE.match(value):
        raise ValueError(f"{field} must match [A-Za-z0-9_.-] (1-64 chars); got {value!r}")
    return value


# ─────────────────────────────────────────────────────────────────────────────
# Atomic 0o600 write
# ─────────────────────────────────────────────────────────────────────────────


def write_secret(path: Path, content: str | bytes) -> None:
    """Create ``path`` with mode 0o600 atomically and write ``content``.

    ``Path.write_text`` + ``Path.chmod`` opens a TOCTOU window during which
    the freshly-created file inherits the process umask (typically 0o022 →
    world-readable). For credential material — WG/AWG private keys,
    OpenVPN PSKs, Reality private keys, ephemeral cred-server TLS keys —
    even a few microseconds of world-readable existence on a multi-tenant
    host is a real exposure. ``os.open(O_CREAT, 0o600)`` sets the mode at
    creation, closing the window.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if isinstance(content, bytes):
            with os.fdopen(fd, "wb") as fh:
                fh.write(content)
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
    except BaseException:
        # If fdopen() itself failed, the fd was never wrapped and we have
        # to close it by hand to avoid a descriptor leak.
        try:
            os.close(fd)
        except OSError:
            pass
        raise


# ─────────────────────────────────────────────────────────────────────────────
# asyncio subprocess shutdown
# ─────────────────────────────────────────────────────────────────────────────


async def graceful_terminate(
    proc: asyncio.subprocess.Process,
    timeout: float = 0.5,
) -> None:
    """SIGTERM ``proc``, fall back to SIGKILL after ``timeout``, then reap.

    ``asyncio.subprocess.Process.returncode`` only updates once ``wait()``
    observes the exit, so a naive ``terminate() + sleep + returncode is None``
    check would always end up calling ``kill()`` and leave the child as a
    zombie until ``wait()`` runs. The pair of awaits below guarantees both
    a real graceful window and a final reap, even on the SIGKILL branch.
    """
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except OSError:
        # ProcessLookupError is an OSError subclass — Sonar S5713.
        return
    try:
        # Python 3.11+ idiom over asyncio.wait_for(... timeout=) (S7483).
        async with asyncio.timeout(timeout):
            await proc.wait()
        return
    except TimeoutError:
        pass
    with contextlib.suppress(OSError, ProcessLookupError):
        proc.kill()
    # wait() can race with kill — we only need an upper bound, not a
    # propagated exception. The caller treats this as best-effort cleanup.
    with contextlib.suppress(Exception):
        await proc.wait()
