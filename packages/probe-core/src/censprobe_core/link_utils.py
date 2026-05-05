"""
link_utils.py — Tun/wireguard interface housekeeping shared by listener + client.

Both sides spawn deterministic-named tun / wg / awg interfaces (so a
crashed run leaves something we can scrub afterwards) and both have to
unlink amneziawg-go's userspace control socket — ``ip link del`` only
removes the TUN, the unix socket persists and trips up the next
``awg-quick up``.

Two flavours of helper are exposed:

  * sync ``delete_iface`` / ``rm_amneziawg_socket`` — for callers that
    drive ``subprocess.run`` synchronously inside ``run_in_executor``
    (the listener responders do this on start/stop).
  * async ``async_delete_iface`` / ``async_rm_amneziawg_socket`` — for
    callers that already live in an asyncio loop and want the same
    behaviour without an executor hop (the client-side probes).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


# amneziawg-go writes its userspace control socket under this directory.
# The vanilla wireguard daemon uses /var/run/wireguard, which is why the
# AWG path needs a separate cleanup helper.
AMNEZIAWG_RUNDIR: Path = Path("/var/run/amneziawg")


# ─────────────────────────────────────────────────────────────────────────────
# Sync helpers (subprocess.run)
# ─────────────────────────────────────────────────────────────────────────────


def delete_iface(name: str) -> None:
    """Best-effort ``ip link del <name>``; never raises.

    Used to scrub a stale tun/wg/awg device left by a SIGKILLed previous
    run. Calling ``ip link del`` on an interface that does not exist
    returns non-zero — that is the normal case here, so we drop both
    streams and the return code on the floor.
    """
    subprocess.run(
        ["ip", "link", "del", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def rm_amneziawg_socket(iface: str) -> None:
    """Best-effort cleanup of leftover amneziawg-go control socket for ``iface``.

    A leftover ``.sock`` file makes the next ``awg-quick up`` fail with
    "address already in use"; deleting an absent file is a no-op.
    """
    try:
        (AMNEZIAWG_RUNDIR / f"{iface}.sock").unlink(missing_ok=True)
    except OSError as e:
        logger.debug("awg socket cleanup for %s failed: %s", iface, e)


# ─────────────────────────────────────────────────────────────────────────────
# Async helpers (asyncio.create_subprocess_exec)
# ─────────────────────────────────────────────────────────────────────────────


async def async_delete_iface(name: str, timeout: float = 3.0) -> None:
    """Async ``ip link del``; never raises. Bounded by ``timeout``.

    Used by the client-side probes that already drive subprocesses through
    asyncio. The deadline guards against an unresponsive ``ip`` call when
    the host is under heavy load.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip",
            "link",
            "del",
            name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return
    try:
        # Python 3.11+ context manager (S7483) instead of asyncio.wait_for(...).
        async with asyncio.timeout(timeout):
            await proc.wait()
    except TimeoutError:
        with contextlib.suppress(OSError):
            proc.kill()
        # wait() can race with kill — we only need an upper bound.
        with contextlib.suppress(Exception):
            await proc.wait()


async def async_rm_amneziawg_socket(iface: str) -> None:
    """Async wrapper around :func:`rm_amneziawg_socket`.

    The underlying op is a single ``unlink`` system call — fast enough
    that we don't bother with an executor hop, but exposing an async
    version keeps call-sites uniform with the rest of the asyncio probe.
    """
    # Yield once so this is a real coroutine — Sonar S7503 otherwise flags
    # "no async features used". The unlink itself is a one-syscall op.
    await asyncio.sleep(0)
    rm_amneziawg_socket(iface)
