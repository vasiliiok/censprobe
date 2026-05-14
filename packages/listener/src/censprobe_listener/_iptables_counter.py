"""
Shared iptables / ip6tables counter primitives used by VPN responders.

Each VPN responder installs ONE accounting rule with a unique
comment when it starts; reads the kernel-side packet counter at
stop time; and removes the rule on clean shutdown. We mirror the
rule on ``ip6tables`` so IPv6-arriving probes also tick the
counter, preventing a false-HANDSHAKE_ONLY split when the client
happens to use an IPv6 path (an AAAA record, dual-stack happy
eyeballs, etc).

The rules have NO ``-j`` target — they're counter-only matches
that fall through to subsequent host-firewall rules. We
deliberately avoid ``-j ACCEPT`` because that would short-circuit
any user-installed firewall on the same chain, and we deliberately
avoid creating a custom chain because iptables' rule-matching
semantics for ``-C`` (idempotency check) do not work with custom
chains as targets.

All three operations are best-effort: when ``iptables`` /
``ip6tables`` is not on PATH (alpine, macOS dev box) or rule
install fails (no CAP_NET_ADMIN), we log a single WARNING and
return — the caller's listener-side verdict then degrades to
"data_transfer_ok=False" rather than crashing the listener.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# We mirror every rule on both IPv4 (``iptables``) and IPv6
# (``ip6tables``). On dual-stack hosts both fire when the client
# arrives over the matching family; reads sum across families.
_IPTABLES_FAMILIES = ("iptables", "ip6tables")


@dataclass(frozen=True)
class InstallStatus:
    """Per-family iptables install outcome.

    ``installed_families`` lists the family commands (e.g. ``("iptables",
    "ip6tables")``) where the accounting rule is now present — could be
    one, both, or neither. ``remove_counter`` consults this set to
    remove ONLY the families it installed on, avoiding the prior bug
    where a half-installed rule (iptables OK, ip6tables failed) would
    cause cleanup to invoke ``ip6tables -D`` on a non-existent rule
    and log spurious "rule does not exist" errors. Also makes
    ``bool(status)`` meaningful: True iff at least one family is live.

    Cleanup-only call sites (no original InstallStatus, e.g.
    :func:`preflight._cleanup_orphan_rules`) pass ``status=None`` to
    :func:`remove_counter` which falls back to iterating every known
    family — same pre-2026-05 behaviour, no factory needed.
    """

    installed_families: frozenset[str] = field(default_factory=frozenset)

    def __bool__(self) -> bool:
        return bool(self.installed_families)


# Per-call subprocess timeout. iptables operations on a healthy
# kernel finish in ms; the only time they stall is when the kernel
# is mid-NF-CONNTRACK exhaustion. Cap at 5 s so a stuck iptables
# binary doesn't wedge listener startup.
_IPTABLES_TIMEOUT_S = 5.0


async def _iptables_check(cmd: str, chain: str, rule_args: list[str], comment: str) -> bool:
    """Run ``<cmd> -C <chain> <rule_args>`` and return True iff the rule
    already exists (rc==0). Suppress process errors as False; caller logs.
    """
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                cmd,
                "-C",
                chain,
                *rule_args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=_IPTABLES_TIMEOUT_S,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=_IPTABLES_TIMEOUT_S)
    except (TimeoutError, OSError) as e:
        logger.warning("%s -C %s for %r failed: %s", cmd, chain, comment, e)
        return False
    return rc == 0


async def _iptables_add(cmd: str, chain: str, rule_args: list[str], comment: str) -> bool:
    """Run ``<cmd> -A <chain> <rule_args>`` and return True iff the
    rule was successfully added (rc==0). False on timeout, OSError, or
    non-zero rc (typically EACCES from missing CAP_NET_ADMIN).
    """
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                cmd,
                "-A",
                chain,
                *rule_args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=_IPTABLES_TIMEOUT_S,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=_IPTABLES_TIMEOUT_S)
    except (TimeoutError, OSError) as e:
        logger.warning("%s -A %s for %r failed: %s", cmd, chain, comment, e)
        return False
    if rc != 0:
        logger.warning(
            "%s -A %s rule install for %r returned rc=%d (likely missing "
            "CAP_NET_ADMIN); listener verdict will fall back to the "
            "non-counter heuristic for this protocol.",
            cmd,
            chain,
            comment,
            rc,
        )
        return False
    return True


async def install_counter(chain: str, rule_args: list[str], comment: str) -> InstallStatus:
    """Install the counter rule on iptables AND ip6tables.

    Returns an :class:`InstallStatus` listing the families where the
    rule is now in place — could be both, one, or neither. Callers
    pass this back to :func:`remove_counter` for symmetric cleanup
    (so a half-installed rule doesn't produce spurious
    "rule does not exist" log noise on the family that never got it).

    Idempotent: uses ``-C`` to check before ``-A``, so re-installs
    across listener restarts don't double-count. A pre-existing rule
    (left over from a crashed listener) counts as "installed" — we
    leave it in place rather than re-adding and resetting the kernel
    counter; ``_cleanup_orphan_rules`` already removed truly stale
    rules at preflight before we got here.
    """
    installed: set[str] = set()
    for cmd in _IPTABLES_FAMILIES:
        if shutil.which(cmd) is None:
            continue
        # -C succeeded → rule already present from a previous run.
        # -C failed AND -A succeeded → we just added it.
        # Either way the family ends up in the installed set; only
        # both-fail leaves the family out (no rule on this family,
        # remove_counter will skip it).
        if await _iptables_check(cmd, chain, rule_args, comment) or await _iptables_add(
            cmd, chain, rule_args, comment
        ):
            installed.add(cmd)
    return InstallStatus(installed_families=frozenset(installed))


async def read_counter_bytes(chain: str, comment: str) -> int:
    """Sum the rule's BYTE counter (column 1) across iptables + ip6tables.

    Counterpart to :func:`read_counter` which returns the packet count
    (column 0). Bytes are what SOCKS-tunneled responders need to compute
    wire-accurate throughput at the tunnel binary's WAN-facing port —
    TCP backpressure from the slow client link forces the kernel to
    drip-emit segments at line rate, so byte-count over time is the
    authoritative wire-throughput metric.

    Same iptables/ip6tables sum semantic as :func:`read_counter`. Returns
    0 when iptables is unavailable or the rule isn't installed; callers
    treat 0 as "no measurement" and fall back to wait_closed timing.
    """
    return await _scrape_counter_column(chain, comment, column=1)


async def read_counter(chain: str, comment: str) -> int:
    """Sum the rule's pkt counter across iptables + ip6tables.

    Returning the sum (rather than the per-family pair) matches the
    "did ANY data segment from a real client tick the counter?"
    semantic the responders use to set ``data_transfer_ok``.
    """
    return await _scrape_counter_column(chain, comment, column=0)


async def _iptables_list(cmd: str, chain: str, comment: str) -> str:
    """Capture ``<cmd> -L <chain> -v -n -x`` stdout as a decoded string.

    Returns ``""`` on subprocess failure so the caller's parsing loop
    becomes a no-op (no families contribute counters when iptables is
    broken — same behaviour as before the helper extraction).
    """
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                cmd,
                "-L",
                chain,
                "-v",
                "-n",
                "-x",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            ),
            timeout=_IPTABLES_TIMEOUT_S,
        )
        out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=_IPTABLES_TIMEOUT_S)
    except (TimeoutError, OSError) as e:
        logger.warning("%s -L %s for %r failed: %s", cmd, chain, comment, e)
        return ""
    return out_b.decode(errors="replace")


def _sum_column_for_comment(output: str, comment: str, column: int) -> int:
    """Parse iptables -L output; sum ``column`` for rows matching ``comment``."""
    total = 0
    for ln in output.splitlines():
        if comment not in ln:
            continue
        parts = ln.split()
        if len(parts) <= column:
            continue
        try:
            total += int(parts[column])
        except ValueError:
            continue
    return total


async def _scrape_counter_column(chain: str, comment: str, *, column: int) -> int:
    """Shared scrape: read ``column`` (0=pkts, 1=bytes) summed across
    iptables and ip6tables for the rule with ``--comment <comment>``.
    """
    total = 0
    for cmd in _IPTABLES_FAMILIES:
        if shutil.which(cmd) is None:
            continue
        out = await _iptables_list(cmd, chain, comment)
        total += _sum_column_for_comment(out, comment, column)
    return total


def read_counter_sync(chain: str, comment: str, *, column: int = 0) -> int:
    """Synchronous twin of :func:`read_counter` for use from non-async
    contexts (specifically the cred-server's snapshot HTTP handler,
    which runs in a stdlib http.server thread without an event loop).

    Same iptables/ip6tables -L -v -n -x scrape, same comment-match
    summing across families. We don't share the parser because the
    async version would force the caller to bridge via
    ``asyncio.run_coroutine_threadsafe`` — adding a sync helper is
    less code and removes the cross-thread asyncio coupling.

    ``column``: 0 = packets (default, matches async ``read_counter``);
    1 = bytes (matches async ``read_counter_bytes``). Previously
    hard-coded to column 0, which meant a future caller asking for
    bytes would silently get packets — fixed to keep the sync/async
    parity explicit.

    Errors are swallowed (returns 0) for the same best-effort reason
    as the async version: a missing iptables binary or a transient
    EAGAIN must not crash the responder snapshot.
    """
    total = 0
    for cmd in _IPTABLES_FAMILIES:
        if shutil.which(cmd) is None:
            continue
        try:
            proc = subprocess.run(  # noqa: S603 — args are hardcoded constants
                [cmd, "-L", chain, "-v", "-n", "-x"],
                capture_output=True,
                timeout=_IPTABLES_TIMEOUT_S,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("%s -L %s for %r failed (sync): %s", cmd, chain, comment, e)
            continue
        for ln in proc.stdout.decode(errors="replace").splitlines():
            if comment not in ln:
                continue
            parts = ln.split()
            if len(parts) <= column:
                continue
            try:
                total += int(parts[column])
            except ValueError:
                continue
    return total


async def remove_counter(
    chain: str,
    rule_args: list[str],
    status: InstallStatus | None = None,
) -> None:
    """Best-effort rule delete on the families that ``install_counter``
    successfully populated.

    Pass back the :class:`InstallStatus` returned by
    :func:`install_counter` so this function only invokes ``-D`` on
    families where the rule was actually installed — eliminates the
    spurious "rule does not exist" log noise on the family that
    silently failed at install time.

    ``status=None`` is the back-compat path: try both families,
    suppress per-family errors (the pre-2026-05 behaviour). Used by
    cleanup-only call sites that don't have an InstallStatus handy
    (e.g. ``preflight._cleanup_orphan_rules``).
    """
    families = status.installed_families if status is not None else _IPTABLES_FAMILIES
    for cmd in families:
        if shutil.which(cmd) is None:
            continue
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    cmd,
                    "-D",
                    chain,
                    *rule_args,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                ),
                timeout=_IPTABLES_TIMEOUT_S,
            )
            await asyncio.wait_for(proc.wait(), timeout=_IPTABLES_TIMEOUT_S)
        except (TimeoutError, OSError):
            # Best-effort; SIGKILL-on-shutdown leftovers will be
            # picked up by ``preflight._cleanup_orphan_rules`` on the
            # next start.
            continue
