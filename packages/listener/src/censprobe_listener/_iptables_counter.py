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

logger = logging.getLogger(__name__)


# We mirror every rule on both IPv4 (``iptables``) and IPv6
# (``ip6tables``). On dual-stack hosts both fire when the client
# arrives over the matching family; reads sum across families.
_IPTABLES_FAMILIES = ("iptables", "ip6tables")

# Per-call subprocess timeout. iptables operations on a healthy
# kernel finish in ms; the only time they stall is when the kernel
# is mid-NF-CONNTRACK exhaustion. Cap at 5 s so a stuck iptables
# binary doesn't wedge listener startup.
_IPTABLES_TIMEOUT_S = 5.0


async def install_counter(chain: str, rule_args: list[str], comment: str) -> bool:
    """Install the counter rule on iptables AND ip6tables.

    Returns True if the rule is now in place on at least one
    family (so the caller knows whether to expect non-zero reads).
    Idempotent: uses ``-C`` to check before ``-A``, so re-installs
    across listener restarts don't double-count.
    """
    installed_anywhere = False
    for cmd in _IPTABLES_FAMILIES:
        if shutil.which(cmd) is None:
            continue
        try:
            check = await asyncio.wait_for(
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
            check_rc = await asyncio.wait_for(check.wait(), timeout=_IPTABLES_TIMEOUT_S)
        except (TimeoutError, OSError) as e:
            logger.warning("%s -C %s for %r failed: %s", cmd, chain, comment, e)
            continue
        if check_rc == 0:
            # Already present from a previous crashed listener — leave
            # in place so the counter starts at zero (kernel resets
            # counters on rule re-install via -R, but -C followed by
            # nothing leaves the existing counter intact, which we want
            # since `_cleanup_orphan_rules` in preflight already removed
            # truly stale rules before we got here).
            installed_anywhere = True
            continue
        try:
            add = await asyncio.wait_for(
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
            rc = await asyncio.wait_for(add.wait(), timeout=_IPTABLES_TIMEOUT_S)
        except (TimeoutError, OSError) as e:
            logger.warning("%s -A %s for %r failed: %s", cmd, chain, comment, e)
            continue
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
            continue
        installed_anywhere = True
    return installed_anywhere


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


async def _scrape_counter_column(chain: str, comment: str, *, column: int) -> int:
    """Shared scrape: read ``column`` (0=pkts, 1=bytes) summed across
    iptables and ip6tables for the rule with ``--comment <comment>``.
    """
    total = 0
    for cmd in _IPTABLES_FAMILIES:
        if shutil.which(cmd) is None:
            continue
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
            continue
        for ln in out_b.decode(errors="replace").splitlines():
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


def read_counter_sync(chain: str, comment: str) -> int:
    """Synchronous twin of :func:`read_counter` for use from non-async
    contexts (specifically the cred-server's snapshot HTTP handler,
    which runs in a stdlib http.server thread without an event loop).

    Same iptables/ip6tables -L -v -n -x scrape, same comment-match
    summing across families. We don't share the parser because the
    async version would force the caller to bridge via
    ``asyncio.run_coroutine_threadsafe`` — adding a sync helper is
    less code and removes the cross-thread asyncio coupling.

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
            if not parts:
                continue
            try:
                total += int(parts[0])
            except ValueError:
                continue
    return total


async def remove_counter(chain: str, rule_args: list[str]) -> None:
    """Best-effort rule delete on both iptables and ip6tables.

    Suppresses non-zero rc — if the rule doesn't exist (e.g. because
    install failed earlier with no CAP_NET_ADMIN), we'd just be
    deleting a phantom and the kernel rightly errors. Don't surface
    that as a warning; it's the expected path.
    """
    for cmd in _IPTABLES_FAMILIES:
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
