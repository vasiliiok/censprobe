"""
preflight.py — Listener-side pre-startup environment checks.

Runs once during listener boot, before responders bind to ports. Surfaces
silent kernel/host conditions that would otherwise look like censorship
at the client side but are actually local resource exhaustion or
listener-side connectivity gaps. Canonical examples:

* ``nf_conntrack: table full, dropping packet`` — kernel drops new
  flows before they reach userspace; listener log is clean while every
  responder mysteriously stops responding.
* CAP_NET_ADMIN missing — iptables counters can't install, mtproto_*
  / openvpn data_transfer_ok stays False even on successful probes.
* Telegram DC unreachable from listener egress — mtproto_proxy /
  mtproto_orig probes timeout on the resPQ leg, returning
  HANDSHAKE_ONLY. Without this preflight the operator can't tell
  "client-side DPI" apart from "my listener can't reach DCs".

Each check returns a small status string ("ok" | "warn" | "skip") plus
a human-readable message. Listener startup never *aborts* on a warning
— operators may legitimately run on a constrained VM and not be able
to fix sysctls — but every WARN is printed loudly so the user gets the
chance to fix it before puzzling over the result table.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import subprocess  # noqa: S404 — listener already shells out elsewhere
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# Below this we treat the conntrack table as a ticking bomb. 65536 is the
# kernel default on most distros and is enough for a few thousand
# concurrent flows; smaller numbers are typically the result of a cloud
# VM image baseline (Yandex Cloud Ubuntu 24.04 ships with 8192) and
# *will* fill within minutes once a public IP is exposed to scanner
# traffic plus the listener's own protocol ports.
_CONNTRACK_MIN_MAX = 65536

# Once the table is more than half-full, retransmit storms during a
# probe run can push it over the edge mid-test. Surface this loudly.
_CONNTRACK_HIGH_WATER_RATIO = 0.5

# Target for the auto-raise — overshoots ``_CONNTRACK_MIN_MAX`` by 16x
# so a few short reboots' worth of half-closed entries don't slowly
# climb back into the warning band.
_CONNTRACK_TARGET_MAX = 1_048_576

_NF_MAX = Path("/proc/sys/net/netfilter/nf_conntrack_max")
_NF_COUNT = Path("/proc/sys/net/netfilter/nf_conntrack_count")

# Public Telegram DC IPv4 addresses. Sourced from
# ``targets/telegram.yaml`` (which the solo package treats as
# canonical) — duplicated here as a literal because the listener
# image doesn't volume-mount the targets/ dir during all
# deployments and we want this preflight to be self-contained.
# Three DCs is enough to distinguish "all blocked" (all 3 fail)
# from "one DC moved" (1-2 fail). If Telegram migrates an IP we
# tolerate up to 2 stale entries before this preflight gives a
# false WARN — refresh by re-reading the YAML on bump.
_TELEGRAM_DC_PROBES: tuple[tuple[str, int, str], ...] = (
    ("149.154.175.53", 443, "DC1 pluto"),
    ("149.154.167.51", 443, "DC2 venus"),
    ("149.154.175.100", 443, "DC3 aurora"),
)

# The C MTProxy binary upstreams to Telegram DCs on TCP/8888 (not 443).
# proxy-multi.conf is downloaded at image build time from
# https://core.telegram.org/getProxyConfig and baked into the runtime
# image at this path — see packages/listener/Dockerfile.
_PROXY_MULTI_CONF_PATH = Path("/usr/local/share/mtproxy-orig/proxy-multi.conf")

# Cap how many upstreams we probe at preflight. proxy-multi.conf
# typically has ~25 IPs; 6 distinct clusters is enough to distinguish
# "all unreachable" (0/6 succeed) from "one DC migrated" (1-2 fail).
_PROXY_MULTI_PROBE_SAMPLE = 6

# Per-IP TCP-connect budget when pruning proxy-multi.conf at responder
# startup. 1.5 s is long enough for a clean SYN/SYN-ACK across a normal
# RU↔EU/US WAN path but short enough that probing all ~25 IPs in
# parallel finishes well inside the 2 s responder-settle window.
_PROXY_MULTI_PRUNE_TIMEOUT_S = 1.5
# Concurrency cap for the prune probe — keeps the listener from opening
# 25+ simultaneous sockets at boot. proxy-multi.conf typically has
# fewer than 30 unique IPs, so this barely throttles anything in
# practice.
_PROXY_MULTI_PRUNE_PARALLEL = 16


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # "ok" | "warn" | "skip"
    message: str


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _check_conntrack(notrack_installed: bool = False) -> CheckResult:
    """Inspect host conntrack capacity and current load.

    Inside docker with ``--network host``, ``/proc/sys/net/netfilter``
    is mounted read-only by the container runtime — we can read the
    counters but not raise the limit. So this check WARNs rather than
    auto-fixing; the operator must raise it on the host.

    The severity drops to ``info`` (status="ok" + advisory message) when
    ``notrack_installed`` is True, because NOTRACK on the VPN UDP ports
    means the main probe traffic skips conntrack entirely. Internet
    scanner noise + TCP listener flows still consume the table, so
    the advisory still mentions the host-side fix — but it's no longer
    a load-bearing issue for VPN reachability.
    """
    nf_max = _read_int(_NF_MAX)
    nf_count = _read_int(_NF_COUNT)

    if nf_max is None or nf_count is None:
        return CheckResult(
            "conntrack",
            "skip",
            "no /proc/sys/net/netfilter/nf_conntrack_* — kernel without netfilter",
        )

    if nf_max < _CONNTRACK_MIN_MAX:
        sysctl_hint = (
            "Raise on host: sudo sysctl -w "
            f"net.netfilter.nf_conntrack_max={_CONNTRACK_TARGET_MAX} "
            "(persist via /etc/sysctl.d/99-conntrack.conf)."
        )
        if notrack_installed:
            return CheckResult(
                "conntrack",
                "ok",
                (
                    f"nf_conntrack_max={nf_max} (low), but VPN UDP ports are NOTRACK — "
                    f"VPN reachability is unaffected. {sysctl_hint}"
                ),
            )
        return CheckResult(
            "conntrack",
            "warn",
            (
                f"nf_conntrack_max={nf_max} (< {_CONNTRACK_MIN_MAX}) and NOTRACK auto-setup "
                f"unavailable (likely missing CAP_NET_ADMIN). Once full, kernel SILENTLY "
                f"DROPS new flows; clients see BLOCKED on half the protocols. {sysctl_hint}"
            ),
        )

    ratio = nf_count / nf_max
    if ratio > _CONNTRACK_HIGH_WATER_RATIO:
        return CheckResult(
            "conntrack",
            "warn",
            (
                f"nf_conntrack {nf_count}/{nf_max} ({ratio:.0%} full). "
                f"A probe burst may exhaust the table mid-test and silently drop handshakes. "
                f"Free up entries (timeouts will clear closed flows) or raise nf_conntrack_max."
            ),
        )

    return CheckResult(
        "conntrack",
        "ok",
        f"nf_conntrack {nf_count}/{nf_max} ({ratio:.0%} full)",
    )


def _check_dmesg_recent_drops() -> CheckResult:
    """Look for recent ``nf_conntrack: table full`` in dmesg.

    Distinct from the count/max ratio check because the table can be
    healthy *now* while having been overwhelmed minutes ago — leftover
    drop events are evidence the system is undersized for real load.
    """
    if shutil.which("dmesg") is None:
        return CheckResult("conntrack-dmesg", "skip", "dmesg not in PATH")
    try:
        # ``dmesg --time-format reltime`` would be nice but isn't on
        # every distro; settle for raw and grep ourselves.
        out = subprocess.run(  # noqa: S603 — fixed argv, no user input
            ["dmesg", "-T"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return CheckResult("conntrack-dmesg", "skip", "dmesg unreadable")

    if out.returncode != 0:
        return CheckResult("conntrack-dmesg", "skip", "dmesg unreadable (perms)")

    # Tail-only — early-boot messages from days ago are not actionable.
    tail = out.stdout.splitlines()[-200:]
    hits = [ln for ln in tail if "nf_conntrack: table full" in ln]
    if not hits:
        return CheckResult("conntrack-dmesg", "ok", "no recent nf_conntrack drops in dmesg")

    return CheckResult(
        "conntrack-dmesg",
        "warn",
        (
            f"{len(hits)} 'nf_conntrack: table full' messages in recent dmesg — kernel was "
            f"dropping packets. Most recent: {hits[-1].strip()[-160:]}"
        ),
    )


def _try_install_notrack(ports_udp: Sequence[int]) -> CheckResult:
    """Best-effort: install raw-table NOTRACK rules so VPN UDP traffic
    bypasses the conntrack accounting entirely.

    If ``iptables`` is not in PATH (alpine without iptables, macOS dev
    env), returns ``skip``. If the call fails (no NET_ADMIN cap in
    container, unprivileged listener), returns ``skip`` rather than
    ``warn`` — many users will run with limited privileges and the
    raised conntrack_max alone is sufficient.
    """
    if shutil.which("iptables") is None:
        return CheckResult("notrack-autosetup", "skip", "iptables not in PATH")

    installed: list[int] = []
    failed: list[int] = []
    for port in ports_udp:
        # -C checks; -I prepends idempotently if missing. Using -C avoids
        # appending duplicate rules across listener restarts.
        for direction in ("PREROUTING", "OUTPUT"):
            check = subprocess.run(  # noqa: S603
                [
                    "iptables",
                    "-t",
                    "raw",
                    "-C",
                    direction,
                    "-p",
                    "udp",
                    "--dport" if direction == "PREROUTING" else "--sport",
                    str(port),
                    "-j",
                    "NOTRACK",
                ],
                capture_output=True,
                check=False,
            )
            if check.returncode == 0:
                continue  # already present
            add = subprocess.run(  # noqa: S603
                [
                    "iptables",
                    "-t",
                    "raw",
                    "-I",
                    direction,
                    "-p",
                    "udp",
                    "--dport" if direction == "PREROUTING" else "--sport",
                    str(port),
                    "-j",
                    "NOTRACK",
                ],
                capture_output=True,
                check=False,
            )
            if add.returncode != 0:
                failed.append(port)
                break
        else:
            installed.append(port)

    if installed and not failed:
        return CheckResult(
            "notrack-autosetup",
            "ok",
            f"NOTRACK installed on UDP ports {installed} (skip conntrack for VPN flows)",
        )
    if failed:
        return CheckResult(
            "notrack-autosetup",
            "skip",
            (
                f"could not install NOTRACK on UDP ports {failed} (likely no NET_ADMIN cap); "
                f"raise nf_conntrack_max instead"
            ),
        )
    return CheckResult("notrack-autosetup", "skip", "no UDP ports to NOTRACK")


def _check_iptables_capability() -> CheckResult:
    """Verify the container has CAP_NET_ADMIN by running a benign
    iptables operation.

    Method: ``iptables -C OUTPUT <fake rule>`` — when the rule is
    absent (it always is, the comment is a session-fresh literal),
    iptables returns rc=1 with the message "Bad rule (does a matching
    rule exist in that chain?)". rc=1 means "command worked, rule
    just isn't there", which proves CAP_NET_ADMIN is effective. Other
    non-zero codes indicate capability or privilege failure (typical
    EPERM message: "Operation not permitted"), and a warning is
    surfaced so the operator immediately sees that the listener will
    NOT be able to install handshake counters and the listener-side
    verdicts will degrade to ``HANDSHAKE_ONLY`` for mtproto_* and
    fall back to the conservative auth-read-byte heuristic for openvpn.
    """
    if shutil.which("iptables") is None:
        return CheckResult(
            "iptables-cap",
            "warn",
            (
                "iptables not in PATH — kernel-level handshake counters "
                "won't install. mtproto_proxy/_alt/_orig will report "
                "data_transfer_ok=False even on successful probes; "
                "openvpn falls back to the auth-read-byte heuristic. "
                "On Alpine: `apk add iptables`."
            ),
        )
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv
            [
                "iptables",
                "-C",
                "OUTPUT",
                "-p",
                "tcp",
                "--sport",
                "65535",
                "-m",
                "comment",
                "--comment",
                "censprobe-cap-probe",
                "-j",
                "ACCEPT",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return CheckResult(
            "iptables-cap",
            "warn",
            f"iptables -C raised {type(e).__name__} — counter installs will fail.",
        )

    err = proc.stderr.strip().lower()
    if proc.returncode == 1 and (
        "matching rule exist" in err or "does a matching rule" in err or err == ""
    ):
        return CheckResult(
            "iptables-cap", "ok", "iptables operations permitted (counters available)"
        )
    if "permission" in err or "operation not permitted" in err:
        return CheckResult(
            "iptables-cap",
            "warn",
            (
                "iptables operations refused — CAP_NET_ADMIN missing. "
                "Listener cannot install kernel-level handshake counters; "
                "mtproto_* / openvpn data_transfer_ok will report False even "
                "on successful probes. Add `cap_add: [NET_ADMIN, NET_RAW]` to "
                "docker-compose.yml or run with `--cap-add=NET_ADMIN`."
            ),
        )
    return CheckResult(
        "iptables-cap",
        "warn",
        f"iptables -C unexpected outcome (rc={proc.returncode}, err={err[:120]!r}); "
        f"counter installs may fail.",
    )


def _cleanup_orphan_rules() -> CheckResult:
    """Delete leftover ``censprobe-*`` iptables/ip6tables rules from
    a previous crashed listener run.

    Each responder removes its rule on graceful shutdown (``stop()``),
    but a SIGKILL or host crash leaves the rule in the kernel. Over
    many restart cycles they accumulate, slowing ``iptables -L`` and
    cluttering the host firewall view. This check parses
    ``iptables -S`` output, identifies rules whose comment starts
    with ``censprobe-`` (our naming convention), and deletes each by
    flipping the ``-A`` to ``-D`` and re-running iptables. Also runs
    against ``ip6tables`` if available.

    Idempotent: if no orphans exist, this is a no-op.
    """
    deleted_total = 0
    skipped_families: list[str] = []
    for cmd in ("iptables", "ip6tables"):
        if shutil.which(cmd) is None:
            skipped_families.append(cmd)
            continue
        try:
            listing = subprocess.run(  # noqa: S603 — fixed argv
                [cmd, "-S"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            continue
        if listing.returncode != 0:
            continue
        for line in listing.stdout.splitlines():
            # Lines starting with ``-A`` are rules in append form. Only
            # ours carry the ``censprobe-`` comment marker.
            if not line.startswith("-A "):
                continue
            if "censprobe-" not in line:
                continue
            # Convert ``-A CHAIN ...`` into ``-D CHAIN ...`` and re-run.
            del_args = line.split()
            del_args[0] = "-D"
            try:
                sub = subprocess.run(  # noqa: S603 — args derived from iptables -S
                    [cmd, *del_args],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except (subprocess.SubprocessError, OSError):
                continue
            if sub.returncode == 0:
                deleted_total += 1
                logger.info("preflight: removed orphan %s rule (%s)", cmd, line[:80])

    if deleted_total > 0:
        return CheckResult(
            "orphan-rules",
            "ok",
            f"removed {deleted_total} stale censprobe rule(s) from previous run",
        )
    if len(skipped_families) == 2:
        return CheckResult("orphan-rules", "skip", "no iptables/ip6tables on PATH")
    return CheckResult("orphan-rules", "ok", "no orphan censprobe rules")


async def _check_telegram_dc_reach(
    timeout_s: float = 3.0,
) -> CheckResult:
    """Verify the listener egress can TCP-connect to ≥1 Telegram DC.

    ``probe_mtproto_proxy`` and ``probe_mtproto_orig`` now actively
    exchange a full obfuscated2 + req_pq_multi handshake which mtg /
    mtproto-proxy(C) RELAY to a real Telegram DC. If the listener
    can't open TCP to any DC (firewall on the listener host blocking
    149.154.0.0/16, or ISP-level egress filter), the resPQ never
    arrives and BOTH probes degrade to HANDSHAKE_ONLY/BLOCKED. That
    is *correct* (data plane really is broken end-to-end), but
    surfacing it here at startup distinguishes "client-side DPI"
    from "my listener can't reach DCs".

    We probe 3 DCs in parallel. ``warn`` if 0/3 reachable; ``ok``
    otherwise (Telegram load-balances across all 5 DCs, so partial
    reachability is normally fine).
    """

    async def _connect(ip: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout_s)
        except (TimeoutError, OSError):
            return False
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()
        return True

    results = await asyncio.gather(*(_connect(ip, port) for ip, port, _ in _TELEGRAM_DC_PROBES))
    reachable = sum(1 for ok in results if ok)
    total = len(_TELEGRAM_DC_PROBES)
    if reachable == 0:
        names = ", ".join(name for _, _, name in _TELEGRAM_DC_PROBES)
        return CheckResult(
            "telegram-dc-reach",
            "warn",
            (
                f"0/{total} Telegram DCs reachable from listener egress ({names}). "
                f"mtproto_proxy / mtproto_orig probes will report HANDSHAKE_ONLY "
                f"or BLOCKED — clients see this as 'reachable but DC blocked'. "
                f"Check the listener's outbound network can reach 149.154.0.0/16 "
                f"(no upstream firewall, no Telegram-block-at-egress jurisdiction)."
            ),
        )
    return CheckResult(
        "telegram-dc-reach",
        "ok",
        f"{reachable}/{total} Telegram DCs reachable",
    )


def _parse_proxy_multi_upstreams(
    path: Path | None = None,
) -> list[tuple[str, int, str]]:
    """Parse ``proxy_for <cluster> <ip>:<port>;`` lines from proxy-multi.conf.

    Returns a list of ``(ip, port, cluster_id)`` tuples in file order.
    Duplicates and malformed lines are dropped silently. Returns an empty
    list when the file is missing (image was built without the
    mtproxy-orig stage, or the path moved).

    The C MTProxy binary cycles auth_cluster RPC heartbeats across every
    listed (ip, port) pair, so any one of them is a representative
    reachability target. We surface ``cluster_id`` so the caller can pick
    one IP per distinct cluster — sampling all of cluster 4's ten IPs
    would waste the budget on a single Telegram DC.

    ``path`` defaults to the module-level ``_PROXY_MULTI_CONF_PATH`` at
    call time (NOT at def time, so monkeypatching the module constant
    in tests reaches this function — a per-call lookup is cheap and
    keeps the call sites argument-free).
    """
    if path is None:
        path = _PROXY_MULTI_CONF_PATH
    if not path.exists():
        return []
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line.startswith("proxy_for "):
            continue
        parts = line.split()
        # `proxy_for <cluster_id> <ip>:<port>;` — exactly three tokens.
        if len(parts) < 3:
            continue
        cluster = parts[1]
        ip_port = parts[2].rstrip(";")
        ip, _, port_s = ip_port.rpartition(":")
        if not ip or not port_s:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)
        out.append((ip, port, cluster))
    return out


async def _check_mtproxy_orig_upstream_reach(
    timeout_s: float = 3.0,
) -> CheckResult:
    """Verify TCP reach to the actual upstream IPs the C MTProxy will dial.

    Augments ``_check_telegram_dc_reach`` (which only tests 3 DC IPs on
    port 443 — the canonical Telegram public endpoint). The original C
    ``mtproto-proxy`` binary upstreams to a DIFFERENT set of IPs on port
    **8888** sourced from ``proxy-multi.conf`` (e.g. the 91.108.4.0/24
    cluster). On hosts where the egress allows 443 but blocks 8888 (or
    where Telegram's port-8888 fleet treats the host's ASN
    differently), the 443 check passes while every ``mtproto_orig``
    probe of the resulting session reports BLOCKED with a length-read
    timeout — a false positive against the strict "BLOCKED ≡ confirmed
    block" invariant. This check closes that gap by probing the actual
    upstream the responder will use, BEFORE clients run.

    Picks at most one IP per distinct cluster_id so 6 probes cover 6
    Telegram clusters rather than 6 IPs in cluster 4. ``warn`` when 0/N
    reachable; ``ok`` otherwise (Telegram load-balances and partial
    reach is normally fine in practice).
    """
    upstreams = _parse_proxy_multi_upstreams()
    if not upstreams:
        return CheckResult(
            "mtproxy-orig-upstream",
            "skip",
            "proxy-multi.conf not found (image built without mtproxy-orig stage)",
        )

    # Pick at most one IP per cluster so we exercise breadth, not depth.
    sampled: list[tuple[str, int, str]] = []
    seen_clusters: set[str] = set()
    for ip, port, cluster in upstreams:
        if cluster in seen_clusters:
            continue
        seen_clusters.add(cluster)
        sampled.append((ip, port, cluster))
        if len(sampled) >= _PROXY_MULTI_PROBE_SAMPLE:
            break

    async def _connect(ip: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout_s)
        except (TimeoutError, OSError):
            return False
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()
        return True

    results = await asyncio.gather(*(_connect(ip, port) for ip, port, _ in sampled))
    reachable = sum(1 for ok in results if ok)
    total = len(sampled)
    if reachable == 0:
        ipport_list = ", ".join(f"{ip}:{port}" for ip, port, _ in sampled)
        return CheckResult(
            "mtproxy-orig-upstream",
            "warn",
            (
                f"0/{total} mtproto-proxy upstream IPs reachable on port 8888 "
                f"({ipport_list}). mtproto_orig sessions WILL timeout at the "
                f"resPQ leg and report as ERROR (responder-side, not network) — "
                f"check listener-egress firewall for TCP/8888 to Telegram's "
                f"proxy fleet, or rebuild the image to refresh proxy-multi.conf."
            ),
        )
    return CheckResult(
        "mtproxy-orig-upstream",
        "ok",
        f"{reachable}/{total} mtproto-proxy upstream IPs reachable on port 8888",
    )


async def probe_all_proxy_multi_upstreams(
    path: Path | None = None,
    *,
    timeout_s: float = _PROXY_MULTI_PRUNE_TIMEOUT_S,
    parallel: int = _PROXY_MULTI_PRUNE_PARALLEL,
) -> tuple[list[tuple[str, int, str]], list[tuple[str, int, str]]]:
    """TCP-probe every (ip, port, cluster) listed in proxy-multi.conf in
    parallel and split them into ``(alive, unreachable)``.

    Unlike :func:`_check_mtproxy_orig_upstream_reach` (which probes one
    IP per cluster to produce a single preflight WARN/OK signal), this
    function is the input to the **responder-side prune**: we want to
    know exactly which IPs the C MTProxy binary can talk to, so we can
    rewrite its config to contain only those IPs before launching the
    daemon. Otherwise the binary's auth_cluster reconnect logic hammers
    every dead IP in a hot ``connect()``→ECONNREFUSED→retry loop
    (observed at 145 connect/s on RU-blocked hosts), starving its
    single accept() worker and producing every session-time mtproto_orig
    verdict as a false BLOCKED.

    Order in ``alive`` preserves config-file order so the rewriter can
    re-emit ``proxy_for`` lines that look as close to the original as
    possible. ``path`` defaults to the module-level constant at call
    time so tests can monkeypatch ``_PROXY_MULTI_CONF_PATH`` and have
    this function pick up the override.
    """
    upstreams = _parse_proxy_multi_upstreams(path)
    if not upstreams:
        return [], []

    sem = asyncio.Semaphore(parallel)

    async def _probe(ip: str, port: int) -> bool:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout_s
                )
            except (TimeoutError, OSError):
                return False
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return True

    results = await asyncio.gather(*(_probe(ip, port) for ip, port, _ in upstreams))
    alive: list[tuple[str, int, str]] = []
    unreachable: list[tuple[str, int, str]] = []
    for upstream, ok in zip(upstreams, results, strict=True):
        (alive if ok else unreachable).append(upstream)
    return alive, unreachable


def write_pruned_proxy_multi_conf(
    alive: list[tuple[str, int, str]],
    dest: Path,
    *,
    source: Path | None = None,
) -> None:
    """Write a minimal proxy-multi.conf containing only the alive IPs.

    Preserves the ``default <cluster>;`` directive from the source file
    (mtproto-proxy refuses to start without one) and re-emits each
    ``proxy_for <cluster> <ip>:<port>;`` line from ``alive`` in
    config-file order. Other directives in the source (e.g. the
    commented ``force_probability``) are intentionally dropped — the
    pruned config is meant to be a minimal valid replacement, not a
    full mirror of the upstream-provided file.

    Caller is responsible for handling the empty-alive case BEFORE
    invoking this function. We assert non-empty so a mistake at the
    call site fails loudly rather than silently writing a config that
    the C binary parses then crashes on.
    """
    assert alive, "write_pruned_proxy_multi_conf requires at least one alive upstream"
    if source is None:
        source = _PROXY_MULTI_CONF_PATH

    default_line = "default 2;\n"
    if source.exists():
        # Mirror whatever "default <cluster>;" the upstream sent. Falls
        # back to "default 2;" (a Frankfurt-routed DC, normally the
        # most-reachable cluster) if no default line exists.
        for raw in source.read_text().splitlines():
            line = raw.strip()
            if line.startswith("default "):
                default_line = raw if raw.endswith("\n") else raw + "\n"
                break

    lines = [default_line]
    lines.extend(f"proxy_for {cluster} {ip}:{port};\n" for ip, port, cluster in alive)
    dest.write_text("".join(lines))


async def run_mtproxy_orig_self_test(
    port: int, secret_hex: str, timeout_s: float = 12.0
) -> CheckResult:
    """Probe the just-started ``mtproto_orig`` responder against itself.

    Single loopback call to :func:`probe_mtproto_orig` on ``127.0.0.1`` /
    ``port`` with the in-memory session secret. Establishes whether the
    C MTProxy slave is *actually* picking up client connections off the
    accept queue, completing the obfuscated2 handshake, and relaying a
    real ``req_pq_multi`` round-trip to a Telegram DC — i.e. the whole
    stack the session-time probe relies on.

    Why this is necessary even when ``_check_mtproxy_orig_upstream_reach``
    passes: that check verifies the TCP path to DC:8888 is open from the
    listener's egress. It does NOT verify the C binary is healthy. The
    binary has known modes (aggressive auth_cluster reconnect loop;
    auth_key-bootstrap stall; slave hard-stuck on a syscall) where
    upstream reach is fine but ``accept4()`` never fires inside the
    probe window — producing the exact BLOCKED-shape failure that
    looks like DPI silent-drop but is purely server-side.

    On WARN, the listener still serves sessions; ``_finalize_protocol_result``
    will downgrade the mtproto_orig verdict from BLOCKED → ERROR with a
    diagnostic note instead of misclassifying the responder bug as
    censorship.
    """
    # Imported lazily to avoid pulling probe-core into the
    # listener-startup hot path when this check is skipped (e.g.
    # mtproto_orig disabled in censprobe.yaml).
    from censprobe_core.models import Verdict
    from censprobe_core.protocol_probes import probe_mtproto_orig

    try:
        result = await asyncio.wait_for(
            probe_mtproto_orig("127.0.0.1", port, secret_hex),
            timeout=timeout_s,
        )
    except TimeoutError:
        return CheckResult(
            "mtproxy-orig-self-test",
            "warn",
            (
                f"loopback probe of mtproto_orig:{port} timed out after "
                f"{timeout_s:.0f}s — responder appears wedged (likely C "
                f"MTProxy auth_cluster reconnect loop starving accept(); "
                f"strace the slave pid + tune -M N to confirm). Sessions "
                f"WILL be downgraded BLOCKED→ERROR for this protocol."
            ),
        )
    except Exception as e:
        return CheckResult(
            "mtproxy-orig-self-test",
            "warn",
            f"loopback probe raised {type(e).__name__}: {e}",
        )

    if result.verdict == Verdict.OK:
        return CheckResult(
            "mtproxy-orig-self-test",
            "ok",
            "loopback probe completed full obfuscated2 + req_pq → resPQ exchange",
        )
    # BLOCKED / ERROR / HANDSHAKE_ONLY from the loopback probe all mean
    # "the responder didn't complete its own handshake within the budget".
    # That is the signal we need for the downgrade — the precise verdict
    # is a diagnostic message, not a fail-axis.
    # ``ProbeResult.error`` is the diagnostic string ("orig_resPQ_len_timeout_post_init"
    # etc.); ``ProbeResult`` has no ``note`` field — that lives on
    # ``ProtocolResult``.
    note_str = result.error or "<no diagnostic>"
    return CheckResult(
        "mtproxy-orig-self-test",
        "warn",
        (
            f"loopback probe returned {result.verdict} (note: {note_str}) — "
            f"responder cannot handshake against itself; session BLOCKED "
            f"verdicts for mtproto_orig will be downgraded to ERROR."
        ),
    )


async def run_preflight(udp_ports: Sequence[int]) -> list[CheckResult]:
    """Run all pre-startup checks in order; return individual results.

    Order matters:
      1. ``orphan-rules`` runs FIRST so subsequent installs aren't
         shadowed by leftover identically-named rules from a previous
         crashed listener.
      2. ``iptables-cap`` exposes "no CAP_NET_ADMIN" loudly so the
         operator knows the iptables-counter signals will be silent
         before they go puzzling over verdict mismatches.
      3. NOTRACK auto-setup ``-A``s our raw-table rules so the rest
         of the run skips conntrack accounting on VPN UDP ports.
      4. ``conntrack`` reads the table state — its severity is
         downgraded to ok-with-advisory when NOTRACK is in place.
      5. ``conntrack-dmesg`` looks for recent table-full drops.
      6. ``telegram-dc-reach`` opens TCP to a few Telegram DCs on port
         443 — quick public-endpoint reach signal for the operator.
      7. ``mtproxy-orig-upstream`` opens TCP to the actual upstream IPs
         the C MTProxy will dial (parsed from proxy-multi.conf,
         port 8888). Complements (6) by exercising the SPECIFIC path
         mtproto_orig sessions need; closes the false-BLOCKED gap where
         a host has 443 reach but 8888 is blocked or treated
         differently.

    The caller is expected to print the results; we return data
    rather than printing here so the listener can format with its
    rich console (and tests can assert on the structured output).
    """
    orphan = _cleanup_orphan_rules()
    cap = _check_iptables_capability()
    notrack = _try_install_notrack(udp_ports)
    conntrack = _check_conntrack(notrack_installed=notrack.status == "ok")
    dmesg = _check_dmesg_recent_drops()
    dc = await _check_telegram_dc_reach()
    upstream = await _check_mtproxy_orig_upstream_reach()
    return [orphan, cap, notrack, conntrack, dmesg, dc, upstream]
