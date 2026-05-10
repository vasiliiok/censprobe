"""
preflight.py — Listener-side pre-startup environment checks.

Runs once during listener boot, before responders bind to ports. Surfaces
silent kernel/host conditions that look like censorship at the client
side but are actually local resource exhaustion. The canonical example
is ``nf_conntrack: table full, dropping packet`` — kernel drops new
flows before they reach userspace, so the listener log is clean while
every responder mysteriously stops responding to half the protocols.

Each check returns a small status string ("ok" | "warn" | "fail") plus
a human-readable message. Listener startup never *aborts* on a warning
— operators may legitimately run on a constrained VM and not be able
to fix sysctls — but every WARN is printed loudly so the user gets the
chance to fix it before puzzling over the result table.
"""

from __future__ import annotations

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

_NF_MAX = Path("/proc/sys/net/netfilter/nf_conntrack_max")
_NF_COUNT = Path("/proc/sys/net/netfilter/nf_conntrack_count")


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


def _check_conntrack() -> CheckResult:
    nf_max = _read_int(_NF_MAX)
    nf_count = _read_int(_NF_COUNT)

    if nf_max is None or nf_count is None:
        return CheckResult(
            "conntrack",
            "skip",
            "no /proc/sys/net/netfilter/nf_conntrack_* — kernel without netfilter",
        )

    if nf_max < _CONNTRACK_MIN_MAX:
        return CheckResult(
            "conntrack",
            "warn",
            (
                f"nf_conntrack_max={nf_max} (< {_CONNTRACK_MIN_MAX}). "
                f"Once full, kernel SILENTLY DROPS new flows before they reach the responders — "
                f"clients will see BLOCKED for protocols whose handshake packets get evicted. "
                f"Fix: sudo sysctl -w net.netfilter.nf_conntrack_max=1048576 "
                f"(persist via /etc/sysctl.d/99-conntrack.conf). "
                f"Optional: NOTRACK the VPN UDP ports — "
                f"sudo iptables -t raw -A PREROUTING -p udp --dport <port> -j NOTRACK."
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


def run_preflight(udp_ports: Sequence[int]) -> list[CheckResult]:
    """Run all pre-startup checks in order; return individual results.

    The caller is expected to print the results; we return data rather
    than printing here so the listener can format with its rich
    console (and tests can assert on the structured output).
    """
    results = [_check_conntrack(), _check_dmesg_recent_drops()]
    # NOTRACK auto-setup runs unconditionally — it's idempotent and cheap
    # when we already have the rules. Even when the conntrack table is
    # OK, NOTRACK shaves a per-packet hashtable lookup off every VPN
    # packet, which is a free win.
    results.append(_try_install_notrack(udp_ports))
    return results
