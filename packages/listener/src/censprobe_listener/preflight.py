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
import secrets
import shutil
import subprocess  # noqa: S404 — listener already shells out elsewhere
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen

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

# Workspace mount point — where censprobe.yaml and targets/*.yaml live
# in every deployment (compose mounts ``./:/workspace`` for all profiles).
# Used by :func:`_load_telegram_dc_probes` to read the canonical DC list
# from ``targets/telegram.yaml`` at preflight time.
_WORKSPACE = Path("/workspace")

# Path inside the workspace mount where the canonical Telegram DC
# definitions live. Loaded once at preflight start; values flow into
# :func:`_check_telegram_dc_reach` so the preflight check probes the
# SAME endpoints that the telegram-module probes downstream — single
# source of truth.
_TELEGRAM_YAML_PATH = Path("targets/telegram.yaml")

# Cap on how many DCs to probe at preflight. The full canonical list
# has 5 DCs (pluto/venus/aurora/vesta/flora across Miami/Amsterdam/
# Singapore); three is enough to distinguish "all blocked" from
# "one DC moved" without 5× SYN budget at startup.
_TELEGRAM_DC_PROBE_LIMIT = 3

# Hardcoded fallback if ``targets/telegram.yaml`` is missing or
# unparseable (image built without the workspace, dev workspace
# moved). Listener boot never aborts on a missing yaml — we degrade
# to this last-known-good list and surface a WARN so the operator
# sees the fallback engaged. Updated 2026-05-14 from telegram.yaml.
# Three DCs is enough to distinguish "all blocked" (all 3 fail)
# from "one DC moved" (1-2 fail).
_TELEGRAM_DC_PROBES_FALLBACK: tuple[tuple[str, int, str], ...] = (
    ("149.154.175.53", 443, "DC1 pluto"),
    ("149.154.167.51", 443, "DC2 venus"),
    ("149.154.175.100", 443, "DC3 aurora"),
)


def _load_telegram_dc_probes() -> tuple[tuple[str, int, str], ...]:
    """Read DC list from ``targets/telegram.yaml`` — single source of truth.

    Falls back to :data:`_TELEGRAM_DC_PROBES_FALLBACK` when the yaml
    is missing or unparseable, and logs a warning so the operator
    sees that we're running on stale baked-in values. The fallback is
    NOT silent because a stale list can mask a real DC migration —
    if Telegram moves DC1 and our hardcoded ``149.154.175.53`` becomes
    a dead address, the preflight would falsely flag every healthy
    egress as "0/3 DCs reachable" without the operator knowing why.

    Returns the first ``_TELEGRAM_DC_PROBE_LIMIT`` entries from
    ``api_datacenters[]`` as ``(ipv4, port, "DC<id> <name>")`` tuples,
    picking the first port from each DC's ``ports`` list (canonical
    443 in current yaml).
    """
    # Local imports — preflight is imported at listener boot, before
    # the asyncio loop is wired up. Loading probe-core's yaml parser
    # at module-import time would force pydantic / yaml costs on every
    # call site that touches preflight (e.g. unit tests). Lazy keeps
    # the import graph shallow.
    import yaml as _yaml
    from censprobe_core.targets import TargetFile
    from pydantic import ValidationError

    yaml_path = _WORKSPACE / _TELEGRAM_YAML_PATH
    if not yaml_path.exists():
        logger.warning(
            "preflight: %s missing — falling back to hardcoded DC list; "
            "operator should rebuild image or check workspace mount",
            yaml_path,
        )
        return _TELEGRAM_DC_PROBES_FALLBACK
    try:
        raw = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        tf = TargetFile.model_validate(raw)
    except (OSError, UnicodeDecodeError, _yaml.YAMLError, ValidationError) as e:
        # OSError — file disappears between exists() and read(), or perms.
        # UnicodeDecodeError — yaml saved with non-UTF8 BOM/encoding.
        # YAMLError — operator typo, mismatched braces, etc.
        # ValidationError — schema violation (e.g. missing required ports).
        logger.warning(
            "preflight: could not parse %s (%s) — falling back to hardcoded DC list",
            yaml_path,
            e,
        )
        return _TELEGRAM_DC_PROBES_FALLBACK

    probes: list[tuple[str, int, str]] = []
    for dc in tf.api_datacenters[:_TELEGRAM_DC_PROBE_LIMIT]:
        if not dc.ipv4:
            continue
        # First v4 IP + first port — ``ports: [443, 80, 5222]`` in canonical
        # yaml. 443 is the universally-reachable variant; 80 and 5222 are
        # informational.
        ipv4 = dc.ipv4[0]
        port = dc.ports[0] if dc.ports else 443
        # ``name`` is in the yaml (``name: pluto``) but TelegramDC's
        # pydantic schema doesn't declare it as a typed field — it
        # lands in ``model_extra`` thanks to ``extra="allow"``. Pull
        # it from there so the operator-facing label stays consistent
        # with the legacy hardcoded format ("DC<id> <name>").
        extras = dc.model_extra or {}
        name_raw = extras.get("name")
        name = name_raw if isinstance(name_raw, str) and name_raw else None
        display = f"DC{dc.id} {name}" if name else f"DC{dc.id}"
        probes.append((ipv4, port, display))

    if not probes:
        logger.warning(
            "preflight: %s parsed but yielded zero usable DC entries — "
            "falling back to hardcoded list",
            yaml_path,
        )
        return _TELEGRAM_DC_PROBES_FALLBACK
    return tuple(probes)


# The C MTProxy binary upstreams to Telegram DCs on TCP/8888 (not 443).
# proxy-multi.conf is downloaded at image build time from
# https://core.telegram.org/getProxyConfig and baked into the runtime
# image at this path — see packages/listener/Dockerfile.
_PROXY_MULTI_CONF_PATH = Path("/usr/local/share/mtproxy-orig/proxy-multi.conf")
# proxy-secret is the AES password file used by mtproto-proxy to derive
# its RPC auth keys when talking to upstream Telegram DCs. Baked from
# https://core.telegram.org/getProxySecret in the same Dockerfile ADD
# block; refreshed at runtime alongside the multi-conf via
# :func:`_refresh_proxy_runtime_config`.
_PROXY_SECRET_PATH = Path("/usr/local/share/mtproxy-orig/proxy-secret")  # noqa: S105

# Telegram serves the dynamic upstream config + matching AES password
# file at these URLs. The DC IP rotation cadence is days-to-weeks: a
# build that's a month old typically has 70-90% stale DC4/DC5 entries,
# triggering an auth-cluster reconnect storm that the responder
# self-test reads as "wedged". Refreshed once per listener startup so
# the rotation lag is bounded by session duration, not by image age.
_PROXY_MULTI_CONF_URL = "https://core.telegram.org/getProxyConfig"
_PROXY_SECRET_URL = "https://core.telegram.org/getProxySecret"  # noqa: S105 — URL, not a credential
_PROXY_CONFIG_FETCH_TIMEOUT_S = 5.0

# Per-IP TCP-connect budget for the proxy-multi.conf upstream probe.
# 1.5 s is the default used by the responder-side FALLBACK probe (kept
# short so it stays inside the responder-settle window). The preflight
# path — now the single authoritative probe — overrides this with a
# more generous 3.0 s (see ``_PROXY_MULTI_PREFLIGHT_TIMEOUT_S``):
# preflight is not latency-critical, so it can afford fewer
# false-unreachable verdicts from a slow SYN/SYN-ACK.
_PROXY_MULTI_PRUNE_TIMEOUT_S = 1.5
# Per-IP budget for the preflight upstream probe (the authoritative one
# whose result is threaded to the mtproto_orig responder).
_PROXY_MULTI_PREFLIGHT_TIMEOUT_S = 3.0
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


@dataclass(frozen=True)
class UpstreamProbe:
    """Outcome of TCP-probing every proxy-multi.conf upstream once.

    Produced a SINGLE time by :func:`run_preflight` (the full
    enumeration — not a sample) and threaded to ``MTProxyOrigResponder``
    so the responder reuses it for its config-prune instead of
    re-probing at launch. The operator-facing pre-flight signal and the
    responder's launch decision then derive from the same measurement
    and can never disagree (the old sample-6-at-preflight vs
    probe-all-at-launch split could, and did: a transiently-reachable
    sampled IP produced "1/6 ok" at preflight while the full launch
    probe found "0/19" seconds later).

    ``alive`` / ``unreachable`` are ``(ip, port, cluster_id)`` tuples in
    proxy-multi.conf order. ``total == 0`` means proxy-multi.conf was
    absent or empty (image built without the mtproxy-orig stage).

    ``conf_path`` / ``secret_path`` are the paths the mtproto_orig
    responder must launch ``mtproto-proxy`` against. They point at the
    freshly-fetched copies under ``/tmp/...`` when the runtime refresh
    succeeded, or fall back to the baked-in
    ``/usr/local/share/mtproxy-orig/*`` paths otherwise. Threading them
    here keeps the responder oblivious to the freshness mechanism — it
    just uses what preflight handed it.
    """

    alive: list[tuple[str, int, str]]
    unreachable: list[tuple[str, int, str]]
    conf_path: Path = _PROXY_MULTI_CONF_PATH
    secret_path: Path = _PROXY_SECRET_PATH

    @property
    def total(self) -> int:
        return len(self.alive) + len(self.unreachable)


def _fetch_url_to_path(url: str, dest: Path, timeout_s: float) -> bool:
    """Download ``url`` into ``dest`` atomically. Return True on success.

    Atomicity: write to a sibling temp file in the same directory and
    ``rename()`` once the body is fully buffered, so a partial download
    can never leave a half-written file the C binary would parse.
    Sync I/O wrapped by the caller in ``asyncio.to_thread``.
    """
    tmp = dest.with_suffix(dest.suffix + f".tmp-{secrets.token_hex(4)}")
    try:
        # urllib's default opener honours both HTTP and HTTPS; we don't
        # need cookie support and the URLs are fixed at module level so
        # this is not user-input — S310 (URL-based filesystem write) is
        # bounded by the constants above.
        with urlopen(url, timeout=timeout_s) as resp:  # noqa: S310  # nosec B310
            if resp.status != 200:
                logger.debug("preflight: %s returned HTTP %s", url, resp.status)
                return False
            body = resp.read()
        if not body:
            logger.debug("preflight: %s returned empty body", url)
            return False
        tmp.write_bytes(body)
        tmp.chmod(0o600)
        tmp.rename(dest)
        return True
    except (OSError, ValueError, TimeoutError) as e:
        logger.debug("preflight: fetch %s failed: %s: %s", url, type(e).__name__, e)
        with contextlib.suppress(OSError):
            tmp.unlink()
        return False


async def _refresh_proxy_runtime_config(
    *,
    conf_url: str = _PROXY_MULTI_CONF_URL,
    secret_url: str = _PROXY_SECRET_URL,
    timeout_s: float = _PROXY_CONFIG_FETCH_TIMEOUT_S,
) -> tuple[Path, Path, Path | None]:
    """Try to refresh both proxy-multi.conf and proxy-secret at startup.

    Telegram rotates the DC4/DC5 IPs over days-to-weeks. Baking the
    config into the Docker image at build time means a release shipped
    on day 0 has fully-stale DC4 entries by ~day 7 — the responder's
    proxy-multi.conf prune still finds the *IPs* reachable (the IPs
    exist; they just no longer terminate the auth_cluster RPC), and the
    self-test then wedges with the symptom every operator has seen:
    "0 mtproto_orig clients in 12s — responder appears wedged".

    Refresh strategy:
      * Write fresh copies to a per-process tempdir under /tmp.
      * If BOTH fetches succeed, return the fresh paths.
      * If either fails, return the baked-in paths so the responder
        still launches — degraded but not broken.

    Returns ``(conf_path, secret_path, tmp_dir)`` where ``tmp_dir`` is
    the per-process directory the fresh files live in (``None`` when
    the refresh failed and the baked-in paths are returned instead).
    The listener owns the tmpdir's lifetime and must ``shutil.rmtree``
    it at session teardown to avoid leaking ``/tmp/censprobe-mtorig-*``
    across restarts.
    """
    tmp_dir = Path(tempfile.gettempdir()) / f"censprobe-mtorig-{secrets.token_hex(4)}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.chmod(0o700)
    fresh_conf = tmp_dir / "proxy-multi.conf"
    fresh_secret = tmp_dir / "proxy-secret"

    # Parallelise the two fetches so the worst-case wallclock is one
    # ``timeout_s`` rather than two. Both endpoints are independent
    # subresources on the same host; serialising them was an oversight.
    conf_ok, secret_ok = await asyncio.gather(
        asyncio.to_thread(_fetch_url_to_path, conf_url, fresh_conf, timeout_s),
        asyncio.to_thread(_fetch_url_to_path, secret_url, fresh_secret, timeout_s),
    )

    if conf_ok and secret_ok:
        logger.info(
            "mtproto_orig: refreshed proxy-multi.conf + proxy-secret from "
            "core.telegram.org (replacing baked-in image copies)"
        )
        return fresh_conf, fresh_secret, tmp_dir

    # At least one fetch failed → fall back to baked-in. Clean up the
    # half-populated tempdir immediately so we don't leak it; the caller
    # then sees ``tmp_dir=None`` and skips its own rmtree.
    logger.warning(
        "mtproto_orig: failed to refresh runtime config (conf_ok=%s secret_ok=%s); "
        "falling back to baked-in proxy-multi.conf and proxy-secret. "
        "The image's copies may be stale — if mtproto_orig wedges, rebuild "
        "the listener image or check egress to core.telegram.org.",
        conf_ok,
        secret_ok,
    )
    with contextlib.suppress(OSError):
        shutil.rmtree(tmp_dir)
    return _PROXY_MULTI_CONF_PATH, _PROXY_SECRET_PATH, None


@dataclass(frozen=True)
class PreflightResult:
    """Structured return of :func:`run_preflight`.

    ``checks`` is the ordered operator-facing list rendered as the
    pre-flight panel. ``mtproxy_upstreams`` carries the full upstream
    probe so the listener can hand it to the mtproto_orig responder
    without a second round of SYNs — see :class:`UpstreamProbe`.

    ``mtproxy_runtime_dir`` is the per-process tempdir into which the
    fresh proxy-multi.conf + proxy-secret were fetched (``None`` when
    the runtime refresh failed and the responder is using the baked-in
    paths instead). Listener teardown should ``rmtree`` it.
    """

    checks: list[CheckResult]
    mtproxy_upstreams: UpstreamProbe
    mtproxy_runtime_dir: Path | None = None


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
        out = subprocess.run(  # noqa: S603  # NOSONAR — fixed argv, no user input
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
        if _install_notrack_for_port(port):
            installed.append(port)
        else:
            failed.append(port)

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


def _install_notrack_for_port(port: int) -> bool:
    """Install NOTRACK in both PREROUTING (--dport) and OUTPUT (--sport)
    for one UDP ``port``. Returns True iff both directions ended in a
    success state — either pre-existing (``-C`` rc=0) or freshly added
    (``-I`` rc=0). False if EITHER direction failed to add a missing
    rule; the per-port atomic semantic means we don't report a half-
    installed port as OK to the caller.

    Each subprocess.run uses ``check=False`` because rc≠0 is the normal
    "rule absent" signal we drive control flow on — raising would be
    noise. ``capture_output=True`` suppresses stderr spam ("Bad rule
    (does a matching rule exist...)") since we only need the return
    code.
    """
    for direction in ("PREROUTING", "OUTPUT"):
        port_arg = "--dport" if direction == "PREROUTING" else "--sport"
        # -C checks; -I prepends idempotently if missing. Using -C avoids
        # appending duplicate rules across listener restarts.
        check = subprocess.run(  # noqa: S603  # NOSONAR — fixed argv, port is int
            [
                "iptables", "-t", "raw", "-C", direction,
                "-p", "udp", port_arg, str(port), "-j", "NOTRACK",
            ],
            capture_output=True,
            check=False,
        )  # fmt: skip
        if check.returncode == 0:
            continue  # already present
        add = subprocess.run(  # noqa: S603  # NOSONAR — fixed argv, port is int
            [
                "iptables", "-t", "raw", "-I", direction,
                "-p", "udp", port_arg, str(port), "-j", "NOTRACK",
            ],
            capture_output=True,
            check=False,
        )  # fmt: skip
        if add.returncode != 0:
            return False
    return True


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
        deleted_total += _delete_orphans_for_family(cmd)

    if deleted_total > 0:
        return CheckResult(
            "orphan-rules",
            "ok",
            f"removed {deleted_total} stale censprobe rule(s) from previous run",
        )
    if len(skipped_families) == 2:
        return CheckResult("orphan-rules", "skip", "no iptables/ip6tables on PATH")
    return CheckResult("orphan-rules", "ok", "no orphan censprobe rules")


def _delete_orphans_for_family(cmd: str) -> int:
    """Scrape ``<cmd> -S`` for ``-A`` rules with our ``censprobe-`` marker
    and delete each. Returns count of successfully-deleted rules.

    Subprocess errors are swallowed — orphans are a hygiene concern, not
    a hard failure. A missing/broken iptables means no orphans to clean;
    next listener restart will retry. Per-family so the iptables/ip6tables
    loop above stays linear and individual subprocess errors don't poison
    the other family's scrape.
    """
    listing = _run_iptables_list(cmd)
    if listing is None:
        return 0
    deleted = 0
    for line in listing.splitlines():
        if not _is_censprobe_rule_line(line):
            continue
        if _delete_one_rule(cmd, line):
            deleted += 1
            logger.info("preflight: removed orphan %s rule (%s)", cmd, line[:80])
    return deleted


def _run_iptables_list(cmd: str) -> str | None:
    """``<cmd> -S`` → stdout or None on error / non-zero rc.

    The returned string is the raw ``-A CHAIN ...`` block we parse in
    the caller. Returning None vs "" distinguishes "subprocess broke"
    from "subprocess succeeded but kernel has no rules" — both translate
    to "no orphans to remove" downstream, so we collapse to None.
    """
    try:
        listing = subprocess.run(  # noqa: S603  # NOSONAR — fixed argv
            [cmd, "-S"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if listing.returncode != 0:
        return None
    return listing.stdout


def _is_censprobe_rule_line(line: str) -> bool:
    """``-A CHAIN ... -m comment --comment "censprobe-..."`` — the shape
    every responder uses for its accounting rule. Other lines (``-N``
    custom-chain create, ``-P`` policy, plain ``-A`` without our marker)
    are skipped.
    """
    return line.startswith("-A ") and "censprobe-" in line


def _delete_one_rule(cmd: str, rule_line: str) -> bool:
    """Convert ``-A CHAIN ...`` into ``-D CHAIN ...`` and re-run iptables.
    Returns True iff the delete subprocess exited 0.

    Args spliced from ``-S`` output via shlex-equivalent ``line.split()`` —
    iptables emits its own escaped form, so this is safe (no operator
    input flows here). The leading token is always ``-A`` which we flip
    to ``-D`` in place.
    """
    del_args = rule_line.split()
    del_args[0] = "-D"
    try:
        sub = subprocess.run(  # noqa: S603  # NOSONAR — args derived from iptables -S
            [cmd, *del_args],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return sub.returncode == 0


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

    We probe up to ``_TELEGRAM_DC_PROBE_LIMIT`` DCs in parallel — the
    list is read from ``targets/telegram.yaml`` (single source of truth)
    and capped to keep the SYN budget small. ``warn`` if zero reachable;
    ``ok`` otherwise (Telegram load-balances across all 5 DCs, so partial
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

    probes = _load_telegram_dc_probes()
    results = await asyncio.gather(*(_connect(ip, port) for ip, port, _ in probes))
    reachable = sum(1 for ok in results if ok)
    total = len(probes)
    if reachable == 0:
        names = ", ".join(name for _, _, name in probes)
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


def _mtproxy_upstream_checkresult(probe: UpstreamProbe) -> CheckResult:
    """Render the operator-facing ``mtproxy-orig-upstream`` pre-flight
    line from an already-completed :class:`UpstreamProbe`.

    Pure (no I/O): the TCP probing happened once in :func:`run_preflight`
    via :func:`probe_all_proxy_multi_upstreams`. Because this CheckResult
    and the mtproto_orig responder's launch-time prune both consume the
    SAME ``(alive, unreachable)`` partition, the pre-flight verdict and
    the responder's skip/spawn decision are guaranteed consistent.

    Context — the C ``mtproto-proxy`` binary upstreams to Telegram on
    port **8888** (sourced from ``proxy-multi.conf``), a DIFFERENT path
    from ``_check_telegram_dc_reach``'s port-443 DC probe. A host whose
    egress allows 443 but blocks 8888 passes the DC check yet has every
    ``mtproto_orig`` session fail — this line closes that gap.

    Status mapping:
      * ``skip`` — proxy-multi.conf absent/empty (image built without
        the mtproxy-orig stage).
      * ``warn`` — 0/N reachable: the responder skips the spawn and
        every ``mtproto_orig`` session reports BLOCKED.
      * ``ok``   — ≥1 reachable (Telegram load-balances; the responder
        prunes the dead IPs and launches on the alive subset).
    """
    if probe.total == 0:
        return CheckResult(
            "mtproxy-orig-upstream",
            "skip",
            "proxy-multi.conf not found (image built without mtproxy-orig stage)",
        )
    alive_n = len(probe.alive)
    if alive_n == 0:
        sample = probe.unreachable[:6]
        ipport_list = ", ".join(f"{ip}:{port}" for ip, port, _ in sample)
        suffix = "..." if len(probe.unreachable) > 6 else ""
        return CheckResult(
            "mtproxy-orig-upstream",
            "warn",
            (
                f"0/{probe.total} mtproto-proxy upstream IPs reachable on port 8888 "
                f"({ipport_list}{suffix}). The mtproto_orig responder will SKIP its "
                f"spawn and every mtproto_orig session reports BLOCKED — the skip "
                f"itself is positive evidence Telegram's DC fleet is unreachable "
                f"from this vantage (typical for RU hosts behind ТСПУ on TCP/8888 "
                f"to 91.108.4.0/24 and 149.154.0.0/16). Check the listener-egress "
                f"firewall, or rebuild the image to refresh proxy-multi.conf."
            ),
        )
    return CheckResult(
        "mtproxy-orig-upstream",
        "ok",
        f"{alive_n}/{probe.total} mtproto-proxy upstream IPs reachable on port 8888",
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
    invoking this function. Production ``raise`` (not ``assert``,
    which python -O strips) so a mistake at the call site fails loudly
    rather than silently writing a config that the C binary parses
    then crashes on.
    """
    if not alive:
        raise ValueError(
            "write_pruned_proxy_multi_conf requires at least one alive upstream; "
            "the caller must skip the spawn when alive=[]"
        )
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
    # S2083: production caller (``MTProxyOrigResponder.start``) builds
    # ``dest`` from ``Path(tempfile.gettempdir()) / f"proxy-multi-pruned-
    # {secrets.token_hex(8)}.conf"`` — provably caller-side safe (no
    # user input). Tests pass pytest's ``tmp_path`` fixture, also safe.
    dest.write_text("".join(lines))  # NOSONAR S2083


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

    On WARN, the listener still serves sessions; the session-time
    verdict will be ``BLOCKED`` with a vantage-specific diagnostic
    note from ``_mtproto_orig_failure_note`` (L7 ТСПУ on RU vs local
    daemon issue elsewhere) so the operator sees both the censorship
    interpretation and the L7-vs-local attribution.
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
                f"{timeout_s:.0f}s — responder appears wedged (likely L7 "
                f"ТСПУ filtering the C MTProxy auth_cluster RPC heartbeat "
                f"on RU vantages, starving accept(); strace the slave pid + "
                f"tune -M N to disambiguate from a local daemon issue). "
                f"Sessions will report BLOCKED with a diagnostic note "
                f"explaining the L7-vs-local attribution."
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
            f"responder cannot handshake against itself; sessions will "
            f"report BLOCKED with a diagnostic note disambiguating L7 "
            f"ТСПУ (likely on RU) from a local daemon issue."
        ),
    )


def _check_setpriv_available() -> CheckResult:
    """Verify ``setpriv`` (util-linux) is on PATH for responder privsep.

    censprobe_core._privsep.with_privsep falls back to a no-op when
    ``setpriv`` is missing — which is sound (an old image keeps working)
    but silently re-introduces the CVE surface
    ``_privsep`` was added to close. Surfacing this at preflight gives
    the operator a chance to rebuild the image or apt-install util-linux
    BEFORE the responders spawn unconstrained tunnel binaries.
    """
    from censprobe_core._privsep import setpriv_available

    if setpriv_available():
        return CheckResult(
            "setpriv-available",
            "ok",
            "setpriv on PATH — responders will spawn under dropped privileges",
        )
    return CheckResult(
        "setpriv-available",
        "warn",
        (
            "setpriv NOT on PATH — tunnel binaries (xray/sing-box/hysteria/mtg) "
            "will inherit the listener's root + NET_ADMIN bounding set. "
            "Install util-linux in the listener image to restore the "
            "privilege-separation defense-in-depth."
        ),
    )


async def run_preflight(udp_ports: Sequence[int]) -> PreflightResult:
    """Run all pre-startup checks in order; return a :class:`PreflightResult`.

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
      7. ``mtproxy-orig-upstream`` opens TCP to EVERY upstream IP the C
         MTProxy will dial (parsed from proxy-multi.conf, port 8888).
         Complements (6) by exercising the SPECIFIC path mtproto_orig
         sessions need; closes the false-BLOCKED gap where a host has
         443 reach but 8888 is blocked or treated differently.

    Step 7 is the single authoritative upstream probe: the full
    ``(alive, unreachable)`` partition is returned in
    :attr:`PreflightResult.mtproxy_upstreams` so the mtproto_orig
    responder reuses it for its config-prune instead of re-probing at
    launch. ``checks`` is the operator-facing list; the caller prints it
    (we return data, not formatted output, so the listener can render
    with its rich console and tests can assert on the structure).
    """
    orphan = _cleanup_orphan_rules()
    cap = _check_iptables_capability()
    setpriv = _check_setpriv_available()
    notrack = _try_install_notrack(udp_ports)
    conntrack = _check_conntrack(notrack_installed=notrack.status == "ok")
    dmesg = _check_dmesg_recent_drops()
    dc = await _check_telegram_dc_reach()
    # Refresh proxy-multi.conf + proxy-secret BEFORE probing upstreams, so
    # the alive/unreachable partition matches the IPs the responder will
    # actually dial. Fetch is best-effort: on failure both paths fall back
    # to the baked-in copies (degraded — and likely why the operator is
    # seeing a wedged self-test in the first place).
    conf_path, secret_path, runtime_dir = await _refresh_proxy_runtime_config()
    alive, unreachable = await probe_all_proxy_multi_upstreams(
        path=conf_path,
        timeout_s=_PROXY_MULTI_PREFLIGHT_TIMEOUT_S,
    )
    upstreams = UpstreamProbe(
        alive=alive,
        unreachable=unreachable,
        conf_path=conf_path,
        secret_path=secret_path,
    )
    upstream = _mtproxy_upstream_checkresult(upstreams)
    return PreflightResult(
        checks=[orphan, cap, setpriv, notrack, conntrack, dmesg, dc, upstream],
        mtproxy_upstreams=upstreams,
        mtproxy_runtime_dir=runtime_dir,
    )
