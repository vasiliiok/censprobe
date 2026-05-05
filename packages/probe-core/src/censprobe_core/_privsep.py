"""
_privsep.py — Privilege-separation helpers for tunnel-binary subprocesses.

xray / sing-box / hysteria do not need CAP_NET_ADMIN or CAP_NET_RAW. The
listener container has both in its bounding set (cap_add in compose) so
WG/OpenVPN responders can configure interfaces; without privsep the
tunnel binaries inherit those caps and an RCE in any of them — these
parse network input and decode crypto frames — escalates straight to a
host-net-mode + NET_ADMIN root shell.

We wrap each tunnel-binary spawn in `setpriv`:
  * --reuid 65534 / --regid 65534  → drop to nobody
  * --bounding-set -all (+cap_net_bind_service for port-443 binders)
  * --inh-caps / --ambient-caps mirror the bounding-set
  * --no-new-privs                 → child cannot regain caps via setcap

The listener python process stays root so it can keep writing
/workspace/reports owned by host root and tear down WG/AWG/OpenVPN
interfaces at shutdown. Only the long-lived child processes are
de-privileged — that's the whole RCE blast-radius surface.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

# Debian convention: nobody=65534, nogroup=65534. python:3.12-slim ships
# with this entry in /etc/passwd. We use numeric IDs in setpriv args so
# the wrapper works even if /etc/passwd is hardened later.
_NOBODY_UID = 65534
_NOBODY_GID = 65534


def setpriv_available() -> bool:
    """True iff /usr/bin/setpriv (util-linux) is on PATH.

    On the listener/client images it is, via the python:3.12-slim Debian
    base. If a custom build dropped util-linux, we fall back to plain
    spawn rather than refusing to run — the user is then no worse off
    than before privsep was added.
    """
    return shutil.which("setpriv") is not None


def chown_tree(path: Path, uid: int = _NOBODY_UID, gid: int = _NOBODY_GID) -> None:
    """Recursively chown `path` to (uid, gid).

    Used after writing config files (and any cert/key material) but
    BEFORE spawning the subprocess: the tunnel binary runs as nobody
    and would otherwise be unable to read root-owned 0o600 files sitting
    in the tempdir.
    """
    if not path.exists():
        return
    os.chown(path, uid, gid)
    if path.is_dir():
        for child in path.iterdir():
            chown_tree(child, uid, gid)


def with_privsep(cmd: list[str], *, need_bind_service: bool = False) -> list[str]:
    """Wrap `cmd` so the spawned process runs as nobody with reduced caps.

    `need_bind_service=True` keeps CAP_NET_BIND_SERVICE in bounding +
    inheritable + ambient (xray for VLESS+Reality on 443, hysteria 2 on
    443). Sing-box for SS does NOT need it — Shadowsocks ports default
    well above 1024 — so the bounding set collapses to empty.

    If setpriv is missing we return the cmd unchanged. That's a soft
    failure: the privsep is defense-in-depth, not the only line of
    defence (the listener already runs in a container, and the cred-
    server pinning + token model bound the network exposure). Logged at
    the responder layer so a missing-binary regression is visible.
    """
    if not setpriv_available():
        return cmd
    bounds = "-all"
    if need_bind_service:
        bounds = "-all,+cap_net_bind_service"
    return [
        "setpriv",
        "--reuid",
        str(_NOBODY_UID),
        "--regid",
        str(_NOBODY_GID),
        "--clear-groups",
        "--bounding-set",
        bounds,
        "--inh-caps",
        bounds,
        "--ambient-caps",
        bounds,
        "--no-new-privs",
        "--",
        *cmd,
    ]
