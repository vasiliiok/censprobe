"""Lock the setpriv capability-name syntax.

Regression guard for the bug where `with_privsep(need_bind_service=True)`
emitted `+cap_net_bind_service` — util-linux's setpriv requires
capabilities WITHOUT the `cap_` prefix and bails with
``setpriv: unknown capability "cap_net_bind_service"`` if you include it.
The listener silently swallowed this as "responder Failed to start" and
the bug only surfaced in an end-to-end run.

We assert the literal flag list rather than running setpriv because the
test must pass even on environments where setpriv cannot apply the
bounding set (e.g. inside containers without CAP_SETPCAP).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from censprobe_core._privsep import with_privsep


def test_bounding_set_omits_cap_prefix() -> None:
    argv = with_privsep(["echo", "ok"], need_bind_service=True)
    if argv == ["echo", "ok"]:
        pytest.skip("setpriv not available on this host")
    joined = " ".join(argv)
    assert "+net_bind_service" in joined
    assert "+cap_net_bind_service" not in joined


def test_bounding_set_minimal_when_no_bind() -> None:
    argv = with_privsep(["echo", "ok"], need_bind_service=False)
    if argv == ["echo", "ok"]:
        pytest.skip("setpriv not available on this host")
    joined = " ".join(argv)
    assert "-all" in joined
    assert "net_bind_service" not in joined


@pytest.mark.skipif(shutil.which("setpriv") is None, reason="setpriv not installed")
def test_setpriv_accepts_emitted_cap_names() -> None:
    """setpriv on the host must parse the cap-name flags we emit.

    We invoke `setpriv --bounding-set ... -- /bin/true` and accept any
    failure mode EXCEPT the parser-level "unknown capability" — the
    EPERM that arises when an unprivileged user can't actually shrink
    the bounding set is fine; we only care that the syntax was valid.
    """
    argv = with_privsep(["/bin/true"], need_bind_service=True)
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert "unknown capability" not in result.stderr.lower(), result.stderr
