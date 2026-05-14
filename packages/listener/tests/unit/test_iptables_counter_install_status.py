"""Tests for :class:`InstallStatus` symmetry between install_counter
and remove_counter.

Pre-2026-05 ``install_counter`` returned a bare ``bool`` ("at least one
family installed?") and ``remove_counter`` blindly tried ``-D`` on
BOTH families. The asymmetry meant a host where only one family is
present (e.g., IPv6-only or no ip6tables binary) would log
"rule does not exist" noise from the wrong family on every shutdown.

The refactor returns a frozen :class:`InstallStatus` carrying the
specific family names that succeeded; ``remove_counter(status=...)``
consults that set and avoids the spurious calls.
"""

from __future__ import annotations

import pytest
from censprobe_listener._iptables_counter import InstallStatus


class TestInstallStatus:
    def test_empty_status_is_falsy(self) -> None:
        # Nothing installed → falsy. Caller can write
        # `if status:` to gate the throughput-reader registration.
        assert not bool(InstallStatus())
        assert not bool(InstallStatus(installed_families=frozenset()))

    def test_one_family_is_truthy(self) -> None:
        # At least one family installed → truthy. Wire-throughput will
        # work via that family.
        assert bool(InstallStatus(installed_families=frozenset({"iptables"})))
        assert bool(InstallStatus(installed_families=frozenset({"ip6tables"})))

    def test_both_families_is_truthy(self) -> None:
        # The healthy dual-stack case.
        both = InstallStatus(installed_families=frozenset({"iptables", "ip6tables"}))
        assert bool(both)

    def test_frozen_dataclass_is_hashable(self) -> None:
        # frozen=True keeps the dataclass immutable, but it must also
        # be hashable so callers can stash it in dicts or sets if they
        # need to (e.g., a responder registry keyed by status).
        s1 = InstallStatus(installed_families=frozenset({"iptables"}))
        s2 = InstallStatus(installed_families=frozenset({"iptables"}))
        assert hash(s1) == hash(s2)
        assert s1 == s2

    def test_default_factory_is_empty(self) -> None:
        # The pre-init default — used as the placeholder before the
        # responder calls install_counter. Must be falsy so the early
        # cleanup path doesn't try to remove an as-yet-uninstalled rule.
        default = InstallStatus()
        assert default.installed_families == frozenset()
        assert not bool(default)


class TestInstallRemoveSymmetry:
    """Round-trip: install_counter returns a status; remove_counter
    consults it and skips families that never went in.

    The original bug this fix targets: on a host where ``ip6tables`` is
    missing (or its install silently failed), the old remove_counter
    blindly invoked ``ip6tables -D``, polluting logs with
    "rule does not exist" noise even though the daemon never had that
    rule to remove. The new flow stores the InstallStatus returned by
    install_counter and uses it as the iteration set on remove.
    """

    @pytest.mark.asyncio
    async def test_remove_only_iterates_installed_families(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pretend ip6tables is absent (shutil.which returns None for it)
        # — install_counter should produce a status with only "iptables",
        # and remove_counter consulting that status should NOT call
        # ip6tables -D at all.
        from censprobe_listener import _iptables_counter as ipc

        which_calls: list[str] = []
        which_returns = {"iptables": "/sbin/iptables"}  # ip6tables omitted

        def fake_which(cmd: str) -> str | None:
            which_calls.append(cmd)
            return which_returns.get(cmd)

        monkeypatch.setattr(ipc.shutil, "which", fake_which)

        # The check (-C) and add (-A) subprocesses both succeed. Capture
        # the cmd-line argv lists so we can assert NO ip6tables call.
        exec_calls: list[list[str]] = []

        class _FakeProc:
            returncode = 0

            async def wait(self) -> int:
                return 0

        async def fake_exec(*args: object, **kwargs: object) -> _FakeProc:
            exec_calls.append([str(a) for a in args])
            return _FakeProc()

        monkeypatch.setattr(ipc.asyncio, "create_subprocess_exec", fake_exec)

        rule_args = ["-p", "tcp", "--sport", "443"]
        status = await ipc.install_counter("OUTPUT", rule_args, "test-comment")

        # Only iptables family in the status; install used -C then -A on it.
        assert status.installed_families == frozenset({"iptables"})
        assert all(call[0] == "iptables" for call in exec_calls), (
            f"install must not call ip6tables when which() said it's missing; "
            f"got {[c[0] for c in exec_calls]}"
        )

        # Now the cleanup: pass the status, only iptables -D should fire.
        exec_calls.clear()
        await ipc.remove_counter("OUTPUT", rule_args, status)
        assert exec_calls, "remove_counter must run at least one -D"
        assert all(call[0] == "iptables" for call in exec_calls), (
            f"remove must not call ip6tables when status excludes it; "
            f"got {[c[0] for c in exec_calls]}"
        )

    @pytest.mark.asyncio
    async def test_remove_with_none_status_iterates_both_families(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The status=None fallback path (cleanup-only call sites) MUST
        # try both families — that's what preserves pre-2026-05 behavior
        # for callers that don't have an InstallStatus handy.
        from censprobe_listener import _iptables_counter as ipc

        monkeypatch.setattr(ipc.shutil, "which", lambda cmd: f"/sbin/{cmd}")

        exec_calls: list[list[str]] = []

        class _FakeProc:
            returncode = 0

            async def wait(self) -> int:
                return 0

        async def fake_exec(*args: object, **kwargs: object) -> _FakeProc:
            exec_calls.append([str(a) for a in args])
            return _FakeProc()

        monkeypatch.setattr(ipc.asyncio, "create_subprocess_exec", fake_exec)

        await ipc.remove_counter("OUTPUT", ["-p", "tcp"], status=None)
        cmds = sorted({call[0] for call in exec_calls})
        assert cmds == ["ip6tables", "iptables"], (
            f"status=None must fan out to BOTH families; got {cmds}"
        )

    @pytest.mark.asyncio
    async def test_remove_with_empty_status_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # An empty status (default InstallStatus()) means nothing was
        # installed — remove_counter must not invoke any subprocess.
        # Verifies the early-cleanup path doesn't try to delete phantom
        # rules.
        from censprobe_listener import _iptables_counter as ipc

        monkeypatch.setattr(ipc.shutil, "which", lambda cmd: f"/sbin/{cmd}")

        exec_calls: list[list[str]] = []

        class _FakeProc:
            returncode = 0

            async def wait(self) -> int:
                return 0

        async def fake_exec(*args: object, **kwargs: object) -> _FakeProc:
            exec_calls.append([str(a) for a in args])
            return _FakeProc()

        monkeypatch.setattr(ipc.asyncio, "create_subprocess_exec", fake_exec)

        await ipc.remove_counter("OUTPUT", ["-p", "tcp"], InstallStatus())
        assert not exec_calls, "empty status must produce zero subprocess calls"
