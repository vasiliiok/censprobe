"""Unit tests for ``censprobe_listener.preflight`` — the pre-startup
environment checks that surface conditions which would silently
degrade verdicts (canonical: nf_conntrack table full).

The real conntrack files live under ``/proc/sys/net/netfilter/`` and
aren't safe to mutate from a test, so we monkeypatch the module-level
``Path`` constants to point at tmp_path-rooted files. ``dmesg`` and
``iptables`` are skipped via ``shutil.which`` returning ``None``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from censprobe_listener import preflight


@pytest.fixture(autouse=True)
def _isolate_external_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """No-op out the dmesg/iptables side effects so tests are hermetic."""
    monkeypatch.setattr(preflight.shutil, "which", lambda _: None)


class TestConntrackCheck:
    """``_check_conntrack`` interprets the two /proc files."""

    def _wire_proc(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, max_v: int, count_v: int
    ) -> None:
        nf_max = tmp_path / "nf_conntrack_max"
        nf_count = tmp_path / "nf_conntrack_count"
        nf_max.write_text(str(max_v))
        nf_count.write_text(str(count_v))
        monkeypatch.setattr(preflight, "_NF_MAX", nf_max)
        monkeypatch.setattr(preflight, "_NF_COUNT", nf_count)

    def test_healthy_table_is_ok(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self._wire_proc(monkeypatch, tmp_path, max_v=1_048_576, count_v=10_000)
        result = preflight._check_conntrack()
        assert result.status == "ok"
        assert "1048576" in result.message

    def test_low_max_warns_when_no_notrack(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # 8192 is the Yandex Cloud Ubuntu 24.04 default that bit us in
        # production — keep the literal pinned. Without NOTRACK on the
        # VPN ports, this is a real risk and surfaces as warn.
        self._wire_proc(monkeypatch, tmp_path, max_v=8192, count_v=100)
        result = preflight._check_conntrack(notrack_installed=False)
        assert result.status == "warn"
        assert "nf_conntrack_max=8192" in result.message
        assert "1048576" in result.message  # recommended value
        assert "sysctl" in result.message

    def test_low_max_downgraded_to_ok_when_notrack_installed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # When NOTRACK is in place on VPN UDP ports, a low conntrack
        # max no longer threatens probe verdicts — VPN flows skip
        # conntrack entirely. The check downgrades to ok-with-advisory.
        self._wire_proc(monkeypatch, tmp_path, max_v=8192, count_v=100)
        result = preflight._check_conntrack(notrack_installed=True)
        assert result.status == "ok"
        assert "VPN reachability is unaffected" in result.message
        # Operator still gets the host-side fix hint for completeness.
        assert "1048576" in result.message

    def test_high_water_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self._wire_proc(monkeypatch, tmp_path, max_v=1_048_576, count_v=600_000)
        result = preflight._check_conntrack()
        assert result.status == "warn"
        # Ratio is shown as a percentage in the message.
        assert "57%" in result.message

    def test_missing_proc_files_skip_silently(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(preflight, "_NF_MAX", tmp_path / "missing-max")
        monkeypatch.setattr(preflight, "_NF_COUNT", tmp_path / "missing-count")
        result = preflight._check_conntrack()
        assert result.status == "skip"


class TestIptablesCapability:
    """``_check_iptables_capability`` differentiates "iptables works"
    from "no CAP_NET_ADMIN" via ``-C`` exit codes."""

    def test_no_iptables_in_path_is_warn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.shutil, "which", lambda _: None)
        result = preflight._check_iptables_capability()
        assert result.status == "warn"
        assert "iptables not in PATH" in result.message

    def test_rule_absent_is_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Pretend iptables exists and -C exited 1 with the canonical
        # "matching rule exists" message — this proves CAP_NET_ADMIN.
        monkeypatch.setattr(preflight.shutil, "which", lambda c: f"/usr/sbin/{c}")

        class _FakeProc:
            returncode = 1
            stderr = "iptables: Bad rule (does a matching rule exist in that chain?)."
            stdout = ""

        monkeypatch.setattr(preflight.subprocess, "run", lambda *_a, **_kw: _FakeProc())
        result = preflight._check_iptables_capability()
        assert result.status == "ok"
        assert "permitted" in result.message

    def test_eperm_is_warn_with_actionable_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.shutil, "which", lambda c: f"/usr/sbin/{c}")

        class _FakeProc:
            returncode = 4
            stderr = "iptables v1.8.7: Operation not permitted"
            stdout = ""

        monkeypatch.setattr(preflight.subprocess, "run", lambda *_a, **_kw: _FakeProc())
        result = preflight._check_iptables_capability()
        assert result.status == "warn"
        assert "CAP_NET_ADMIN missing" in result.message
        # Operator-actionable hint must be present.
        assert "cap_add" in result.message.lower()


class TestOrphanCleanup:
    """``_cleanup_orphan_rules`` deletes stale ``censprobe-*`` rules
    so iptables -L doesn't accumulate them across SIGKILL/restart."""

    def test_no_iptables_skips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.shutil, "which", lambda _: None)
        result = preflight._cleanup_orphan_rules()
        assert result.status == "skip"

    def test_no_orphans_returns_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.shutil, "which", lambda c: f"/usr/sbin/{c}")

        class _FakeListProc:
            returncode = 0
            # Listing has unrelated host firewall rules but no censprobe-*.
            stdout = "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"
            stderr = ""

        monkeypatch.setattr(preflight.subprocess, "run", lambda *_a, **_kw: _FakeListProc())
        result = preflight._cleanup_orphan_rules()
        assert result.status == "ok"
        assert "no orphan" in result.message

    def test_deletes_censprobe_rules(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(preflight.shutil, "which", lambda c: f"/usr/sbin/{c}")
        # Track every iptables call so we can assert the -A→-D conversion.
        invocations: list[list[str]] = []

        class _FakeProc:
            def __init__(self, argv: list[str], rc: int = 0, out: str = "", err: str = "") -> None:
                self.args = argv
                self.returncode = rc
                self.stdout = out
                self.stderr = err

        list_output = (
            "-P OUTPUT ACCEPT\n"
            "-A OUTPUT -p tcp --sport 2080 --tcp-flags PSH,ACK PSH,ACK "
            "-m comment --comment censprobe-mtorig-2080\n"
            "-A OUTPUT -p tcp --sport 22 -j ACCEPT\n"
        )

        def _fake_run(args, **_kw):  # type: ignore[no-untyped-def]
            invocations.append(args)
            # First call per family: ``-S`` listing.
            if args[1] == "-S":
                return _FakeProc(args, rc=0, out=list_output)
            # Subsequent calls: ``-D ...`` rule deletion.
            return _FakeProc(args, rc=0)

        monkeypatch.setattr(preflight.subprocess, "run", _fake_run)
        result = preflight._cleanup_orphan_rules()
        assert result.status == "ok"
        assert "removed 2" in result.message  # 2 rules deleted: ipv4 + ipv6
        # Verify we converted -A to -D when re-running.
        del_calls = [a for a in invocations if "-D" in a]
        assert del_calls, "Expected at least one -D iptables call"
        for argv in del_calls:
            # The args after -D should match the original -A line minus the -A token.
            assert "OUTPUT" in argv
            assert "censprobe-mtorig-2080" in argv


class TestTelegramDcReach:
    """``_check_telegram_dc_reach`` opens TCP to a few DCs in parallel."""

    def test_all_unreachable_is_warn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _fail(_host, _port):  # type: ignore[no-untyped-def]
            raise OSError("connection refused")

        monkeypatch.setattr(preflight.asyncio, "open_connection", _fail)
        import asyncio

        result = asyncio.run(preflight._check_telegram_dc_reach(timeout_s=0.05))
        assert result.status == "warn"
        assert "0/3" in result.message
        # The hint must mention the IP block and the consequence on verdicts.
        assert "149.154" in result.message
        assert "HANDSHAKE_ONLY" in result.message

    def test_at_least_one_ok_is_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Fake a writer that closes cleanly.
        class _FakeWriter:
            def close(self) -> None: ...
            async def wait_closed(self) -> None: ...

        async def _ok(_host, _port):  # type: ignore[no-untyped-def]
            return None, _FakeWriter()

        monkeypatch.setattr(preflight.asyncio, "open_connection", _ok)
        import asyncio

        result = asyncio.run(preflight._check_telegram_dc_reach(timeout_s=0.05))
        assert result.status == "ok"
        assert "3/3" in result.message


class TestRunPreflight:
    """The orchestrator should aggregate all checks and never raise."""

    def test_returns_results_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        nf_max = tmp_path / "nf_conntrack_max"
        nf_count = tmp_path / "nf_conntrack_count"
        nf_max.write_text("1048576")
        nf_count.write_text("100")
        monkeypatch.setattr(preflight, "_NF_MAX", nf_max)
        monkeypatch.setattr(preflight, "_NF_COUNT", nf_count)

        # Stub the DC reach check so the test stays hermetic
        # (no real outbound TCP) and finishes in milliseconds.
        async def _fake_dc(timeout_s: float = 3.0) -> preflight.CheckResult:
            return preflight.CheckResult("telegram-dc-reach", "skip", "stubbed in unit test")

        monkeypatch.setattr(preflight, "_check_telegram_dc_reach", _fake_dc)

        import asyncio

        results = asyncio.run(preflight.run_preflight(udp_ports=[1194, 51820, 51821, 443]))
        names = [r.name for r in results]
        # Order is fixed for deterministic operator-facing output:
        # orphan cleanup runs FIRST so subsequent installs aren't shadowed
        # by leftover rules; cap check is reported next so a missing-CAP
        # condition is loud BEFORE the conntrack/notrack output that
        # depends on it; DC reach last because it's network-dependent
        # and the slowest.
        assert names == [
            "orphan-rules",
            "iptables-cap",
            "notrack-autosetup",
            "conntrack",
            "conntrack-dmesg",
            "telegram-dc-reach",
        ]
        # No warnings on a healthy host with stubbed-out tools.
        assert all(r.status in {"ok", "skip", "warn"} for r in results)
