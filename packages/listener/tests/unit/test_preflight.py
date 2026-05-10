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

    def test_low_max_warns_with_sysctl_fix(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # 8192 is the Yandex Cloud Ubuntu 24.04 default that bit us in
        # production — keep the literal pinned.
        self._wire_proc(monkeypatch, tmp_path, max_v=8192, count_v=100)
        result = preflight._check_conntrack()
        assert result.status == "warn"
        assert "nf_conntrack_max=8192" in result.message
        assert "sysctl" in result.message
        assert "1048576" in result.message  # recommended value

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


class TestRunPreflight:
    """The orchestrator should aggregate all checks and never raise."""

    def test_returns_three_results_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        nf_max = tmp_path / "nf_conntrack_max"
        nf_count = tmp_path / "nf_conntrack_count"
        nf_max.write_text("1048576")
        nf_count.write_text("100")
        monkeypatch.setattr(preflight, "_NF_MAX", nf_max)
        monkeypatch.setattr(preflight, "_NF_COUNT", nf_count)

        results = preflight.run_preflight(udp_ports=[1194, 51820, 51821, 443])
        names = [r.name for r in results]
        assert names == ["conntrack", "conntrack-dmesg", "notrack-autosetup"]
        # No warnings on a healthy host with stubbed-out tools.
        assert all(r.status in {"ok", "skip"} for r in results)
