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

    def test_all_factory_includes_both_families(self) -> None:
        # ``InstallStatus.all()`` is the "no signal, try both" fallback
        # for cleanup-only call sites that don't have an explicit
        # InstallStatus handy. Used by preflight._cleanup_orphan_rules.
        status = InstallStatus.all()
        assert "iptables" in status.installed_families
        assert "ip6tables" in status.installed_families

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
