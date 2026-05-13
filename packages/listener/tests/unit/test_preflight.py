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

        async def _fake_upstream(timeout_s: float = 3.0) -> preflight.CheckResult:
            return preflight.CheckResult("mtproxy-orig-upstream", "skip", "stubbed in unit test")

        monkeypatch.setattr(preflight, "_check_telegram_dc_reach", _fake_dc)
        monkeypatch.setattr(preflight, "_check_mtproxy_orig_upstream_reach", _fake_upstream)

        import asyncio

        results = asyncio.run(preflight.run_preflight(udp_ports=[1194, 51820, 51821, 443]))
        names = [r.name for r in results]
        # Order is fixed for deterministic operator-facing output:
        # orphan cleanup runs FIRST so subsequent installs aren't shadowed
        # by leftover rules; cap check is reported next so a missing-CAP
        # condition is loud BEFORE the conntrack/notrack output that
        # depends on it; DC reach checks run last because they're
        # network-dependent and the slowest, with the cheaper 443-port
        # public probe ahead of the per-proxy-multi.conf 8888 probe.
        assert names == [
            "orphan-rules",
            "iptables-cap",
            "notrack-autosetup",
            "conntrack",
            "conntrack-dmesg",
            "telegram-dc-reach",
            "mtproxy-orig-upstream",
        ]
        # No warnings on a healthy host with stubbed-out tools.
        assert all(r.status in {"ok", "skip", "warn"} for r in results)


class TestParseProxyMultiUpstreams:
    """``_parse_proxy_multi_upstreams`` extracts (ip, port, cluster) tuples."""

    def test_extracts_canonical_lines(self, tmp_path: Path) -> None:
        p = tmp_path / "proxy-multi.conf"
        p.write_text(
            "# force_probability 10 10\n"
            "default 2;\n"
            "proxy_for 1 149.154.175.50:8888;\n"
            "proxy_for 2 149.154.161.144:8888;\n"
            "proxy_for 4 91.108.4.206:8888;\n"
        )
        got = preflight._parse_proxy_multi_upstreams(p)
        assert got == [
            ("149.154.175.50", 8888, "1"),
            ("149.154.161.144", 8888, "2"),
            ("91.108.4.206", 8888, "4"),
        ]

    def test_dedupes_repeated_ipport(self, tmp_path: Path) -> None:
        p = tmp_path / "proxy-multi.conf"
        # The same (ip, port) appears in both directions (e.g. cluster 1
        # and cluster -1 in real proxy-multi.conf); dedup keeps the
        # first-seen entry so we don't probe the same socket twice.
        p.write_text("proxy_for 1 149.154.175.50:8888;\nproxy_for -1 149.154.175.50:8888;\n")
        got = preflight._parse_proxy_multi_upstreams(p)
        assert got == [("149.154.175.50", 8888, "1")]

    def test_skips_malformed_and_comments(self, tmp_path: Path) -> None:
        p = tmp_path / "proxy-multi.conf"
        p.write_text(
            "# comment line\n"
            "default 2;\n"  # not a proxy_for line
            "proxy_for 1 not-an-ip-port;\n"  # no colon → dropped
            "proxy_for 1 1.2.3.4:notanint;\n"  # bad port → dropped
            "proxy_for 1\n"  # truncated → dropped
            "proxy_for 1 1.2.3.4:8888;\n"  # valid
        )
        got = preflight._parse_proxy_multi_upstreams(p)
        assert got == [("1.2.3.4", 8888, "1")]

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        # Image built without the mtproxy-orig stage → file doesn't exist;
        # the upstream check then SKIPs rather than raising.
        assert preflight._parse_proxy_multi_upstreams(tmp_path / "absent.conf") == []


class TestMtproxyOrigUpstreamReach:
    """``_check_mtproxy_orig_upstream_reach`` samples + tcp-probes."""

    def test_skip_when_conf_missing(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(preflight, "_PROXY_MULTI_CONF_PATH", tmp_path / "absent.conf")
        import asyncio

        r = asyncio.run(preflight._check_mtproxy_orig_upstream_reach())
        assert r.status == "skip"
        assert "proxy-multi.conf" in r.message

    def test_warn_when_zero_reachable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        p = tmp_path / "proxy-multi.conf"
        p.write_text("proxy_for 1 1.2.3.4:8888;\nproxy_for 2 5.6.7.8:8888;\n")
        monkeypatch.setattr(preflight, "_PROXY_MULTI_CONF_PATH", p)

        async def _all_fail(host: str, port: int) -> tuple:  # type: ignore[type-arg]
            raise TimeoutError

        # asyncio.open_connection is what _connect inside the check calls;
        # stub it to fail so we test the WARN branch deterministically.
        monkeypatch.setattr(preflight.asyncio, "open_connection", _all_fail)

        import asyncio

        r = asyncio.run(preflight._check_mtproxy_orig_upstream_reach(timeout_s=0.05))
        assert r.status == "warn"
        # The error message must explain WHY this is not a network block —
        # operators reading the listener startup banner need to know that
        # mtproto_orig BLOCKED verdicts are being rewritten to ERROR.
        assert "8888" in r.message
        assert "ERROR" in r.message

    def test_one_ip_per_cluster_sample(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Cluster 4 has 10 entries in real proxy-multi.conf; preflight
        # MUST pick at most one of them so the sample exercises distinct
        # clusters rather than the same DC ten times.
        p = tmp_path / "proxy-multi.conf"
        p.write_text(
            "".join(f"proxy_for 4 91.108.4.{i}:8888;\n" for i in (133, 143, 149, 158))
            + "proxy_for 5 91.108.56.110:8888;\n"
        )
        monkeypatch.setattr(preflight, "_PROXY_MULTI_CONF_PATH", p)
        attempted: list[tuple[str, int]] = []

        async def _record(host: str, port: int) -> tuple:  # type: ignore[type-arg]
            attempted.append((host, port))
            raise OSError

        monkeypatch.setattr(preflight.asyncio, "open_connection", _record)

        import asyncio

        asyncio.run(preflight._check_mtproxy_orig_upstream_reach(timeout_s=0.05))
        # First IP for each of cluster 4 and 5 — not all 5 entries.
        assert attempted == [("91.108.4.133", 8888), ("91.108.56.110", 8888)]


class TestMtproxyOrigSelfTest:
    """``run_mtproxy_orig_self_test`` consumes the protocol_probes verdict."""

    def test_ok_when_probe_returns_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from censprobe_core.models import Verdict
        from censprobe_core.protocol_probes import ProbeResult

        async def _probe_ok(host: str, port: int, secret_hex: str) -> ProbeResult:
            r = ProbeResult()
            r.verdict = Verdict.OK
            r.handshake_ok = True
            return r

        import censprobe_core.protocol_probes as pp

        monkeypatch.setattr(pp, "probe_mtproto_orig", _probe_ok)

        import asyncio

        r = asyncio.run(
            preflight.run_mtproxy_orig_self_test(port=2080, secret_hex="dd" + "00" * 16)
        )
        assert r.status == "ok"

    def test_warn_when_probe_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from censprobe_core.models import Verdict
        from censprobe_core.protocol_probes import ProbeResult

        async def _probe_blocked(host: str, port: int, secret_hex: str) -> ProbeResult:
            r = ProbeResult()
            r.verdict = Verdict.BLOCKED
            r.error = "orig_resPQ_len_timeout_post_init"
            return r

        import censprobe_core.protocol_probes as pp

        monkeypatch.setattr(pp, "probe_mtproto_orig", _probe_blocked)

        import asyncio

        r = asyncio.run(
            preflight.run_mtproxy_orig_self_test(port=2080, secret_hex="dd" + "00" * 16)
        )
        assert r.status == "warn"
        assert "ERROR" in r.message  # explains the downgrade behaviour

    def test_warn_when_probe_hangs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import asyncio

        async def _hang(host: str, port: int, secret_hex: str) -> object:
            await asyncio.sleep(10)
            raise AssertionError("should not return")

        import censprobe_core.protocol_probes as pp

        monkeypatch.setattr(pp, "probe_mtproto_orig", _hang)

        r = asyncio.run(
            preflight.run_mtproxy_orig_self_test(
                port=2080, secret_hex="dd" + "00" * 16, timeout_s=0.1
            )
        )
        assert r.status == "warn"
        assert "wedged" in r.message.lower() or "timeout" in r.message.lower()


class TestProbeAllProxyMultiUpstreams:
    """``probe_all_proxy_multi_upstreams`` enumerates ALL upstreams, not a sample."""

    def test_partitions_alive_and_unreachable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Two clusters, three IPs total; the rigged TCP-probe stub says
        # the middle one is alive, the outer two are dead. The function
        # must return them split into ([alive], [unreachable]) with the
        # original config-file order preserved within each list.
        p = tmp_path / "proxy-multi.conf"
        p.write_text(
            "proxy_for 1 1.2.3.4:8888;\nproxy_for 2 5.6.7.8:8888;\nproxy_for 3 9.10.11.12:8888;\n"
        )
        monkeypatch.setattr(preflight, "_PROXY_MULTI_CONF_PATH", p)

        async def _probe(host: str, port: int) -> tuple:  # type: ignore[type-arg]
            if host == "5.6.7.8":
                # _probe inside the helper calls open_connection() and
                # only inspects the writer, so a tuple shape that works
                # for `_, writer = await ...` is enough.
                class _W:
                    def close(self) -> None:
                        pass

                    async def wait_closed(self) -> None:
                        pass

                return (None, _W())
            raise OSError("rejected")

        monkeypatch.setattr(preflight.asyncio, "open_connection", _probe)

        import asyncio

        alive, dead = asyncio.run(preflight.probe_all_proxy_multi_upstreams(timeout_s=0.05))
        assert alive == [("5.6.7.8", 8888, "2")]
        assert dead == [("1.2.3.4", 8888, "1"), ("9.10.11.12", 8888, "3")]

    def test_empty_when_conf_missing(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # No proxy-multi.conf — return ([], []) so caller can distinguish
        # "image missing the binary" from "0/N alive due to censorship".
        monkeypatch.setattr(preflight, "_PROXY_MULTI_CONF_PATH", tmp_path / "absent.conf")

        import asyncio

        alive, dead = asyncio.run(preflight.probe_all_proxy_multi_upstreams())
        assert alive == [] and dead == []


class TestWritePrunedProxyMultiConf:
    """``write_pruned_proxy_multi_conf`` emits a minimal valid config."""

    def test_emits_proxy_for_lines_in_order(self, tmp_path: Path) -> None:
        src = tmp_path / "src.conf"
        src.write_text("# force_probability 10 10\ndefault 4;\nproxy_for 1 a:b:8888;\n")
        dest = tmp_path / "out.conf"

        preflight.write_pruned_proxy_multi_conf(
            [("1.2.3.4", 8888, "2"), ("5.6.7.8", 443, "203")],
            dest,
            source=src,
        )
        body = dest.read_text()
        assert "default 4;" in body  # mirrored from source
        # Lines preserved in the order they were passed in.
        i_pf1 = body.find("proxy_for 2 1.2.3.4:8888;")
        i_pf2 = body.find("proxy_for 203 5.6.7.8:443;")
        assert 0 < i_pf1 < i_pf2

    def test_fallback_default_when_source_has_no_default(self, tmp_path: Path) -> None:
        src = tmp_path / "src.conf"
        src.write_text("# nothing useful here\n")
        dest = tmp_path / "out.conf"
        preflight.write_pruned_proxy_multi_conf([("1.2.3.4", 8888, "1")], dest, source=src)
        body = dest.read_text()
        # Falls back to DC 2 (Frankfurt-routed cluster, normally most-
        # reachable). The C binary refuses to start without a default,
        # so this fallback is load-bearing.
        assert body.startswith("default 2;")

    def test_rejects_empty_alive_list(self, tmp_path: Path) -> None:
        # Caller is supposed to handle 0-alive specially (skip launching
        # mtproto-proxy entirely). Asserting here protects against a
        # caller mistake silently writing an unparseable config.
        with pytest.raises(AssertionError):
            preflight.write_pruned_proxy_multi_conf([], tmp_path / "out.conf")
