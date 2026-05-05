"""
Tests for targets.py — Pydantic models + auto-discovery loader.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from censprobe_core.targets import (
    CfHttpTarget,
    Target,
    TargetFile,
    TargetSet,
    TelegramDC,
    load_targets,
)
from pydantic import ValidationError


class TestTarget:
    def test_minimal_empty(self) -> None:
        t = Target()
        assert t.domain is None
        assert t.urls == []
        assert t.ech_advertised is False

    def test_extra_fields_allowed(self) -> None:
        # extra="allow" — operator-added fields are preserved without
        # requiring a model change.
        t = Target.model_validate({"domain": "x", "blocked_sni": "y"})
        # model_extra captures unknown fields.
        assert t.model_extra is not None
        assert t.model_extra.get("blocked_sni") == "y"


class TestCfHttpTarget:
    def test_host_required_or_domain(self) -> None:
        with pytest.raises(ValueError, match="host"):
            CfHttpTarget.model_validate({})

    def test_domain_coerces_to_host(self) -> None:
        # cloudflare.yaml's http_targets section uses `domain`. The
        # validator normalises it onto `host` so consumers don't care
        # which key the YAML used.
        t = CfHttpTarget.model_validate({"domain": "example.com"})
        assert t.host == "example.com"

    def test_host_takes_precedence(self) -> None:
        # When both are set, host wins — domain is just the fallback.
        t = CfHttpTarget.model_validate({"host": "primary", "domain": "secondary"})
        assert t.host == "primary"


class TestTelegramDC:
    def test_string_ip_coerced_to_list(self) -> None:
        # Real telegram.yaml has both single-string and list forms.
        dc = TelegramDC.model_validate({"id": 1, "ipv4": "1.2.3.4", "ports": [443]})
        assert dc.ipv4 == ["1.2.3.4"]

    def test_ports_required(self) -> None:
        # No silent default for ports — every DC must enumerate its ports
        # explicitly. A typo'd `port: 443` (singular) used to land here as
        # an extra-allow attribute and the probe ran against a stale [443].
        with pytest.raises(ValidationError, match="ports"):
            TelegramDC.model_validate({"id": 1})

    def test_ports_min_length_one(self) -> None:
        with pytest.raises(ValidationError, match="ports"):
            TelegramDC.model_validate({"id": 1, "ports": []})

    def test_none_ipv4_becomes_empty_list(self) -> None:
        dc = TelegramDC.model_validate({"id": 1, "ipv4": None, "ports": [443]})
        assert dc.ipv4 == []


class TestLoadTargets:
    def test_missing_directory_returns_empty(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Loader must not crash on a missing directory — operator may
        # have just renamed the path. A warning is logged so they can
        # find it.
        with caplog.at_level(logging.WARNING):
            ts = load_targets(tmp_path / "nonexistent")
        assert ts.files == {}
        assert any("does not exist" in r.message for r in caplog.records)

    def test_empty_directory_returns_empty_set(self, tmp_path: Path) -> None:
        ts = load_targets(tmp_path)
        assert ts.files == {}

    def test_auto_discover_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "news.yaml").write_text("targets:\n  - domain: meduza.io\n    name: meduza\n")
        (tmp_path / "social.yaml").write_text("targets:\n  - domain: facebook.com\n    name: fb\n")
        ts = load_targets(tmp_path)
        assert set(ts.files) == {"news", "social"}
        assert len(ts.files["news"].targets) == 1
        assert ts.files["news"].targets[0].domain == "meduza.io"

    def test_explicit_files_overrides_discovery(self, tmp_path: Path) -> None:
        # When `files` is non-empty, only the listed basenames are loaded
        # — even if other YAMLs exist on disk.
        (tmp_path / "news.yaml").write_text("targets: []\n")
        (tmp_path / "social.yaml").write_text("targets: []\n")
        ts = load_targets(tmp_path, files=["news"])
        assert set(ts.files) == {"news"}

    def test_module_owned_excluded_from_generic_view(self, tmp_path: Path) -> None:
        # Telegram + cloudflare files should still be in `files` but
        # excluded from the generic view fed to dns/tcp/tls/http.
        (tmp_path / "news.yaml").write_text("targets:\n  - domain: meduza.io\n    name: meduza\n")
        (tmp_path / "telegram.yaml").write_text("targets:\n  - domain: t.me\n    name: t_me\n")
        ts = load_targets(tmp_path, module_owned=["telegram"])
        assert "telegram" in ts.files
        assert "telegram" in ts.module_owned
        # Generic view excludes telegram.
        domains = ts.domains()
        assert "meduza.io" in domains
        # No telegram domain leaks in (telegram.yaml's `targets` list is
        # scanned only for the generic side, and module_owned drops it).
        assert "t.me" not in domains

    def test_malformed_yaml_logs_warning_and_skips(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Today load_targets is warn-only. The CI validate-config job
        # promotes that warning to an error; this test pins the
        # underlying behaviour (warning logged, file skipped, sibling
        # files still loaded).
        (tmp_path / "good.yaml").write_text("targets:\n  - domain: ok.com\n    name: ok\n")
        (tmp_path / "broken.yaml").write_text("targets: [not a dict\n")
        with caplog.at_level(logging.WARNING):
            ts = load_targets(tmp_path)
        assert "good" in ts.files
        assert "broken" not in ts.files
        # The warning must mention the offending file path so operators
        # don't have to grep for it.
        assert any("broken" in r.message.lower() for r in caplog.records)

    def test_top_level_non_mapping_logs_and_skips(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # A YAML whose top-level value is a list / string instead of a
        # mapping must be rejected — the rest of the loader assumes a
        # dict shape.
        (tmp_path / "scalar.yaml").write_text("just a string\n")
        with caplog.at_level(logging.WARNING):
            ts = load_targets(tmp_path)
        assert ts.files == {}
        assert any("not a YAML mapping" in r.message for r in caplog.records)

    def test_symlink_skipped(self, tmp_path: Path) -> None:
        # load_targets refuses to follow symlinks (defence-in-depth, same
        # rationale as load_json in sync-api: an operator's `git pull`
        # could ship a symlink → /etc/passwd).
        real = tmp_path / "real.yaml"
        real.write_text("targets:\n  - domain: ok.com\n    name: ok\n")
        link = tmp_path / "linked.yaml"
        link.symlink_to(real)
        ts = load_targets(tmp_path)
        # The real file loads; the symlink is skipped.
        assert "real" in ts.files
        assert "linked" not in ts.files


class TestTargetSetViews:
    def test_domains_dedup_and_sort(self) -> None:
        tf = TargetFile.model_validate(
            {
                "targets": [
                    {"domain": "z.com", "name": "z"},
                    {"domain": "a.com", "name": "a"},
                    {"domain": "z.com", "name": "z2"},  # dup
                ]
            }
        )
        ts = TargetSet(files={"news": tf})
        assert ts.domains() == ["a.com", "z.com"]

    def test_telegram_web_folded_into_domains(self) -> None:
        # Telegram's web hostnames are folded into domains() because the
        # DNS module wants them through the same resolver-comparison
        # path — the dedicated telegram module only handles DC ports.
        news = TargetFile.model_validate({"targets": [{"domain": "meduza.io", "name": "meduza"}]})
        tg = TargetFile.model_validate({"web": ["t.me", "telegram.org"]})
        ts = TargetSet(files={"news": news, "telegram": tg}, module_owned=["telegram"])
        assert "t.me" in ts.domains()
        assert "telegram.org" in ts.domains()

    def test_tcp_targets_dedup(self) -> None:
        tf = TargetFile.model_validate(
            {
                "tcp_targets": [
                    {"ip": "1.1.1.1", "port": 443},
                    {"ip": "1.1.1.1", "port": 443},  # dup
                    {"ip": "8.8.8.8", "port": 443},
                ]
            }
        )
        ts = TargetSet(files={"resolvers": tf})
        assert sorted(ts.tcp_targets()) == [("1.1.1.1", 443), ("8.8.8.8", 443)]
