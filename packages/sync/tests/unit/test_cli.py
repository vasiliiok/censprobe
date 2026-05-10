"""CLI surface tests via click's CliRunner.

We don't actually exec rclone here — just verify the click command
group's argument parsing: required options, default values, error
messages on misuse.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from censprobe_sync import main as sync_main
from click.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestCliShape:
    def test_cli_has_serve_and_pull(self, runner: CliRunner) -> None:
        result = runner.invoke(sync_main.cli, ["--help"])
        assert result.exit_code == 0
        assert "serve" in result.output
        assert "pull" in result.output

    def test_serve_help_shows_port_default(self, runner: CliRunner) -> None:
        result = runner.invoke(sync_main.cli, ["serve", "--help"])
        assert result.exit_code == 0
        # default port surfaces in --help (click ``show_default=True``).
        assert "8444" in result.output

    def test_pull_requires_all_four_options(self, runner: CliRunner) -> None:
        # No options → click should fail with a missing-option error
        # listing the first required one (alphabetic by definition order).
        result = runner.invoke(sync_main.cli, ["pull"])
        assert result.exit_code != 0
        assert "Missing option" in result.output

    def test_pull_errors_on_bad_fingerprint(
        self, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # If the fingerprint is malformed, _fetch_and_verify_peer_cert
        # raises ValueError BEFORE any network call. The CLI should
        # surface that as a non-zero exit and not call execvp.
        execvp_calls: list[object] = []
        monkeypatch.setattr(sync_main.os, "execvp", lambda *a, **kw: execvp_calls.append((a, kw)))
        # Block any network attempt as a tripwire.
        monkeypatch.setattr(
            sync_main.socket,
            "create_connection",
            MagicMock(side_effect=AssertionError("network must not be touched")),
        )

        result = runner.invoke(
            sync_main.cli,
            [
                "pull",
                "--server-host",
                "1.2.3.4",
                "--port",
                "8444",
                "--token",
                "tok",
                "--cert-fingerprint",
                "definitely-not-hex",
            ],
        )
        assert result.exit_code == 1
        assert not execvp_calls, "execvp must not run on malformed fingerprint"
