"""Tests for http._classify_connect_error and _describe_exception.

Regression: the May 2026 ya-a Yandex.Cloud run produced
``http_currenttime_tv__4de7ad`` with ``evidence: {"connect_error": ""}``.
``str(httpx.ConnectError())`` is empty when the underlying httpcore chain
gave no message — the saved evidence had nothing to display. The fix
falls back to the cause chain and finally the exception class name.
"""

from __future__ import annotations

import httpx
from censprobe_core.models import BlockingMethod, Verdict
from censprobe_core.modules.http import _classify_connect_error, _describe_exception


class TestDescribeException:
    def test_uses_str_when_present(self) -> None:
        err = ValueError("connection broke")
        assert _describe_exception(err) == "connection broke"

    def test_falls_back_to_cause_chain(self) -> None:
        outer = httpx.ConnectError("")
        outer.__cause__ = OSError("[Errno 113] No route to host")
        out = _describe_exception(outer)
        assert "OSError" not in out  # we want our type label
        assert "ConnectError" in out
        assert "No route to host" in out

    def test_falls_back_to_class_name_when_everything_empty(self) -> None:
        err = httpx.ConnectError("")
        out = _describe_exception(err)
        assert out == "ConnectError (no message)"

    def test_strips_whitespace_only_message(self) -> None:
        err = httpx.ConnectError("   ")
        out = _describe_exception(err)
        assert out == "ConnectError (no message)"


class TestClassifyConnectError:
    def test_empty_connect_error_never_serialises_to_empty_string(self) -> None:
        # The exact regression: httpx.ConnectError("") used to surface as
        # connect_error: "" in saved reports.
        err = httpx.ConnectError("")
        result = _classify_connect_error(err, "https://example.com/", "http_x", 1)
        assert result.verdict == Verdict.BLOCKED
        assert result.method == BlockingMethod.IP_DROPPED
        assert result.evidence["connect_error"] != ""
        assert "ConnectError" in result.evidence["connect_error"]

    def test_ssl_branch_gets_describe_exception_too(self) -> None:
        err = httpx.ConnectError("[SSL: WRONG_VERSION_NUMBER]")
        result = _classify_connect_error(err, "https://example.com/", "http_x", 1)
        assert result.method == BlockingMethod.TLS_HANDSHAKE_FAILURE
        assert "WRONG_VERSION_NUMBER" in result.evidence["ssl_error"]

    def test_rst_branch_gets_describe_exception_too(self) -> None:
        err = httpx.ConnectError("Connection reset by peer")
        result = _classify_connect_error(err, "https://example.com/", "http_x", 1)
        assert result.method == BlockingMethod.TCP_RST_INJECTION
        assert "Connection reset" in result.evidence["error"]
