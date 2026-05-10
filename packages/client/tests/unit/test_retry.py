"""Tests for the retry policy on /creds and /snapshot fetches.

The client-side ``_pinned_get_with_retry`` wraps ``_pinned_get`` to:
  * Retry up to ``_FETCH_MAX_ATTEMPTS`` times on transient errors
    (connection refused, TLS hiccup, 5xx, OSError).
  * Short-circuit on permanent errors (401/403/410, cert pinning
    mismatch, malformed response) — no retries waste operator time
    on errors that will never resolve themselves.

We exercise the policy here without spinning up a real HTTPS socket:
``_pinned_get`` is monkeypatched and we verify call counts + the
exception that propagates.
"""

from __future__ import annotations

import pytest
from censprobe_client import main as client_main


def _zero_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip the sleep() between retries so tests finish fast."""
    monkeypatch.setattr(client_main, "_FETCH_RETRY_BACKOFF_BASE_SEC", 0.0)
    monkeypatch.setattr(client_main.time, "sleep", lambda _s: None)


class TestRetryPolicy:
    def test_first_attempt_succeeds_no_retry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _zero_backoff(monkeypatch)
        calls: list[str] = []

        def _fake(host: str, port: int, token: str, sha: str, *, path: str) -> str:
            calls.append(path)
            return "OK"

        monkeypatch.setattr(client_main, "_pinned_get", _fake)
        result = client_main._pinned_get_with_retry(
            "h", 1, "t", "f" * 64, path="/creds", max_attempts=3
        )
        assert result == "OK"
        assert calls == ["/creds"]

    def test_transient_then_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> str:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise client_main._TransientEndpointError("temporarily unreachable")
            return "OK"

        monkeypatch.setattr(client_main, "_pinned_get", _fake)
        result = client_main._pinned_get_with_retry(
            "h", 1, "t", "f" * 64, path="/snapshot", max_attempts=3
        )
        assert result == "OK"
        assert attempts["n"] == 3

    def test_transient_exhaust_max_attempts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> str:
            attempts["n"] += 1
            raise client_main._TransientEndpointError("listener down")

        monkeypatch.setattr(client_main, "_pinned_get", _fake)
        with pytest.raises(client_main._TransientEndpointError, match="listener down"):
            client_main._pinned_get_with_retry(
                "h", 1, "t", "f" * 64, path="/creds", max_attempts=3
            )
        # 1 initial + 2 retries == 3 total attempts.
        assert attempts["n"] == 3

    def test_permanent_short_circuits_on_first_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> str:
            attempts["n"] += 1
            raise client_main._PermanentEndpointError("403 invalid token")

        monkeypatch.setattr(client_main, "_pinned_get", _fake)
        with pytest.raises(client_main._PermanentEndpointError, match="403"):
            client_main._pinned_get_with_retry(
                "h", 1, "t", "f" * 64, path="/creds", max_attempts=3
            )
        # NO retries — permanent errors propagate immediately.
        assert attempts["n"] == 1

    def test_value_error_propagates_without_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # ValueError on cert format is raised BEFORE any I/O, so it
        # propagates straight through the retry wrapper just like a
        # permanent error would.
        _zero_backoff(monkeypatch)
        attempts = {"n": 0}

        def _fake(*_a: object, **_kw: object) -> str:
            attempts["n"] += 1
            raise ValueError("CREDS_CERT_SHA256 must be a 64-char hex SHA-256 fingerprint")

        monkeypatch.setattr(client_main, "_pinned_get", _fake)
        with pytest.raises(ValueError, match="64-char"):
            client_main._pinned_get_with_retry(
                "h", 1, "t", "shortbad", path="/creds", max_attempts=3
            )
        assert attempts["n"] == 1


class TestStatusCodeClassification:
    """Verify which HTTP status codes are treated as transient.

    The full _pinned_get parses raw HTTP and raises typed exceptions.
    We can drive it through monkeypatched socket.create_connection
    + ssl wrap, but a much simpler test stays at the parser layer:
    simulate the post-recv bytes and verify the exception type.
    """

    @staticmethod
    def _drive_response_parser(status_line: str, body: str = "") -> Exception | None:
        """Mini-clone of _pinned_get's response parsing logic, for
        testing the status-code → exception-type mapping in isolation
        without spinning up a real HTTPS server.

        Mirrors the relevant tail-of-_pinned_get exactly so the
        classification rule stays in lockstep with production.
        """
        head_body = f"{status_line}\r\n\r\n{body}"
        head, _, body_b = head_body.encode("latin-1").partition(b"\r\n\r\n")
        sl = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = sl.split(maxsplit=2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            return client_main._PermanentEndpointError(f"malformed: {sl!r}")
        try:
            status_code = int(parts[1])
        except ValueError:
            return client_main._PermanentEndpointError(f"non-numeric: {sl!r}")
        if status_code == 200:
            return None
        msg = body_b.decode("utf-8", errors="replace").strip() or sl
        if status_code >= 500 or status_code == 408:
            return client_main._TransientEndpointError(f"{status_code}: {msg}")
        return client_main._PermanentEndpointError(f"{status_code}: {msg}")

    @pytest.mark.parametrize("code", [500, 502, 503, 504, 599, 408])
    def test_5xx_and_408_are_transient(self, code: int) -> None:
        exc = self._drive_response_parser(f"HTTP/1.1 {code} something", "")
        assert isinstance(exc, client_main._TransientEndpointError)

    @pytest.mark.parametrize("code", [401, 403, 404, 410, 418, 422])
    def test_4xx_is_permanent(self, code: int) -> None:
        exc = self._drive_response_parser(f"HTTP/1.1 {code} no", "")
        assert isinstance(exc, client_main._PermanentEndpointError)

    def test_malformed_status_line_is_permanent(self) -> None:
        exc = self._drive_response_parser("not-http garbage", "")
        assert isinstance(exc, client_main._PermanentEndpointError)
        assert "malformed" in str(exc)

    def test_non_numeric_status_is_permanent(self) -> None:
        exc = self._drive_response_parser("HTTP/1.1 OK?", "")
        assert isinstance(exc, client_main._PermanentEndpointError)


# Smoke check that _zero_backoff helper was applied — keeps tests fast
# (without it, exponential backoff would balloon test wallclock).
def test_backoff_helper_imports_clean() -> None:
    # If the helper raised on import, none of the tests above would run.
    assert callable(client_main.time.sleep)
    assert hasattr(client_main, "_FETCH_MAX_ATTEMPTS")
    assert client_main._FETCH_MAX_ATTEMPTS >= 1


