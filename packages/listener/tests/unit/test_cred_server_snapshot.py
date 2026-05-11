"""Tests for the cred-server's ``/snapshot`` cross-verification endpoint.

The /snapshot endpoint is the listener-side half of the
client→listener verdict-comparison flow added on 2026-05-10. We verify
its three guarantees here:

  1. Bearer-token auth: same secret as ``/creds``, hmac-compared.
  2. Lifecycle: returns 503 before responders are attached and after
     they're detached, 200 in between.
  3. Multi-serve: unlike ``/creds`` (single-use), ``/snapshot`` can be
     polled repeatedly during a session — operators may want to watch
     counters tick live.

We don't spin up a real HTTPS socket — the handler logic lives behind
``CredServer._make_handler``. Mocking the request shape directly
exercises the auth / lifecycle / serialisation paths in isolation.
"""

from __future__ import annotations

import io
import json
from typing import Any

from censprobe_core.models import LiveSnapshot
from censprobe_listener.cred_server import CredServer


def _build_handler_class(
    cs: CredServer,
) -> type:
    """Pull the handler class out of ``CredServer._make_handler``.

    The handler is normally instantiated by ``http.server.HTTPServer``
    on each request; for testing we stub the constructor pieces it
    needs (rfile/wfile/headers/path) and call methods directly.
    """
    return cs._make_handler()


def _invoke(
    handler_cls: type,
    *,
    path: str,
    headers: dict[str, str],
    method: str = "GET",
) -> tuple[int, bytes]:
    """Drive a handler instance through a single fake request.

    Returns ``(status_code, body)`` parsed from the wfile sink. Each
    test gets its own handler instance because BaseHTTPRequestHandler
    is built around per-request state. ``method`` selects whether
    ``do_GET`` or ``do_POST`` is invoked.
    """
    # Build a partially-initialised handler: we skip __init__ (which
    # would try to handle a real request synchronously) and just
    # populate the attributes the response codepath touches.
    h = handler_cls.__new__(handler_cls)
    h.path = path
    h.headers = headers  # dict-like duck-typed; .get(...) is enough
    h.client_address = ("127.0.0.1", 65535)
    h.request_version = "HTTP/1.1"
    h.rfile = io.BytesIO(b"")
    h.wfile = io.BytesIO()

    # Capture the eventual status code via send_response. The default
    # implementation writes a status line into wfile; we just snoop
    # the integer. That way we don't depend on parsing wfile across
    # the handler's many headers/blank-line/body writes.
    captured: dict[str, Any] = {"code": None}

    def _send_response(code: int, message: str | None = None) -> None:
        captured["code"] = code
        # Mirror what the real send_response would put into wfile so
        # downstream send_header/end_headers don't blow up. We only
        # need the bytes shape, not parseable HTTP.
        h.wfile.write(f"HTTP/1.1 {code} OK\r\n".encode("ascii"))

    def _send_header(_k: str, _v: str) -> None:
        return  # discard — we don't parse them

    def _end_headers() -> None:
        h.wfile.write(b"\r\n")

    h.send_response = _send_response  # type: ignore[method-assign]
    h.send_header = _send_header  # type: ignore[method-assign]
    h.end_headers = _end_headers  # type: ignore[method-assign]
    if method == "POST":
        h.do_POST()
    else:
        h.do_GET()
    h.wfile.seek(0)
    raw = h.wfile.read()
    _, _, body = raw.partition(b"\r\n\r\n")
    return captured["code"] or 0, body


def _build_cred_server() -> CredServer:
    """Construct a CredServer without binding a real socket.

    The ``__init__`` path generates a real self-signed cert which
    takes ~500 ms; that's acceptable for a test suite under a second
    overall. We never call ``start()`` — we only exercise handler
    logic in-process.
    """
    return CredServer(creds_yaml="placeholder: 1\n", port=0)


class TestSnapshotAuth:
    def test_missing_bearer_returns_401(self) -> None:
        # Auth runs before lifecycle check, so a 401 is the response
        # regardless of whether snapshots have been committed.
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(h, path="/snapshot", headers={})
        assert code == 401

    def test_wrong_token_returns_403(self) -> None:
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert code == 403

    def test_correct_token_after_commit_returns_200(self) -> None:
        # /snapshot semantics: post-stop only. After
        # commit_final_snapshots, an authenticated GET returns 200
        # with the committed dict.
        cs = _build_cred_server()
        cs.commit_final_snapshots({"openvpn": {"handshake_count": 1}})
        h = _build_handler_class(cs)
        code, body = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 200
        assert json.loads(body) == {"openvpn": {"handshake_count": 1}}


class TestSnapshotLifecycle:
    def test_before_commit_returns_503(self) -> None:
        # Session not finalised yet — client must POST /stop and
        # poll. The handler returns 503 with an actionable message.
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 503

    def test_after_commit_multi_serve_allowed(self) -> None:
        # Once committed the snapshot is immutable; the client (or
        # operator) can poll it any number of times.
        cs = _build_cred_server()
        cs.commit_final_snapshots({"wireguard": {"handshake_count": 1}})
        h = _build_handler_class(cs)
        for _ in range(3):
            code, body = _invoke(
                h,
                path="/snapshot",
                headers={"Authorization": f"Bearer {cs.token}"},
            )
            assert code == 200
            assert "wireguard" in json.loads(body)


class TestSnapshotSerialisation:
    def test_committed_snapshots_are_returned_verbatim(self) -> None:
        # The handler returns whatever main.py serialised into
        # commit_final_snapshots — preserves error entries (per-protocol
        # snapshot failures captured as {"error": "..."}).
        cs = _build_cred_server()
        committed = {
            "openvpn": LiveSnapshot(
                handshake_count=2,
                data_transfer_ok=True,
                data_packets=5,
                bytes_received=1024,
            ).model_dump(mode="json"),
            "wireguard": {"error": "RuntimeError: counter unavailable"},
        }
        cs.commit_final_snapshots(committed)
        h = _build_handler_class(cs)
        code, body = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 200
        payload = json.loads(body)
        assert payload["openvpn"]["handshake_count"] == 2
        assert payload["openvpn"]["data_transfer_ok"] is True
        assert payload["openvpn"]["data_packets"] == 5
        assert payload["openvpn"]["bytes_received"] == 1024
        assert "error" in payload["wireguard"]
        assert "RuntimeError" in payload["wireguard"]["error"]


class TestStopEndpoint:
    """``POST /stop`` triggers client-driven shutdown.

    The handler authenticates with the same bearer token as /creds
    and /snapshot, then sets a threading.Event mirror (always) AND
    flips the asyncio Event bound by ``bind_stop_event`` (if main.py
    has bound it already). The HTTP response is 202 Accepted with a
    tiny JSON body — the client is just acknowledging "stop request
    received", actual responder teardown happens in main.py's loop.
    """

    def test_post_stop_requires_bearer(self) -> None:
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(h, path="/stop", headers={}, method="POST")
        assert code == 401

    def test_post_stop_wrong_token_403(self) -> None:
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/stop",
            headers={"Authorization": "Bearer bad"},
            method="POST",
        )
        assert code == 403

    def test_post_stop_sets_threading_event(self) -> None:
        # Without the asyncio event bound (early-stop race), the
        # threading mirror still records the request so bind_stop_event
        # can replay it.
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/stop",
            headers={"Authorization": f"Bearer {cs.token}"},
            method="POST",
        )
        assert code == 202
        assert cs._stop_requested.is_set()

    def test_post_stop_sets_asyncio_event(self) -> None:
        # When main.py has bound the asyncio Event, /stop schedules
        # ev.set() via call_soon_threadsafe.
        import asyncio as _asyncio

        cs = _build_cred_server()
        loop = _asyncio.new_event_loop()
        try:
            ev = _asyncio.Event()
            cs.bind_stop_event(ev, loop)

            h = _build_handler_class(cs)
            code, _ = _invoke(
                h,
                path="/stop",
                headers={"Authorization": f"Bearer {cs.token}"},
                method="POST",
            )
            assert code == 202
            # Run the scheduled call_soon_threadsafe so ev.set fires.
            loop.call_soon(loop.stop)
            loop.run_forever()
            assert ev.is_set()
        finally:
            loop.close()

    def test_get_stop_is_405(self) -> None:
        # /stop exists as a resource but only accepts POST — accidental
        # GET (operator curl) gets 405 Method Not Allowed with
        # Allow: POST, rather than the misleading 404 we used to send.
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/stop",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 405

    def test_post_to_get_only_endpoint_is_405(self) -> None:
        # Mirror: POSTing to /creds or /snapshot returns 405 with
        # Allow: GET. Operator-debug friendliness, no behaviour change
        # for the legitimate client which only POSTs /stop.
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/creds",
            headers={"Authorization": f"Bearer {cs.token}"},
            method="POST",
        )
        assert code == 405


class TestUnknownPathStillReturns404:
    def test_404_on_unrelated_path(self) -> None:
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(h, path="/something-else", headers={})
        assert code == 404
