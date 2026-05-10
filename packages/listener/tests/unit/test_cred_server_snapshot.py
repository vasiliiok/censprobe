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
from unittest.mock import MagicMock

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


def _invoke(handler_cls: type, *, path: str, headers: dict[str, str]) -> tuple[int, bytes]:
    """Drive a handler instance through a single fake GET.

    Returns ``(status_code, body)`` parsed from the wfile sink. Each
    test gets its own handler instance because BaseHTTPRequestHandler
    is built around per-request state.
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
        cs = _build_cred_server()
        cs.attach_responders({})
        h = _build_handler_class(cs)
        code, _ = _invoke(h, path="/snapshot", headers={})
        assert code == 401

    def test_wrong_token_returns_403(self) -> None:
        cs = _build_cred_server()
        cs.attach_responders({})
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert code == 403

    def test_correct_token_returns_200(self) -> None:
        cs = _build_cred_server()
        cs.attach_responders({})
        h = _build_handler_class(cs)
        code, body = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 200
        # No responders attached → empty JSON object.
        assert json.loads(body) == {}


class TestSnapshotLifecycle:
    def test_before_attach_returns_503(self) -> None:
        cs = _build_cred_server()
        # Note: never call attach_responders.
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 503

    def test_after_detach_returns_503(self) -> None:
        cs = _build_cred_server()
        cs.attach_responders({})
        cs.detach_responders()
        h = _build_handler_class(cs)
        code, _ = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 503

    def test_multi_serve_allowed(self) -> None:
        # Unlike /creds the snapshot endpoint must accept repeated polls
        # so the client can fetch once after probes AND an operator
        # can poll mid-session for diagnostics.
        cs = _build_cred_server()
        cs.attach_responders({})
        h = _build_handler_class(cs)
        for _ in range(3):
            code, _ = _invoke(
                h,
                path="/snapshot",
                headers={"Authorization": f"Bearer {cs.token}"},
            )
            assert code == 200


class TestSnapshotSerialisation:
    def test_responder_snapshot_is_serialised(self) -> None:
        cs = _build_cred_server()
        fake_responder = MagicMock()
        fake_responder.live_snapshot.return_value = LiveSnapshot(
            handshake_count=2,
            data_transfer_ok=True,
            data_packets=5,
            bytes_received=1024,
        )
        cs.attach_responders({"openvpn": fake_responder})
        h = _build_handler_class(cs)
        code, body = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 200
        payload = json.loads(body)
        assert "openvpn" in payload
        assert payload["openvpn"]["handshake_count"] == 2
        assert payload["openvpn"]["data_transfer_ok"] is True
        assert payload["openvpn"]["data_packets"] == 5
        assert payload["openvpn"]["bytes_received"] == 1024

    def test_responder_exception_yields_per_protocol_error(self) -> None:
        # If a single responder's live_snapshot raises, the endpoint
        # surfaces the per-protocol error in the JSON instead of 500'ing
        # the whole snapshot — operators want partial visibility.
        cs = _build_cred_server()
        ok_responder = MagicMock()
        ok_responder.live_snapshot.return_value = LiveSnapshot(handshake_count=1)
        bad_responder = MagicMock()
        bad_responder.live_snapshot.side_effect = RuntimeError("counter unavailable")

        cs.attach_responders({"openvpn": ok_responder, "wireguard": bad_responder})
        h = _build_handler_class(cs)
        code, body = _invoke(
            h,
            path="/snapshot",
            headers={"Authorization": f"Bearer {cs.token}"},
        )
        assert code == 200
        payload = json.loads(body)
        assert payload["openvpn"]["handshake_count"] == 1
        assert "error" in payload["wireguard"]
        assert "RuntimeError" in payload["wireguard"]["error"]


class TestUnknownPathStillReturns404:
    def test_404_on_unrelated_path(self) -> None:
        cs = _build_cred_server()
        h = _build_handler_class(cs)
        code, _ = _invoke(h, path="/something-else", headers={})
        assert code == 404
