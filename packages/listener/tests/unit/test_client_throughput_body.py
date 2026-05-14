"""Unit tests for the /stop body parser ``_parse_client_throughput``.

The client POSTs a JSON body like::

    {"client_throughput": {"wireguard": 360.7, "shadowsocks": 523.4}}

with the per-protocol curl-through-tunnel throughput measurements. The
listener parses this in the http.server thread and **must not** raise:
a malformed body would leave the listener wedged after probes finish.

These tests pin the silent-drop semantics so future cred_server refactors
don't accidentally start raising.
"""

from __future__ import annotations

from censprobe_listener.cred_server import _parse_client_throughput


def test_well_formed_body_parses() -> None:
    body = b'{"client_throughput": {"wireguard": 360.7, "shadowsocks": 523.4}}'
    assert _parse_client_throughput(body) == {"wireguard": 360.7, "shadowsocks": 523.4}


def test_empty_body_returns_empty_dict() -> None:
    assert _parse_client_throughput(b"") == {}


def test_missing_key_returns_empty_dict() -> None:
    assert _parse_client_throughput(b'{"other": 1}') == {}


def test_malformed_json_returns_empty_dict() -> None:
    assert _parse_client_throughput(b"not json at all") == {}


def test_non_dict_top_level_returns_empty_dict() -> None:
    assert _parse_client_throughput(b"[1,2,3]") == {}


def test_nan_and_negative_values_filtered() -> None:
    body = (
        b'{"client_throughput": {"wireguard": 100.0, '
        b'"openvpn": -5.0, "shadowsocks": null, "hysteria2": 0.0}}'
    )
    # Only wireguard's positive finite value survives.
    assert _parse_client_throughput(body) == {"wireguard": 100.0}


def test_non_string_protocol_name_filtered() -> None:
    # JSON lets integer keys in objects only as strings, so we test
    # the case where a value is a list/dict (definitely not numeric).
    body = b'{"client_throughput": {"wireguard": [1,2,3], "openvpn": 50.0}}'
    assert _parse_client_throughput(body) == {"openvpn": 50.0}


def test_int_values_accepted_as_float() -> None:
    body = b'{"client_throughput": {"wireguard": 100}}'
    assert _parse_client_throughput(body) == {"wireguard": 100.0}


def test_unicode_decode_error_returns_empty_dict() -> None:
    # 0xff is invalid UTF-8 byte 1.
    assert _parse_client_throughput(b"\xff\xfe\xfd") == {}
