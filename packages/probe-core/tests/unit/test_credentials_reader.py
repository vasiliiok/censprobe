"""
Tests for credentials_reader.parse_protocols_yaml.

Pin the fail-loud contract: a protocol section that is PRESENT in the
YAML must carry every operational field (port, keys, method, awg
obfuscation params, etc.). A section absent from the YAML is fine —
the dataclass keeps its zero defaults and the client uses
``_protocols_enabled`` to skip the corresponding probe.
"""

from __future__ import annotations

import pytest
import yaml
from censprobe_core.credentials_reader import parse_protocols_yaml


def _full_yaml(extra: dict[str, object] | None = None) -> str:
    """Build a complete, parseable credentials YAML body for a single
    protocol so individual fields can be deleted or corrupted in tests."""
    body: dict[str, object] = {
        "_protocols_enabled": ["shadowsocks"],
        "shadowsocks": {
            "port": 8388,
            "method": "2022-blake3-aes-256-gcm",
            "password_b64": "AAAA",
        },
    }
    if extra:
        body.update(extra)
    return yaml.safe_dump(body)


class TestProtocolsEnabledRequired:
    def test_missing_protocols_enabled_raises(self) -> None:
        body = yaml.safe_dump({"shadowsocks": {"port": 8388, "method": "x", "password_b64": "y"}})
        with pytest.raises(ValueError, match="_protocols_enabled"):
            parse_protocols_yaml(body)

    def test_null_protocols_enabled_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": None,
                "shadowsocks": {"port": 8388, "method": "x", "password_b64": "y"},
            }
        )
        with pytest.raises(ValueError, match="_protocols_enabled"):
            parse_protocols_yaml(body)

    def test_non_list_protocols_enabled_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": "wireguard",
                "wireguard": {},
            }
        )
        with pytest.raises(ValueError, match="_protocols_enabled"):
            parse_protocols_yaml(body)

    def test_non_string_entries_in_protocols_enabled_raise(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks", 42],
                "shadowsocks": {"port": 8388, "method": "x", "password_b64": "y"},
            }
        )
        with pytest.raises(ValueError, match="_protocols_enabled"):
            parse_protocols_yaml(body)

    def test_empty_list_is_accepted(self) -> None:
        # Empty list = listener brought up zero protocols. Edge case
        # but valid: no sections to parse, no fields to require.
        body = yaml.safe_dump({"_protocols_enabled": []})
        creds = parse_protocols_yaml(body)
        assert creds._protocols_enabled == []


class TestSectionFieldsRequired:
    def test_missing_port_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks"],
                "shadowsocks": {"method": "x", "password_b64": "y"},
            }
        )
        with pytest.raises(ValueError, match="shadowsocks.port"):
            parse_protocols_yaml(body)

    def test_missing_method_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks"],
                "shadowsocks": {"port": 8388, "password_b64": "y"},
            }
        )
        with pytest.raises(ValueError, match="shadowsocks.method"):
            parse_protocols_yaml(body)

    def test_missing_password_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks"],
                "shadowsocks": {"port": 8388, "method": "x"},
            }
        )
        with pytest.raises(ValueError, match="shadowsocks.password_b64"):
            parse_protocols_yaml(body)

    def test_invalid_port_range_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks"],
                "shadowsocks": {"port": 70000, "method": "x", "password_b64": "y"},
            }
        )
        with pytest.raises(ValueError, match="invalid shadowsocks.port"):
            parse_protocols_yaml(body)

    def test_amneziawg_missing_obfuscation_field_raises(self) -> None:
        # AWG h1..h4 / s1..s2 / jc/jmin/jmax are all required.
        # If the listener emits an old schema without h4, parsing
        # fails loud rather than handshaking with a stale magic value.
        awg = {
            "port": 51821,
            "server_public_key": "x",
            "client_private_key": "x",
            "client_public_key": "x",
            "preshared_key": "x",
            "jc": 4,
            "jmin": 40,
            "jmax": 70,
            "s1": 100,
            "s2": 200,
            "h1": 1234,
            "h2": 2345,
            "h3": 3456,
            # h4 deliberately missing
        }
        body = yaml.safe_dump({"_protocols_enabled": ["amneziawg"], "amneziawg": awg})
        with pytest.raises(ValueError, match="amneziawg.h4"):
            parse_protocols_yaml(body)

    def test_vless_missing_server_name_raises(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["vless_reality"],
                "vless_reality": {
                    "port": 8444,
                    "uuid": "00000000-0000-0000-0000-000000000001",
                    "public_key": "PBK",
                    "short_id": "abcd1234",
                    # server_name deliberately missing
                },
            }
        )
        with pytest.raises(ValueError, match="vless_reality.server_name"):
            parse_protocols_yaml(body)


class TestAbsentSectionIsAllowed:
    def test_absent_section_keeps_dataclass_default(self) -> None:
        # _protocols_enabled lists wireguard, but the operator may have
        # omitted other sections — the parser does not require them.
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks"],
                "shadowsocks": {"port": 8388, "method": "x", "password_b64": "y"},
            }
        )
        creds = parse_protocols_yaml(body)
        # ss got populated.
        assert creds.ss_port == 8388
        assert creds.ss_method == "x"
        # wireguard section absent → fields stay at zero/empty.
        assert creds.wg_port == 0
        assert creds.wg_server_public == ""

    def test_section_must_be_mapping(self) -> None:
        body = yaml.safe_dump(
            {
                "_protocols_enabled": ["shadowsocks"],
                "shadowsocks": ["not", "a", "mapping"],
            }
        )
        with pytest.raises(ValueError, match="must be a mapping"):
            parse_protocols_yaml(body)


class TestTopLevelShape:
    def test_non_mapping_top_level_raises(self) -> None:
        with pytest.raises(ValueError, match="top-level mapping"):
            parse_protocols_yaml("- a\n- b\n")
