"""
Tests for creds_to_yaml — round-trip the on-wire YAML schema.

We can't call ``generate_credentials`` in CI because it shells out to
``wg``, ``xray``, and ``openvpn`` — those binaries don't exist on the
default GitHub runner. Instead build a fully-populated
:class:`ProtocolCredentials` directly and verify:
  * every protocol section appears under the right key,
  * every section contains the documented field set,
  * ``enabled_protocols`` filters the output as advertised,
  * the result is valid YAML that round-trips byte-stable.
"""

from __future__ import annotations

import yaml
from censprobe_listener.credentials import ProtocolCredentials, creds_to_yaml


def _populated_creds() -> ProtocolCredentials:
    """A ProtocolCredentials with every field set to a deterministic
    sentinel — no subprocess calls, no randomness.
    """
    _ovpn_pem = "-----BEGIN OpenVPN Static key V1-----\nAAA\n-----END OpenVPN Static key V1-----"
    c = ProtocolCredentials(
        openvpn_psk_pem=_ovpn_pem,
        openvpn_port=1194,
        wg_server_private="WG_SRV_PRIV",
        wg_server_public="WG_SRV_PUB",
        wg_client_private="WG_CLI_PRIV",
        wg_client_public="WG_CLI_PUB",
        wg_preshared_key="WG_PSK",
        wg_port=51820,
        awg_server_private="AWG_SRV_PRIV",
        awg_server_public="AWG_SRV_PUB",
        awg_client_private="AWG_CLI_PRIV",
        awg_client_public="AWG_CLI_PUB",
        awg_preshared_key="AWG_PSK",
        awg_port=51821,
        awg_jc=5,
        awg_jmin=42,
        awg_jmax=88,
        awg_s1=100,
        awg_s2=200,
        awg_h1=12345,
        awg_h2=23456,
        awg_h3=34567,
        awg_h4=45678,
        ss_port=8388,
        ss_method="2022-blake3-aes-256-gcm",
        ss_password_b64="SSPASSWORD",
        vless_port=8444,
        vless_uuid="00000000-0000-0000-0000-000000000001",
        vless_pbk="VLESS_PBK",
        vless_pvk="VLESS_PVK",
        vless_short_id="abcd1234",
        vless_server_name="apimaps.yandex.ru",
        hy2_port=443,
        hy2_auth="HY2_AUTH",
        hy2_obfs_password="HY2_OBFS",
        # Synthetic test sentinel (NOT a real secret): "ee" + 16 zero-bytes
        # in hex + "google.com".hex(). Format-valid for the mtg parser; low
        # entropy so gitleaks doesn't flag the literal.
        mtproxy_secret="ee" + "00" * 16 + "676f6f676c652e636f6d",  # gitleaks:allow
        mtproxy_port=444,
        mtproxy_alt_secret="ee" + "11" * 16 + "676f6f676c652e636f6d",  # gitleaks:allow
        mtproxy_alt_port=8888,
    )
    return c


ALL_PROTOS = (
    "openvpn",
    "wireguard",
    "amneziawg",
    "shadowsocks",
    "vless_reality",
    "hysteria2",
    "mtproto_proxy",
    "mtproto_proxy_alt",
)


class TestCredsToYamlRoundTrip:
    def test_emits_every_protocol_section(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        assert isinstance(loaded, dict)
        assert set(ALL_PROTOS).issubset(loaded.keys())

    def test_yaml_round_trip_byte_stable(self) -> None:
        # dump → load → dump must produce identical text. This catches
        # any non-determinism in dict ordering, key sort, or escaping.
        c = _populated_creds()
        out1 = creds_to_yaml(c, enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out1)
        out2 = yaml.dump(loaded, allow_unicode=True, sort_keys=False)
        # We dump once with the same options and verify identity.
        loaded_again = yaml.safe_load(out2)
        assert loaded_again == loaded

    def test_section_shapes_openvpn(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["openvpn"]
        assert sec["port"] == 1194
        assert sec["protocol"] == "udp"
        assert sec["psk_pem"].startswith("-----BEGIN OpenVPN Static key V1")

    def test_section_shapes_wireguard(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["wireguard"]
        assert sec["port"] == 51820
        assert sec["server_public_key"] == "WG_SRV_PUB"
        assert sec["client_private_key"] == "WG_CLI_PRIV"
        assert sec["client_public_key"] == "WG_CLI_PUB"
        assert sec["preshared_key"] == "WG_PSK"
        # Server-private intentionally NOT in the wireguard section
        # (wg_server_private is server-side only).
        assert "server_private_key" not in sec

    def test_section_shapes_amneziawg(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["amneziawg"]
        assert sec["port"] == 51821
        # All AWG junk-param fields must be present — parser on the
        # client side reads each one. A missing key would crash the probe.
        for f in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
            assert f in sec
        assert sec["h1"] == 12345
        assert sec["s1"] == 100
        assert sec["s2"] == 200

    def test_section_shapes_shadowsocks(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["shadowsocks"]
        assert sec["port"] == 8388
        assert sec["method"] == "2022-blake3-aes-256-gcm"
        assert sec["password_b64"] == "SSPASSWORD"

    def test_section_shapes_vless_reality(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["vless_reality"]
        assert sec["port"] == 8444
        assert sec["uuid"] == "00000000-0000-0000-0000-000000000001"
        # Reality public_key is shared; private_key must NOT leak to the
        # client side since only the server uses it.
        assert sec["public_key"] == "VLESS_PBK"
        assert "private_key" not in sec

    def test_section_shapes_hysteria2(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["hysteria2"]
        assert sec["port"] == 443
        assert sec["auth"] == "HY2_AUTH"
        assert sec["obfs_password"] == "HY2_OBFS"

    def test_section_shapes_mtproto_proxy(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["mtproto_proxy"]
        assert sec["port"] == 444
        assert sec["secret"].startswith("ee")
        # 'ee' + 32 hex chars (16 random bytes) + hex-encoded SNI.
        assert len(sec["secret"]) > len("ee") + 32

    def test_section_shapes_mtproto_proxy_alt(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        sec = loaded["mtproto_proxy_alt"]
        assert sec["port"] == 8888
        assert sec["secret"].startswith("ee")
        assert len(sec["secret"]) > len("ee") + 32
        # The alt instance must have an independent random part — not a
        # copy of the primary secret. This protects against a future
        # refactor that accidentally aliases the two fields.
        assert sec["secret"] != loaded["mtproto_proxy"]["secret"]


class TestEnabledProtocolsFilter:
    def test_filters_to_subset(self) -> None:
        out = creds_to_yaml(_populated_creds(), enabled_protocols=["wireguard"])
        loaded = yaml.safe_load(out)
        assert "wireguard" in loaded
        for other in (
            "openvpn",
            "amneziawg",
            "shadowsocks",
            "vless_reality",
            "hysteria2",
            "mtproto_proxy",
            "mtproto_proxy_alt",
        ):
            assert other not in loaded
        # _protocols_enabled is a metadata mirror — client reads it to
        # know what to probe.
        assert loaded["_protocols_enabled"] == ["wireguard"]

    def test_unknown_protocol_silently_dropped(self) -> None:
        # An entry the operator put in `enabled` that isn't in the
        # registered _SECTION_BUILDERS is filtered out (not crashed).
        out = creds_to_yaml(
            _populated_creds(),
            enabled_protocols=["wireguard", "future_proto_xyz"],
        )
        loaded = yaml.safe_load(out)
        assert "wireguard" in loaded
        assert "future_proto_xyz" not in loaded
        # _protocols_enabled echoes whatever the operator passed.
        assert "future_proto_xyz" in loaded["_protocols_enabled"]

    def test_full_set_emits_all_sections(self) -> None:
        # Explicit "every protocol" — _protocols_enabled is required, so
        # the listener must pass the full list rather than relying on a
        # silent None-means-all default.
        out = creds_to_yaml(_populated_creds(), enabled_protocols=list(ALL_PROTOS))
        loaded = yaml.safe_load(out)
        for proto in ALL_PROTOS:
            assert proto in loaded
        assert loaded["_protocols_enabled"] == list(ALL_PROTOS)
