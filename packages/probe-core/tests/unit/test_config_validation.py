"""
Tests for CensprobeConfig + ProtocolsConfig validation.

The most important check is :meth:`ProtocolsConfig._check_ports_cover_enabled`
— it catches half-edited yaml (added to ``enabled`` but forgot the port,
or vice versa) at startup instead of at runtime when a responder fails
to bind.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from censprobe_core.config import ProtocolsConfig
from pydantic import ValidationError


class TestProtocolsConfigCrossCheck:
    def test_valid_minimal(self) -> None:
        # Smoke: a correctly-set protocols block validates.
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["openvpn"],
                "priority": ["openvpn"],
                "ports": {"openvpn": 1194},
                "sni": {},
            }
        )
        assert cfg.enabled == ["openvpn"]

    def test_enabled_without_port_rejected(self) -> None:
        # Adding a protocol to enabled without a corresponding port entry
        # is the most likely operator mistake — it must fail at startup.
        with pytest.raises(ValidationError, match="missing entries"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn", "wireguard"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194},
                    "sni": {},
                }
            )

    def test_orphan_port_rejected(self) -> None:
        # A port for a protocol unknown to the registry is dead config —
        # almost always a typo on the protocol name. Since 2026-05-14
        # the validator does a late-import registry cross-check, so the
        # rejection message names "unknown to the registry" rather than
        # the older "not listed in enabled/priority" wording.
        with pytest.raises(ValidationError, match="unknown to the registry"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194, "openvpn_typo": 1195},
                    "sni": {},
                }
            )

    def test_unknown_enabled_rejected(self) -> None:
        # 2026-05-14 audit: protocols.enabled used to silently drop names
        # that weren't in the registry (typo'd ``vless-reality`` with a
        # dash). Now the validator cross-checks against
        # protocol_registry.known_names() at startup.
        with pytest.raises(ValidationError, match="enabled references protocols unknown"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn", "vless-reality"],  # typo: dash
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194, "vless-reality": 8444},
                    "sni": {},
                }
            )

    def test_orphan_port_in_priority_only_accepted(self) -> None:
        # Priority can name protocols that aren't enabled — operator
        # might want them in the suggestion order if they re-enable
        # later. ports-for-priority-only is therefore valid.
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["openvpn"],
                "priority": ["openvpn", "wireguard"],
                "ports": {"openvpn": 1194, "wireguard": 51820},
                "sni": {},
            }
        )
        assert cfg.ports["wireguard"] == 51820

    @pytest.mark.parametrize("port", [0, -1, 65536, 100000])
    def test_invalid_port_range_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError, match="invalid port numbers"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": port},
                    "sni": {},
                }
            )

    @pytest.mark.parametrize("port", [1, 443, 1194, 65535])
    def test_valid_port_range_accepted(self, port: int) -> None:
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["openvpn"],
                "priority": ["openvpn"],
                "ports": {"openvpn": port},
                "sni": {},
            }
        )
        assert cfg.ports["openvpn"] == port


class TestProtocolsConfigSniValidator:
    """SNI map: required for enabled SNI-using protocols, rejected for
    non-SNI-using protocols.
    """

    def test_enabled_sni_using_protocol_without_sni_rejected(self) -> None:
        # vless_reality is in enabled but no sni entry → fatal.
        with pytest.raises(ValidationError, match="protocols.sni missing entries"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["vless_reality"],
                    "priority": ["vless_reality"],
                    "ports": {"vless_reality": 8444},
                    "sni": {},
                }
            )

    def test_enabled_mtproto_pair_requires_both_sni_entries(self) -> None:
        # Enable both mtproto siblings, only configure SNI for one →
        # the other must fail loudly. Catches the "edited primary,
        # forgot the alt" half-edit which is the easiest mistake to
        # make on this knob.
        with pytest.raises(ValidationError, match="mtproto_proxy_alt"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["mtproto_proxy", "mtproto_proxy_alt"],
                    "priority": ["mtproto_proxy"],
                    "ports": {"mtproto_proxy": 443, "mtproto_proxy_alt": 8888},
                    "sni": {"mtproto_proxy": "google.com"},
                }
            )

    def test_sni_entry_for_non_sni_using_protocol_rejected(self) -> None:
        # OpenVPN doesn't carry an SNI; an entry here is operator
        # confusion (e.g. accidentally generalising the matrix to all
        # protocols). Rejected so the error surface stays small.
        with pytest.raises(ValidationError, match="non-SNI-using protocols"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194},
                    "sni": {"openvpn": "example.com"},
                }
            )

    def test_empty_sni_value_rejected(self) -> None:
        # An empty string sneaking through would make mtg's ee-secret
        # parser barf with an opaque error at responder start. Reject
        # at config-load instead so the message points at the YAML.
        with pytest.raises(ValidationError, match="empty or non-string"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["mtproto_proxy"],
                    "priority": ["mtproto_proxy"],
                    "ports": {"mtproto_proxy": 443},
                    "sni": {"mtproto_proxy": ""},
                }
            )

    def test_sni_for_disabled_sni_using_protocol_accepted(self) -> None:
        # Operator might keep SNI configured for a sibling currently
        # disabled (planning to re-enable). That's not dead config —
        # tolerated as long as the name is a real SNI-using protocol.
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["openvpn"],
                "priority": ["openvpn"],
                "ports": {"openvpn": 1194},
                "sni": {"vless_reality": "kept-for-later.example"},
            }
        )
        assert cfg.sni["vless_reality"] == "kept-for-later.example"

    def test_three_sni_using_protocols_full_set_accepted(self) -> None:
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["vless_reality", "mtproto_proxy", "mtproto_proxy_alt"],
                "priority": ["vless_reality", "mtproto_proxy", "mtproto_proxy_alt"],
                "ports": {
                    "vless_reality": 8444,
                    "mtproto_proxy": 443,
                    "mtproto_proxy_alt": 8888,
                },
                "sni": {
                    "vless_reality": "apimaps.yandex.ru",
                    "mtproto_proxy": "google.com",
                    "mtproto_proxy_alt": "microsoft.com",
                },
            }
        )
        # Distinct SNIs propagate cleanly — this is the operator-facing
        # A/B knob the entire feature exists for.
        assert cfg.sni["mtproto_proxy"] != cfg.sni["mtproto_proxy_alt"]

    def test_mtproto_orig_enabled_without_sni_entry_accepted(self) -> None:
        # mtproto_orig speaks legacy obfuscated2 — no SNI carrier.
        # Validator must accept enabled mtproto_orig without an entry
        # in protocols.sni and reject any entry with that key.
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["mtproto_orig"],
                "priority": ["mtproto_orig"],
                "ports": {"mtproto_orig": 2080},
                "sni": {},
            }
        )
        assert cfg.enabled == ["mtproto_orig"]
        assert "mtproto_orig" not in cfg.sni

    def test_sni_entry_for_mtproto_orig_rejected(self) -> None:
        # Putting an SNI string under mtproto_orig is a config typo.
        # Same fail-loud behaviour as openvpn/wg/awg/ss/hysteria2.
        with pytest.raises(ValidationError, match="non-SNI-using protocols"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["mtproto_orig"],
                    "priority": ["mtproto_orig"],
                    "ports": {"mtproto_orig": 2080},
                    "sni": {"mtproto_orig": "google.com"},
                }
            )


class TestProtocolsConfigExtraForbidden:
    def test_unknown_top_level_field_rejected(self) -> None:
        # extra="forbid" — typo in a field name fails fast.
        with pytest.raises(ValidationError):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194},
                    "sni": {},
                    "enabled_typo": ["x"],
                }
            )


class TestCensprobeConfigStructure:
    def test_minimal_valid_config_loads(self, make_config: Callable[..., Any]) -> None:
        # The make_config factory itself proves the default shape is
        # acceptable — without it every other test would be blocked.
        cfg = make_config()
        assert cfg.scoring.entry.protocol == 0.6
        assert cfg.vantage.censoring_countries == ["RU", "BY"]

    def test_missing_required_section_rejected(self, make_config: Callable[..., Any]) -> None:
        # Drop scoring entirely — config must reject (no fallback).
        from censprobe_core.config import CensprobeConfig

        cfg_dict = make_config().model_dump()
        del cfg_dict["scoring"]
        with pytest.raises(ValidationError):
            CensprobeConfig.model_validate(cfg_dict)

    def test_unknown_top_level_section_rejected(self, make_config: Callable[..., Any]) -> None:
        # 2026-05-14 audit: CensprobeConfig switched from extra="ignore"
        # to extra="forbid" so a typo'd top-level key (e.g. ``module:``
        # instead of ``modules:``) fails with a clear "extra fields not
        # permitted" rather than ignoring the typo and emitting a less
        # actionable "modules: field required" message.
        from censprobe_core.config import CensprobeConfig

        cfg_dict = make_config().model_dump()
        cfg_dict["future_section"] = {"x": 1}
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CensprobeConfig.model_validate(cfg_dict)
        # Sanity: the canonical dict (without the extra) still validates.
        cfg = CensprobeConfig.model_validate(make_config().model_dump())
        # Existing fields still work.
        assert cfg.scoring.entry.protocol == 0.6
