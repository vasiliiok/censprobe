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
                }
            )

    def test_orphan_port_rejected(self) -> None:
        # A port for a protocol nobody references is dead config — almost
        # always a typo on the protocol name.
        with pytest.raises(ValidationError, match="not listed in"):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194, "openvpn_typo": 1195},
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
                }
            )

    @pytest.mark.parametrize("port", [1, 443, 1194, 65535])
    def test_valid_port_range_accepted(self, port: int) -> None:
        cfg = ProtocolsConfig.model_validate(
            {
                "enabled": ["openvpn"],
                "priority": ["openvpn"],
                "ports": {"openvpn": port},
            }
        )
        assert cfg.ports["openvpn"] == port


class TestProtocolsConfigExtraForbidden:
    def test_unknown_top_level_field_rejected(self) -> None:
        # extra="forbid" — typo in a field name fails fast.
        with pytest.raises(ValidationError):
            ProtocolsConfig.model_validate(
                {
                    "enabled": ["openvpn"],
                    "priority": ["openvpn"],
                    "ports": {"openvpn": 1194},
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

    def test_unknown_top_level_section_ignored(self, make_config: Callable[..., Any]) -> None:
        # CensprobeConfig has extra="ignore" — older deployments must
        # not crash when newer yaml adds sections they don't know about.
        from censprobe_core.config import CensprobeConfig

        cfg_dict = make_config().model_dump()
        cfg_dict["future_section"] = {"x": 1}
        cfg = CensprobeConfig.model_validate(cfg_dict)
        # Existing fields still work.
        assert cfg.scoring.entry.protocol == 0.6
