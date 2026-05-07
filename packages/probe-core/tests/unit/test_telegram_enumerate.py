"""Regression tests for ``_enumerate_dc_endpoints``.

Reproduces the silent-data-loss bug found in the May 2026 ya-a Yandex.Cloud
report: ``TelegramDC.ipv4`` is ``list[str]``, model_dump emits a list, and
the previous enumerator forwarded the list itself as if it were a single
``ip``. ``asyncio.open_connection([...], port)`` then raised TypeError,
``gather(return_exceptions=True)`` swallowed it at debug level, and every
report shipped with zero ``telegram_dc_*`` rows and a ~55-point underestimate
of telegram_health_score.

These tests would have flagged the regression before it shipped.
"""

from __future__ import annotations

from censprobe_core.modules.telegram import _enumerate_dc_endpoints


class TestEnumerateDcEndpoints:
    def test_list_ipv4_yields_one_tuple_per_ip_per_port(self) -> None:
        # The model coerces a yaml scalar to a one-element list. The output
        # must contain a STRING ``ip``, not a list — otherwise the downstream
        # asyncio.open_connection call raises TypeError.
        dcs = [
            {
                "id": 1,
                "ipv4": ["149.154.175.53"],
                "ipv6": ["2001:b28:f23d:f001::a"],
                "ports": [443, 80, 5222],
            }
        ]
        endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6=False)
        # 1 DC × 2 IP versions × 3 ports = 6 endpoints.
        assert len(endpoints) == 6
        # Every emitted ip MUST be a string — never a list/tuple.
        for _dc_id, _ip_ver, ip, _port in endpoints:
            assert isinstance(ip, str), (
                f"ip must be str for asyncio.open_connection — got {type(ip).__name__}"
            )

    def test_skip_ipv6_drops_v6_endpoints(self) -> None:
        dcs = [
            {
                "id": 1,
                "ipv4": ["149.154.175.53"],
                "ipv6": ["2001:b28:f23d:f001::a"],
                "ports": [443, 80, 5222],
            }
        ]
        endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6=True)
        # 3 v4 ports only.
        assert len(endpoints) == 3
        assert all(ip_ver == "v4" for _, ip_ver, _, _ in endpoints)

    def test_multi_ip_per_dc_fans_out(self) -> None:
        # A future telegram.yaml could put multiple v4 IPs in one DC entry.
        # Each one must produce its own (dc_id, ip_ver, ip, port) tuple.
        dcs = [
            {
                "id": 2,
                "ipv4": ["149.154.167.51", "149.154.167.52"],
                "ipv6": [],
                "ports": [443],
            }
        ]
        endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6=True)
        assert len(endpoints) == 2
        ips = sorted(ep[2] for ep in endpoints)
        assert ips == ["149.154.167.51", "149.154.167.52"]

    def test_scalar_ipv4_legacy_form_normalized(self) -> None:
        # Defensive path: if a legacy serialised form leaks a bare string
        # (model_dump of a hand-built dict), normalise to list rather than
        # iterate over its characters.
        dcs = [{"id": 5, "ipv4": "91.108.56.130", "ipv6": [], "ports": [443]}]
        endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6=True)
        assert len(endpoints) == 1
        assert endpoints[0] == (5, "v4", "91.108.56.130", 443)

    def test_empty_ip_list_skips_dc(self) -> None:
        dcs = [{"id": 6, "ipv4": [], "ipv6": [], "ports": [443]}]
        endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6=False)
        assert endpoints == []

    def test_full_targets_yaml_shape_yields_15_v4_endpoints(self) -> None:
        # End-to-end shape check matching targets/telegram.yaml: 5 DCs ×
        # 1 IPv4 × 3 ports = 15 v4 endpoints when v6 is skipped.
        dcs = [
            {"id": i, "ipv4": [f"149.154.175.{i}"], "ipv6": [], "ports": [443, 80, 5222]}
            for i in range(1, 6)
        ]
        endpoints = _enumerate_dc_endpoints(dcs, skip_ipv6=True)
        assert len(endpoints) == 15
