"""
Tests for subcategories.derive — the contract between probe test names and
Grafana SQL filters. Verifies all four resolution levels (override → suffix
→ substring → prefix), plus ordering rules and the unknown fallback.
"""

from __future__ import annotations

import pytest
from censprobe_core.subcategories import derive


class TestNameOverride:
    @pytest.mark.parametrize(
        ("test_name", "expected"),
        [
            ("telegram_health_score", "telegram_health"),
            ("telegram_ipv6_skipped", "telegram_meta"),
            ("throttling_youtube_sni_probe_method_b", "throttling"),
            ("google_quic_dns", "cloudflare_quic"),
            ("quad9_quic_dns", "cloudflare_quic"),
        ],
    )
    def test_explicit_overrides(self, test_name: str, expected: str) -> None:
        # Highest priority — name overrides win even when a prefix would
        # otherwise match (google_/quad9_ have no prefix rules but the
        # principle holds for telegram_*).
        assert derive(test_name) == expected


class TestSuffixRules:
    @pytest.mark.parametrize(
        ("test_name", "expected"),
        [
            ("tls_meduza_io_sni_blocked", "tls_sni_blocked"),
            ("tls_youtube_com_sni_neutral", "tls_sni_neutral"),
            ("tls_some_domain_ech", "tls_ech"),
            ("tcp_no_ip", "tls_meta"),  # _no_ip suffix wins over tcp prefix
        ],
    )
    def test_suffix_wins_over_prefix(self, test_name: str, expected: str) -> None:
        # Suffix rules are checked before prefix rules — splits one family
        # into named sub-families by role suffix.
        assert derive(test_name) == expected


class TestSubstringRules:
    @pytest.mark.parametrize(
        ("test_name", "expected"),
        [
            ("cloudflare_warp_masque_udp_4443", "cloudflare_warp_udp_masque"),
            ("cloudflare_warp_wg_udp_2408", "cloudflare_warp_udp_wg"),
        ],
    )
    def test_warp_udp_substring_split(self, test_name: str, expected: str) -> None:
        # Substring rules sit between suffix and prefix — they let WARP UDP
        # variants split out of the broader WARP family without enumerating
        # every concrete name.
        assert derive(test_name) == expected


class TestPrefixRules:
    @pytest.mark.parametrize(
        ("test_name", "expected"),
        [
            ("doh_access_cloudflare", "doh"),
            ("dot_access_quad9", "dot"),
            ("dns_meduza_io_system", "dns"),
            ("cloudflare_quic_1_1_1_1", "cloudflare_quic"),
            ("cloudflare_warp_tcp_2408", "cloudflare_warp"),
            ("cloudflare_http_anycast", "cloudflare_http"),
            ("cloudflare_anycast_ping", "cloudflare"),
            ("telegram_dc1_443", "telegram_dc"),
            ("telegram_health", "telegram_health"),
            ("telegram_web_t_me", "telegram_web"),
            ("telegram_aux_api", "telegram_aux"),
            ("telegram_cdn_t_me", "telegram_cdn"),
            ("telegram_other", "telegram"),
            ("throttling_a_b_test", "throttling"),
            ("middlebox_invalid_uri", "middlebox"),
            ("tls_other_probe", "tls"),
            ("tcp_meduza_io_443", "tcp"),
            ("http_meduza_io", "http"),
        ],
    )
    def test_prefix_match(self, test_name: str, expected: str) -> None:
        assert derive(test_name) == expected

    def test_prefix_order_quic_before_generic(self) -> None:
        # cloudflare_quic_ MUST come before cloudflare_ — otherwise QUIC
        # tests would land in the generic cloudflare bucket.
        assert derive("cloudflare_quic_h3") == "cloudflare_quic"

    def test_doh_dot_before_dns(self) -> None:
        # doh_access_ / dot_access_ must come before dns_ — otherwise
        # encrypted DNS tests would all collapse into the dns bucket.
        assert derive("doh_access_google") == "doh"
        assert derive("dot_access_google") == "dot"


class TestFallback:
    def test_unknown_name_with_category(self) -> None:
        # Unknown name + category → fallback to category.
        assert derive("totally_new_probe_xyz", category="custom") == "custom"

    def test_unknown_name_no_category(self) -> None:
        # No category supplied → "unknown" — surfaces in dashboards as a
        # hint that a probe family slipped through the contract.
        assert derive("totally_new_probe_xyz") == "unknown"

    def test_unknown_name_empty_category(self) -> None:
        # Empty string category is falsy — same as None.
        assert derive("totally_new_probe_xyz", category="") == "unknown"


class TestKnownStableSubcategories:
    """Lock in the set of subcategories the dashboards filter on.

    If a contributor renames or removes a subcategory, this regression
    test fires before the dashboard goes silent. Update this set ONLY
    when intentionally changing the contract — and at the same time
    update the Grafana panel SQL.
    """

    KNOWN: frozenset[str] = frozenset(
        {
            "doh",
            "dot",
            "dns",
            "tls",
            "tls_sni_blocked",
            "tls_sni_neutral",
            "tls_ech",
            "tls_meta",
            "tcp",
            "http",
            "throttling",
            "middlebox",
            "telegram",
            "telegram_dc",
            "telegram_web",
            "telegram_aux",
            "telegram_cdn",
            "telegram_health",
            "telegram_meta",
            "cloudflare",
            "cloudflare_quic",
            "cloudflare_warp",
            "cloudflare_http",
            "cloudflare_warp_udp_masque",
            "cloudflare_warp_udp_wg",
        }
    )

    def test_sample_names_all_resolve_to_known(self) -> None:
        # Sample one name per family — derive() output must stay inside
        # the agreed subcategory set.
        samples = [
            "dns_meduza_io_system",
            "doh_access_google",
            "dot_access_quad9",
            "tls_meduza_io_sni_blocked",
            "tls_meduza_io_sni_neutral",
            "tls_some_ech",
            "tcp_meduza_io_443",
            "http_meduza_io",
            "throttling_method_b",
            "middlebox_invalid_uri",
            "telegram_dc1_443",
            "telegram_web_t_me",
            "telegram_aux_api",
            "telegram_cdn_t_me",
            "telegram_health_score",
            "telegram_ipv6_skipped",
            "cloudflare_quic_h3",
            "cloudflare_warp_tcp_2408",
            "cloudflare_warp_masque_udp_4443",
            "cloudflare_warp_wg_udp_2408",
            "cloudflare_http_anycast",
            "cloudflare_anycast_ping",
            "google_quic_dns",
            "quad9_quic_dns",
        ]
        for name in samples:
            sub = derive(name)
            assert sub in self.KNOWN, f"{name!r} → {sub!r} not in known set"
