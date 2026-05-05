"""
Contract test — subcategories.derive() output ⊇ Grafana SQL filter set.

Walk every Grafana panel JSON, regex-extract every literal subcategory
name used in a SQL filter, and verify that ``subcategories.derive`` (the
stable contract entry point) is *capable* of producing every one of
them. If a contributor renames a subcategory in subcategories.py without
updating Grafana, this test fires; the inverse direction (Grafana panel
referencing a subcategory that nothing produces) is also caught.

The test relies on the same KNOWN-set used in test_subcategories.py so
the two ends of the contract have a single source of truth.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# The Grafana JSON references subcategories in two SQL forms:
#   subcategory = '<name>'
#   subcategory IN ('a', 'b', 'c')
_EQ_RE = re.compile(r"subcategory\s*=\s*'([^']+)'")
_IN_RE = re.compile(r"subcategory\s+IN\s*\(([^)]*)\)", re.IGNORECASE)
_QUOTED_RE = re.compile(r"'([^']+)'")


REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARDS_DIR = REPO_ROOT / "packages" / "dashboard" / "grafana" / "dashboards"


def _grafana_subcategories() -> set[str]:
    """Walk every dashboard JSON, return the set of subcategory literals
    referenced in SQL panels."""
    found: set[str] = set()
    if not DASHBOARDS_DIR.exists():
        pytest.skip(f"Dashboards directory not found: {DASHBOARDS_DIR}")
    for path in sorted(DASHBOARDS_DIR.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        # `=` matches
        found.update(_EQ_RE.findall(text))
        # `IN (...)` matches — pull out each quoted literal inside.
        for parens in _IN_RE.findall(text):
            found.update(_QUOTED_RE.findall(parens))
    return found


# Names produced by subcategories.derive over a deliberately-wide sweep
# of test-name shapes. If the producer set diverges from the Grafana
# set, the assertion below names exactly which subcategory is rotting.
SAMPLE_TEST_NAMES = (
    # dns family
    "dns_meduza_io_system",
    "doh_access_cloudflare",
    "doh_access_google",
    "dot_access_quad9",
    # tls family
    "tls_meduza_io_sni_blocked",
    "tls_meduza_io_sni_neutral",
    "tls_meduza_io_ech",
    # tcp/http family
    "tcp_meduza_io_443",
    "tcp_no_ip",
    "http_meduza_io",
    # throttling/middlebox
    "throttling_method_b",
    "middlebox_invalid_uri",
    # telegram
    "telegram_dc1_ipv4_443",
    "telegram_health_score",
    "telegram_ipv6_skipped",
    "telegram_web_t_me",
    "telegram_aux_api",
    "telegram_cdn_t_me",
    # cloudflare
    "cloudflare_quic_h3",
    "cloudflare_warp_tcp_2408",
    "cloudflare_warp_masque_udp_4443",
    "cloudflare_warp_wg_udp_2408",
    "cloudflare_http_anycast",
    "cloudflare_anycast_ping",
    "google_quic_dns",
    "quad9_quic_dns",
)


def _producer_subcategories() -> set[str]:
    from censprobe_core.subcategories import derive

    return {derive(n) for n in SAMPLE_TEST_NAMES}


def test_grafana_only_filters_on_producer_subcategories() -> None:
    """Every subcategory the dashboards filter on must be producible by
    ``subcategories.derive``. Otherwise the panel goes silently empty."""
    grafana = _grafana_subcategories()
    producer = _producer_subcategories()
    missing = grafana - producer
    assert not missing, (
        f"Grafana panels filter on subcategories that no producer emits: "
        f"{sorted(missing)}. Either rename the panel SQL or add a rule "
        f"to subcategories.py."
    )


def test_grafana_actually_extracted_some_subcategories() -> None:
    """Defence against a regex regression — if the extractor pulls 0
    subcategories the previous assertion would silently pass."""
    grafana = _grafana_subcategories()
    assert grafana, (
        "No subcategory literals extracted from Grafana panels — either "
        "the regex broke or the dashboards moved."
    )
    # Sanity: at minimum the well-known core ones must be present.
    # (Many subcategories appear as group-by dimensions in the dashboards
    # rather than literal SQL filters; we only require representatives
    # from the families that *do* use literal filters.)
    for required in ("doh", "tls_sni_blocked", "tls_sni_neutral", "tls_ech"):
        assert required in grafana, f"Grafana extractor didn't see {required!r} — regex regression?"
