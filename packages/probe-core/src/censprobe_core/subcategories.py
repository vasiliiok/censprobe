"""
subcategories.py — Stable contract between test names and dashboard SQL.

Modules emit :class:`TestResult` rows whose ``test`` field follows a
loose naming convention (``dns_<domain>_system``, ``doh_access_<resolver>``,
``tls_<domain>_sni_blocked``, …). Grafana panels used to filter on those
prefixes via fragile ``LIKE 'doh_%'``-style SQL — a rename in any
producer module would silently empty an entire dashboard panel without
raising an error anywhere.

This module centralises the convention. Each :class:`TestResult` carries
a ``subcategory`` derived once at parse time via :func:`derive`; sync-api
persists it as a dedicated column; Grafana panels filter on
``subcategory = 'doh'`` instead of pattern-matching test names.

Adding a new probe family:
  * Pick a stable subcategory name (snake_case, short, descriptive).
  * Either pick a test-name prefix that maps to it via _PREFIX_RULES
    below, or add an explicit name → subcategory entry to
    _NAME_OVERRIDES.

Renaming an existing probe family:
  * Change BOTH the prefix here AND the dashboard panels that filter
    on the old subcategory — they're the two ends of the same contract.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Mapping rules
# ─────────────────────────────────────────────────────────────────────────────
#
# Resolution order in :func:`derive`:
#   1. _NAME_OVERRIDES (explicit per-test mapping — cross-vendor controls)
#   2. _SUFFIX_RULES   (longest-first; splits the TLS family by role)
#   3. _SUBSTRING_RULES (middle-of-name markers; WARP UDP variants)
#   4. _PREFIX_RULES   (declaration-order, first match wins)
#   5. category fallback then "unknown"
#
# Cloudflare prefixes are layered specific-first (``cloudflare_quic_`` >
# ``cloudflare_warp_`` > ``cloudflare_http_`` > ``cloudflare_``). Cross-
# vendor QUIC controls (Google/Quad9 DNS) carry the vendor name as the
# prefix and reach ``cloudflare_quic`` via _NAME_OVERRIDES instead.

# Suffix rules — split a family by role suffix. Longest first so a less
# specific match doesn't shadow a more specific one.
_SUFFIX_RULES: tuple[tuple[str, str], ...] = (
    ("_sni_blocked", "tls_sni_blocked"),
    ("_sni_neutral", "tls_sni_neutral"),
    ("_ech", "tls_ech"),
    ("_no_ip", "tls_meta"),
)


# Prefix rules — first match wins.
_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    # DNS family
    ("doh_access_", "doh"),
    ("dot_access_", "dot"),
    ("dns_", "dns"),
    # Cloudflare family
    ("cloudflare_quic_", "cloudflare_quic"),
    ("cloudflare_warp_", "cloudflare_warp"),
    ("cloudflare_http_", "cloudflare_http"),
    ("cloudflare_", "cloudflare"),
    # Telegram family — DC reachability vs web/auxiliary/CDN/health.
    ("telegram_dc", "telegram_dc"),
    ("telegram_health", "telegram_health"),
    ("telegram_ipv6", "telegram_meta"),
    ("telegram_web_", "telegram_web"),
    ("telegram_aux_", "telegram_aux"),
    ("telegram_cdn_", "telegram_cdn"),
    ("telegram_", "telegram"),
    # Throttling
    ("throttling_", "throttling"),
    # Middlebox
    ("middlebox_", "middlebox"),
    # TLS — must come AFTER the suffix rules at the top of the module.
    ("tls_", "tls"),
    # TCP
    ("tcp_", "tcp"),
    # HTTP
    ("http_", "http"),
)


# Substring rules — checked between prefix and suffix rules. Used for
# splitting WARP UDP variants out of the broader WARP family without
# enumerating every concrete name.
_SUBSTRING_RULES: tuple[tuple[str, str], ...] = (
    ("_warp_masque_udp", "cloudflare_warp_udp_masque"),
    ("_warp_wg_udp", "cloudflare_warp_udp_wg"),
)


# Explicit overrides for specific test names that don't fit a prefix.
# Used for cross-vendor QUIC controls (Google / Quad9) which carry the
# vendor name as the prefix instead of ``cloudflare_``.
_NAME_OVERRIDES: dict[str, str] = {
    "telegram_health_score": "telegram_health",
    "telegram_ipv6_skipped": "telegram_meta",
    "throttling_youtube_sni_probe_method_b": "throttling",
    "google_quic_dns": "cloudflare_quic",
    "quad9_quic_dns": "cloudflare_quic",
}


def derive(test_name: str, category: str | None = None) -> str:
    """Return the stable subcategory for a given ``test`` field value.

    Resolution order (most specific first):

      1. Explicit name override (``_NAME_OVERRIDES``).
      2. Suffix rule (``_SUFFIX_RULES``) — splits one family into named
         sub-families by role suffix (``_sni_blocked``, ``_ech``, …).
      3. Substring rule (``_SUBSTRING_RULES``) — middle-of-name markers.
      4. Prefix rule (``_PREFIX_RULES``).
      5. Fallback to ``category`` if available (the HTTP module doesn't
         prefix its test names).
      6. ``"unknown"`` — surfaces in dashboards as a hint that a probe
         family slipped through the contract.
    """
    if test_name in _NAME_OVERRIDES:
        return _NAME_OVERRIDES[test_name]
    for suffix, sub in _SUFFIX_RULES:
        if test_name.endswith(suffix):
            return sub
    for substr, sub in _SUBSTRING_RULES:
        if substr in test_name:
            return sub
    for prefix, sub in _PREFIX_RULES:
        if test_name.startswith(prefix):
            return sub
    if category:
        return category
    # Surfacing "unknown" in the dashboard means a producer module emitted
    # a test name that doesn't fit any rule above. Log at WARNING so the
    # operator notices in the listener/solo console — a silent "unknown"
    # row used to slip past every reviewer until Grafana surfaced it.
    logger.warning(
        "subcategory: test name %r matched no rule and has no category — "
        "defaulting to 'unknown'; add a prefix/suffix/override mapping",
        test_name,
    )
    return "unknown"
