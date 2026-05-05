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

# ─────────────────────────────────────────────────────────────────────────────
# Mapping rules
# ─────────────────────────────────────────────────────────────────────────────
#
# Suffix rules win over prefix rules — they let us split a single
# top-level family into named sub-families based on the role suffix
# (``_sni_blocked`` / ``_sni_neutral`` / ``_ech`` for the TLS family).
# Order matters within suffix rules too: the longest / most specific
# suffix should come first so a less specific match doesn't shadow it.
_SUFFIX_RULES: tuple[tuple[str, str], ...] = (
    ("_sni_blocked", "tls_sni_blocked"),
    ("_sni_neutral", "tls_sni_neutral"),
    ("_ech", "tls_ech"),
    ("_no_ip", "tls_meta"),
)


# Prefix rules are evaluated in order — first match wins. The order
# matters: e.g. ``cloudflare_quic_`` must come before ``cloudflare_``
# so QUIC tests don't get the generic ``cloudflare`` subcategory.
# Each rule is (prefix, subcategory). A matching test name is reduced
# to the subcategory and nothing else from the name is used.
_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    # DNS family
    ("doh_access_", "doh"),
    ("dot_access_", "dot"),
    ("dns_", "dns"),
    # TLS family — split into the two halves of the SNI-paired probe and
    # the standalone ECH probe. Pair-key reconstruction in dashboards
    # joins on the ``_sni_blocked`` / ``_sni_neutral`` halves.
    # Order: more specific suffixes first.
    # NB: subcategory is the same for both halves; dashboards use
    # ``tls_pair`` and re-derive blocked/neutral from the test-name suffix.
    # We don't try to encode the suffix in the subcategory itself
    # (that would explode the cardinality).
    # Cloudflare family — sub-subcategories for QUIC / WARP TCP / WARP UDP / HTTP.
    # WARP UDP names look like ``cloudflare_warp_masque_udp_4443`` and
    # ``cloudflare_warp_wg_udp_2408`` — both contain the substring
    # ``_udp_``, so we use a substring rule to split UDP from TCP within
    # the WARP family. (Substring rules are matched in :func:`derive`
    # before the simple prefix rules below.)
    # Note: we keep ``cloudflare_quic_`` ahead of ``google_quic_dns`` /
    # ``quad9_quic_dns`` (which begin with ``google_`` / ``quad9_`` and
    # would otherwise miss). Those land in the ``cloudflare_quic``
    # subcategory by way of the explicit name-override block below.
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
    # TLS — must come AFTER specific tls_* rules above (none currently;
    # listed last in the family so future tls_xxx_<thing> can be split).
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
    return "unknown"
