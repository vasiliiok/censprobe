"""Tests for ``_pick_neutral_sni``.

The May 2026 ya-zone-a run produced 4 spurious INCONCLUSIVE rows in the
TLS category because the hardcoded SNI=``cloudflare.com`` was rejected
server-side by every non-Cloudflare CDN edge: Akamai-hosted RFE/RT,
CurrentTime, TikTok, plus AWS-CloudFront-hosted ExpressVPN. Per-family
SNI selection drops those by sending an SNI the family is provisioned to
serve.

These cover the IP families we observed in real solo-run JSONs.
"""

from __future__ import annotations

import pytest
from censprobe_core.modules.tls import _pick_neutral_sni


class TestPickNeutralSni:
    @pytest.mark.parametrize(
        "ip",
        [
            "104.16.133.229",  # cloudflare.com itself
            "172.66.169.237",  # novayagazeta.eu via Cloudflare
            "1.1.1.1",  # not in any defined family — falls through to default
            "8.8.8.8",  # Google — also default
            "192.0.2.1",  # TEST-NET-1
        ],
    )
    def test_cloudflare_or_default(self, ip: str) -> None:
        assert _pick_neutral_sni(ip) == "cloudflare.com"

    @pytest.mark.parametrize(
        "ip",
        [
            "2.19.183.34",  # currenttime.tv (Akamai)
            "2.19.183.4",  # rferl.org (Akamai)
            "2.19.183.50",  # tiktok.com (Akamai)
            "2.21.240.78",  # related Akamai prefix
            "23.3.90.25",  # currenttime.tv via Akamai US
            "23.36.162.204",  # tiktok.com via Akamai NA (23.32.0.0/11)
            "92.123.133.187",  # currenttime.tv via Akamai EU Frankfurt
            "104.94.100.170",  # rferl.org via Akamai
            "104.126.37.123",  # tiktok.com via Akamai 104.64/10
            "184.50.55.55",  # Akamai NA (184.50.0.0/15)
            "184.86.103.214",  # rferl.org via Akamai EU Frankfurt (184.84.0.0/14)
            "184.86.103.223",  # tiktok.com via Akamai EU Frankfurt (184.84.0.0/14)
        ],
    )
    def test_akamai(self, ip: str) -> None:
        assert _pick_neutral_sni(ip) == "www.akamai.com"

    @pytest.mark.parametrize(
        "ip",
        [
            "13.249.8.97",  # expressvpn.com via CloudFront US
            "13.249.8.18",
            "108.156.22.108",
            "18.66.112.127",
            "108.156.22.49",
        ],
    )
    def test_cloudfront(self, ip: str) -> None:
        assert _pick_neutral_sni(ip) == "aws.amazon.com"

    def test_invalid_ip_falls_back_to_default(self) -> None:
        # Defensive: an IP-like string that ipaddress can't parse must
        # not crash — it should degrade to the historical baseline.
        assert _pick_neutral_sni("not-an-ip") == "cloudflare.com"
        assert _pick_neutral_sni("") == "cloudflare.com"
