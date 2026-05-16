"""Tests for ``detect_nat_pair`` — the cloud-VM NAT-pair detector.

Background: the original C MTProxy embeds the local source IP it observed
into its ``auth_cluster`` RPC handshake. On cloud VMs (GCP/AWS/DO private
VPC) the kernel sees a private IP (10.x.y.z) while the upstream Telegram
DC sees the NAT-translated public IP, so the embedded IP mismatches and
upstream silently drops every connection after the nonce exchange. The
fix passes ``--nat-info <private>:<public>`` — :func:`detect_nat_pair`
returns the pair when (and only when) it can be confidently derived.

The function returns ``None`` for any case where we'd otherwise be
guessing — explicit "no NAT detected" rather than a half-correct pair.
"""

from __future__ import annotations

from unittest.mock import patch

from censprobe_core.ephemeral_cert import detect_nat_pair


class TestDetectNatPair:
    def test_direct_public_ip_returns_none(self) -> None:
        # Bare-metal / budget VPS with a directly-attached public IP:
        # ``_udp_connect_local_ip`` already returns the public address,
        # so there's no NAT to disclose — return None and the caller
        # skips --nat-info (the daemon's local-IP embed is already
        # correct).
        with patch(
            "censprobe_core.ephemeral_cert._udp_connect_local_ip",
            return_value="34.176.4.124",
        ):
            assert detect_nat_pair() is None

    def test_gcp_nat_returns_pair(self) -> None:
        # Canonical GCP/AWS shape: private 10.x → echo service reveals
        # the NAT-translated public IP. Returned tuple is consumed
        # verbatim as ``--nat-info <private>:<public>``.
        with (
            patch(
                "censprobe_core.ephemeral_cert._udp_connect_local_ip",
                return_value="10.194.0.2",
            ),
            patch(
                "censprobe_core.ephemeral_cert._query_public_ip_echo",
                return_value="34.176.4.124",
            ),
        ):
            assert detect_nat_pair() == ("10.194.0.2", "34.176.4.124")

    def test_rfc1918_172_subnet_treated_as_unroutable(self) -> None:
        # 172.16.0.0/12 — same RFC1918 family as 10/8, different netmask.
        # is_private() covers it; the implementation should not special-case.
        with (
            patch(
                "censprobe_core.ephemeral_cert._udp_connect_local_ip",
                return_value="172.18.0.5",
            ),
            patch(
                "censprobe_core.ephemeral_cert._query_public_ip_echo",
                return_value="203.0.113.7",
            ),
        ):
            assert detect_nat_pair() == ("172.18.0.5", "203.0.113.7")

    def test_cgnat_local_treated_as_unroutable(self) -> None:
        # 100.64.0.0/10 — RFC 6598 carrier-grade NAT. Not covered by
        # ipaddress.IPv4Address.is_private in CPython, so the
        # implementation has a dedicated _CGNAT_NETWORK check.
        with (
            patch(
                "censprobe_core.ephemeral_cert._udp_connect_local_ip",
                return_value="100.96.5.10",
            ),
            patch(
                "censprobe_core.ephemeral_cert._query_public_ip_echo",
                return_value="198.51.100.42",
            ),
        ):
            assert detect_nat_pair() == ("100.96.5.10", "198.51.100.42")

    def test_no_outbound_network_returns_none(self) -> None:
        # ``_udp_connect_local_ip`` returns None when there's no default
        # route at all — air-gapped CI runner, broken interface. Caller
        # must NOT pass --nat-info with synthesised values.
        with patch(
            "censprobe_core.ephemeral_cert._udp_connect_local_ip",
            return_value=None,
        ):
            assert detect_nat_pair() is None

    def test_echo_service_unreachable_returns_none(self) -> None:
        # Behind NAT but the public-IP echo services are unreachable
        # (firewall, DPI blocking ifconfig.me, captive portal). We don't
        # have a confirmed public IP, so we can't honestly construct the
        # pair — return None and let the caller skip --nat-info.
        # Better degraded than wrong.
        with (
            patch(
                "censprobe_core.ephemeral_cert._udp_connect_local_ip",
                return_value="10.194.0.2",
            ),
            patch(
                "censprobe_core.ephemeral_cert._query_public_ip_echo",
                return_value=None,
            ),
        ):
            assert detect_nat_pair() is None

    def test_echo_equals_local_returns_none(self) -> None:
        # Defensive: a misbehaving echo service that reports back the
        # request's source-IP literal could in principle return the
        # private address (e.g. if accidentally hosted inside the same
        # VPC). The local==public case means the kernel routing already
        # has the right answer — no NAT translation in play, so skip.
        with (
            patch(
                "censprobe_core.ephemeral_cert._udp_connect_local_ip",
                return_value="10.194.0.2",
            ),
            patch(
                "censprobe_core.ephemeral_cert._query_public_ip_echo",
                return_value="10.194.0.2",
            ),
        ):
            assert detect_nat_pair() is None
