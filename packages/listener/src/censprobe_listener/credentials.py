"""
credentials.py — Generate per-test-session VPN credentials.

Generates one-time credentials for all 6 VPN protocols. Persistence is
deliberately not provided: every listener start handed off to a single
``SESSION_ID`` produces a fresh set, the credentials live only in
memory, and ``cred_server.CredServer`` exposes them to the client over a
dedicated TLS endpoint. Old per-test-id files in ``reports/<id>/`` are
no longer written or read, eliminating the protocols.yaml git-history
exposure that earlier versions relied on.

Credentials are single-use test keys — not production VPN credentials.
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ProtocolCredentials:
    """All credentials needed for one test session.

    Port fields have NO defaults — every value flows in from
    ``censprobe.yaml::protocols.ports`` via :func:`generate_credentials`,
    so a missing config entry surfaces at config-load time rather than as
    a silent "everyone bound the right port by accident".
    """
    # OpenVPN: static-key PSK in OpenVPN "Static key V1" PEM format
    # (headers + 2048 hex bits). Raw base64 bytes are NOT valid input for
    # the `secret` directive.
    openvpn_psk_pem: str = ""
    openvpn_port: int = 0

    # WireGuard: server keypair + client pubkey
    wg_server_private: str = ""
    wg_server_public: str = ""
    wg_client_private: str = ""
    wg_client_public: str = ""
    wg_preshared_key: str = ""
    wg_port: int = 0

    # AmneziaWG: WG keypair + junk params
    awg_server_private: str = ""
    awg_server_public: str = ""
    awg_client_private: str = ""
    awg_client_public: str = ""
    awg_preshared_key: str = ""
    awg_port: int = 0
    awg_jc: int = 4
    awg_jmin: int = 40
    awg_jmax: int = 70
    awg_s1: int = 0
    awg_s2: int = 0
    awg_h1: int = 0
    awg_h2: int = 0
    awg_h3: int = 0
    awg_h4: int = 0

    # Shadowsocks 2022
    ss_port: int = 0
    ss_method: str = "2022-blake3-aes-256-gcm"
    ss_password_b64: str = ""

    # VLESS + Reality
    vless_port: int = 0
    vless_uuid: str = ""
    vless_pbk: str = ""           # Reality public key
    vless_pvk: str = ""           # Reality private key (server only)
    vless_short_id: str = ""      # Reality short ID
    vless_server_name: str = "apimaps.yandex.ru"   # Reality SNI

    # Hysteria 2
    hy2_port: int = 0
    hy2_auth: str = ""
    hy2_obfs_password: str = ""

    # MTProto Proxy (mtg)
    mtproxy_secret: str = ""
    mtproxy_port: int = 0


# Map from canonical protocol name → credential-port attribute. Used when
# applying ``cfg.protocols.ports`` onto a fresh ProtocolCredentials.
# Adding a protocol requires extending this map alongside the dataclass
# field; the symmetry is enforced by ``_apply_ports`` (KeyError on a name
# without a known attr).
_PROTOCOL_PORT_ATTR: dict[str, str] = {
    "openvpn":       "openvpn_port",
    "wireguard":     "wg_port",
    "amneziawg":     "awg_port",
    "shadowsocks":   "ss_port",
    "vless_reality": "vless_port",
    "hysteria2":     "hy2_port",
    "mtproto_proxy": "mtproxy_port",
}


def _apply_ports(creds: ProtocolCredentials, ports: dict[str, int]) -> None:
    """Stamp every port from ``cfg.protocols.ports`` onto ``creds``.

    Raises ``KeyError`` on a protocol name that has no matching attr —
    that's a programmer error (registry got a new protocol but
    credentials.py didn't), not an operator error, and we want it to
    surface immediately instead of being papered over.
    """
    for name, port in ports.items():
        attr = _PROTOCOL_PORT_ATTR.get(name)
        if attr is None:
            raise KeyError(
                f"protocols.ports contains '{name}' but no port attribute "
                f"is registered in _PROTOCOL_PORT_ATTR — extend "
                f"censprobe_listener.credentials when adding a protocol."
            )
        setattr(creds, attr, port)


def generate_credentials(ports: dict[str, int]) -> ProtocolCredentials:
    """Generate fresh one-time credentials for all protocols.

    ``ports`` MUST be a complete map of protocol-name → bind-port,
    typically ``cfg.protocols.ports`` (validated in
    :class:`ProtocolsConfig` so every enabled protocol is covered).
    """
    creds = ProtocolCredentials()
    _apply_ports(creds, ports)

    # OpenVPN PSK: must be in OpenVPN's "Static key V1" PEM envelope
    # (16 lines of 32 hex chars wrapped in BEGIN/END markers). Raw random
    # bytes — even if base64-encoded — are rejected by `openvpn --secret`.
    creds.openvpn_psk_pem = _openvpn_static_key()

    # WireGuard: use wg genkey/pubkey
    creds.wg_server_private, creds.wg_server_public = _wg_keypair()
    creds.wg_client_private, creds.wg_client_public = _wg_keypair()
    creds.wg_preshared_key = _wg_preshared_key()

    # AmneziaWG: same structure as WG + junk params
    creds.awg_server_private, creds.awg_server_public = _wg_keypair()
    creds.awg_client_private, creds.awg_client_public = _wg_keypair()
    creds.awg_preshared_key = _wg_preshared_key()
    # H1-H4 are AmneziaWG's per-message-type magic header replacements.
    # Standard WireGuard uses fixed values 1..4 (handshake_init,
    # handshake_resp, cookie_reply, transport_data — see
    # drivers/net/wireguard/messages.h); the whole point of overriding
    # them is to NOT collide with those values, otherwise the on-the-wire
    # bytes still match a vanilla WG fingerprint. They must also be
    # mutually distinct, otherwise the AWG demuxer cannot tell which
    # message type a given inbound packet represents and silently drops
    # half of the handshake. Sample from a constrained range that avoids
    # both pitfalls in one shot.
    creds.awg_h1, creds.awg_h2, creds.awg_h3, creds.awg_h4 = _awg_magic_headers()
    creds.awg_jc = secrets.randbelow(5) + 3   # 3-7 junk packets
    creds.awg_jmin = secrets.randbelow(20) + 40   # 40-59
    creds.awg_jmax = secrets.randbelow(30) + 70   # 70-99

    # AmneziaWG junk-payload sizes for handshake init / response. The
    # only on-wire constraint is that an obfuscated init packet length
    # (148 + S1) must NOT equal an obfuscated response length (92 + S2),
    # i.e. S1 + 56 != S2 — otherwise an observer can demux the two
    # message types by length alone, defeating the obfuscation.
    creds.awg_s1 = secrets.randbelow(135) + 15
    creds.awg_s2 = secrets.randbelow(135) + 15
    while creds.awg_s1 + 56 == creds.awg_s2:
        creds.awg_s2 = secrets.randbelow(135) + 15

    # Shadowsocks 2022: 32-byte password
    creds.ss_password_b64 = base64.b64encode(os.urandom(32)).decode()

    # VLESS + Reality: UUID + reality keys
    creds.vless_uuid = _generate_uuid()
    creds.vless_pvk, creds.vless_pbk = _reality_keypair()
    creds.vless_short_id = secrets.token_hex(4)  # 4 bytes = 8 hex chars

    # Hysteria 2: random auth + obfs password
    creds.hy2_auth = secrets.token_urlsafe(24)
    creds.hy2_obfs_password = secrets.token_urlsafe(20)

    # MTProto Proxy (mtg): Fake-TLS ('ee') secret
    # Format: 'ee' + 16 random bytes (32 hex chars) + hex-encoded SNI domain.
    # We use google.com as a safe default for domain fronting / SNI mimicry.
    sni = b"google.com".hex()
    random_part = secrets.token_hex(16)
    creds.mtproxy_secret = f"ee{random_part}{sni}"

    return creds


_SECTION_BUILDERS: dict[str, Any] = {
    "openvpn": lambda c: {
        "port": c.openvpn_port,
        "protocol": "udp",
        "psk_pem": c.openvpn_psk_pem,
    },
    "wireguard": lambda c: {
        "port": c.wg_port,
        "server_public_key": c.wg_server_public,
        "client_private_key": c.wg_client_private,
        "client_public_key": c.wg_client_public,
        "preshared_key": c.wg_preshared_key,
    },
    "amneziawg": lambda c: {
        "port": c.awg_port,
        "server_public_key": c.awg_server_public,
        "client_private_key": c.awg_client_private,
        "client_public_key": c.awg_client_public,
        "preshared_key": c.awg_preshared_key,
        "jc": c.awg_jc,
        "jmin": c.awg_jmin,
        "jmax": c.awg_jmax,
        "s1": c.awg_s1,
        "s2": c.awg_s2,
        "h1": c.awg_h1,
        "h2": c.awg_h2,
        "h3": c.awg_h3,
        "h4": c.awg_h4,
    },
    "shadowsocks": lambda c: {
        "port": c.ss_port,
        "method": c.ss_method,
        "password_b64": c.ss_password_b64,
    },
    "vless_reality": lambda c: {
        "port": c.vless_port,
        "uuid": c.vless_uuid,
        "public_key": c.vless_pbk,
        "short_id": c.vless_short_id,
        "server_name": c.vless_server_name,
    },
    "hysteria2": lambda c: {
        "port": c.hy2_port,
        "auth": c.hy2_auth,
        "obfs_password": c.hy2_obfs_password,
    },
    "mtproto_proxy": lambda c: {
        "port": c.mtproxy_port,
        "secret": c.mtproxy_secret,
    },
}


def creds_to_yaml(
    creds: ProtocolCredentials,
    enabled_protocols: list[str] | None = None,
) -> str:
    """Serialise the credential set (server + client material) for the
    one-shot HTTPS endpoint.

    Server-private keys (WG/AWG server_private, Reality private_key) are
    intentionally INCLUDED. The earlier file-based flow split them into a
    gitignored sidecar because protocols.yaml was committed to a public
    repo; the cred-server delivers everything over a TLS pinned channel
    to a single client per session, so there is no shared persistence
    surface for them to leak through. The client itself never uses the
    server-private fields — they are emitted here only because both
    sides parse the same YAML schema.

    ``enabled_protocols`` is the operator-configured subset the listener
    actually started. Only those sections are emitted, so a protocol the
    operator removed from ``protocols.enabled`` (and therefore from
    ``protocols.ports``) does not show up in the YAML at all — the client
    sees the absence via ``_protocols_enabled`` and skips that probe.
    ``None`` means "every protocol this listener knows about", which
    matches the historical no-filter behaviour. Listener and client
    upgrade in lockstep (same docker-compose image), so the schema is
    versioned by deployment, not by best-effort back-compat.
    """
    if enabled_protocols is None:
        names = list(_SECTION_BUILDERS.keys())
    else:
        names = [n for n in enabled_protocols if n in _SECTION_BUILDERS]

    data: dict[str, Any] = {
        "_note": "One-time test credentials. Do not use for production VPN.",
        "_protocols_enabled": list(enabled_protocols)
        if enabled_protocols is not None
        else None,
    }
    for name in names:
        data[name] = _SECTION_BUILDERS[name](creds)
    return yaml.dump(data, allow_unicode=True, sort_keys=False)


# ─────────────────────────────────────────────────────────────────────────────
# Key generation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _wg_keypair() -> tuple[str, str]:
    """
    Generate a WireGuard (Curve25519) keypair via `wg genkey` / `wg pubkey`.

    The `wg` binary is provisioned by the listener Docker image
    (wireguard-tools). If it is missing or fails, fail loudly: a silent
    fallback to `cryptography.X25519PrivateKey` would mask a broken image
    and the operator would only discover it later when the WireGuard
    responder fails to start with a confusing key-format error.
    """
    try:
        private = subprocess.check_output(["wg", "genkey"]).decode().strip()
        public = subprocess.check_output(
            ["wg", "pubkey"], input=private.encode()
        ).decode().strip()
    except FileNotFoundError as e:
        raise RuntimeError(
            "wg binary not found — listener image is missing wireguard-tools"
        ) from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wg genkey/pubkey failed: {e}") from e
    return private, public


def _awg_magic_headers() -> tuple[int, int, int, int]:
    """Generate four distinct 32-bit values for AmneziaWG H1..H4.

    Constraints (all enforced by amneziawg-go / amneziawg kernel-module):
      * each H_i is parsed as a 32-bit unsigned int;
      * the four values must be pairwise distinct (the receiver demuxes
        message type by exact-match against H1..H4);
      * none of them may equal the standard WireGuard message-type ids
        1, 2, 3, 4 — using those defeats the whole obfuscation since
        the wire bytes coincide with vanilla WG.
    """
    forbidden: set[int] = {1, 2, 3, 4}
    chosen: list[int] = []
    while len(chosen) < 4:
        v = secrets.randbits(32)
        if v in forbidden or v in chosen:
            continue
        chosen.append(v)
    return chosen[0], chosen[1], chosen[2], chosen[3]


def _wg_preshared_key() -> str:
    """
    Generate a WireGuard preshared key via `wg genpsk`.

    Even though a PSK is just an opaque 32-byte symmetric secret and
    `secrets.token_bytes(32)` would be cryptographically equivalent, we
    intentionally route through `wg` so that a missing binary surfaces
    here (during credential generation) instead of later as an opaque
    "load_psk_file" error from the WireGuard responder.
    """
    try:
        return subprocess.check_output(["wg", "genpsk"]).decode().strip()
    except FileNotFoundError as e:
        raise RuntimeError(
            "wg binary not found — listener image is missing wireguard-tools"
        ) from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"wg genpsk failed: {e}") from e


def _generate_uuid() -> str:
    """Generate a RFC 4122 UUID v4."""
    import uuid
    return str(uuid.uuid4())


def _reality_keypair() -> tuple[str, str]:
    """
    Generate an x25519 keypair for VLESS+Reality using `xray x25519`.
    Returns (private_key_urlsafe_b64, public_key_urlsafe_b64).

    Xray/Reality parses keys with Go's base64.RawURLEncoding — URL-safe
    alphabet, NO padding. Standard base64 (`+`/`/` with `=` padding) is
    rejected at server startup, so we always go through xray itself
    rather than re-implementing the encoding. The xray binary is
    provisioned by the listener Docker image; if it is missing, fail
    loudly here instead of letting the VLESS responder die later with
    an opaque "invalid private key" error.
    """
    try:
        out = subprocess.check_output(
            ["xray", "x25519"], stderr=subprocess.DEVNULL
        ).decode()
    except FileNotFoundError as e:
        raise RuntimeError(
            "xray binary not found — listener image is missing xray-core"
        ) from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"xray x25519 failed: {e}") from e

    # Output format:
    # Private key: <b64>
    # Public key:  <b64>
    lines = out.strip().splitlines()
    if len(lines) < 2:
        raise RuntimeError(f"xray x25519 returned unexpected output: {out!r}")
    private = lines[0].split(": ", 1)[1].strip()
    public = lines[1].split(": ", 1)[1].strip()
    return private, public


def _openvpn_static_key() -> str:
    """
    Generate an OpenVPN static key in the exact PEM envelope that
    `openvpn --secret` expects:

        -----BEGIN OpenVPN Static key V1-----
        <16 × 32 hex chars>
        -----END OpenVPN Static key V1-----

    Always calls `openvpn --genkey secret`. The openvpn binary ships in
    the listener Docker image; a missing or failing binary is a fatal
    image bug and must surface here, not as a confusing
    "Cannot load static key" error from the responder later.

    Some openvpn builds refuse to write the key to /dev/stdout, and
    `--genkey secret <file>` refuses to overwrite an existing file —
    `NamedTemporaryFile` would create the target eagerly and trip that
    check. Use a 0o700 TemporaryDirectory and pass a not-yet-existing
    path inside it instead.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="censprobe_ovpn_genkey_") as td:
            key_path = Path(td) / "static.key"
            subprocess.check_call(
                ["openvpn", "--genkey", "secret", str(key_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return key_path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise RuntimeError(
            "openvpn binary not found — listener image is missing openvpn"
        ) from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"openvpn --genkey secret failed: {e}") from e
