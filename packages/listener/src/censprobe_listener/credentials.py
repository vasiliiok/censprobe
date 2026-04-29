"""
credentials.py — Generate per-test-session VPN credentials.

Generates one-time credentials for all 6 VPN protocols and writes
them to reports/<test_id>/protocols.yaml so the client container
can read them via git pull.

Credentials are single-use test keys — not production VPN credentials.
Both server and client sides read the same file, so server-only secrets
(WG server private keys, Reality private key, OpenVPN PEM PSK) are
persisted too; otherwise a listener restart on the next SESSION_ID
would load empty strings and the VPN binaries would refuse to start.
"""
from __future__ import annotations

import base64
import contextlib
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
    """All credentials needed for one test session."""
    # OpenVPN: static-key PSK in OpenVPN "Static key V1" PEM format
    # (headers + 2048 hex bits). Raw base64 bytes are NOT valid input for
    # the `secret` directive.
    openvpn_psk_pem: str = ""
    openvpn_port: int = 1194

    # WireGuard: server keypair + client pubkey
    wg_server_private: str = ""
    wg_server_public: str = ""
    wg_client_private: str = ""
    wg_client_public: str = ""
    wg_preshared_key: str = ""
    wg_port: int = 51820

    # AmneziaWG: WG keypair + junk params
    awg_server_private: str = ""
    awg_server_public: str = ""
    awg_client_private: str = ""
    awg_client_public: str = ""
    awg_preshared_key: str = ""
    awg_port: int = 51821
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
    ss_port: int = 8388
    ss_method: str = "2022-blake3-aes-256-gcm"
    ss_password_b64: str = ""

    # VLESS + Reality
    vless_port: int = 443
    vless_uuid: str = ""
    vless_pbk: str = ""           # Reality public key
    vless_pvk: str = ""           # Reality private key (server only)
    vless_short_id: str = ""      # Reality short ID
    vless_server_name: str = "apimaps.yandex.ru"   # Reality SNI

    # Hysteria 2
    hy2_port: int = 443
    hy2_auth: str = ""
    hy2_obfs_password: str = ""


def generate_credentials() -> ProtocolCredentials:
    """Generate fresh one-time credentials for all protocols."""
    creds = ProtocolCredentials()

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

    return creds


# Sidecar filename for server-only secrets (WG/AWG server private keys
# and the Reality server private key). Lives next to protocols.yaml so
# they're easy to relate, but the `.secret.yaml` suffix is gitignored
# (see top-level .gitignore) so these files never enter git history.
SERVER_SECRETS_SUFFIX = "protocols-server.secret.yaml"


def server_secrets_path(protocols_yaml_path: Path) -> Path:
    """Return the sidecar path for server-only secrets next to protocols.yaml."""
    return protocols_yaml_path.parent / SERVER_SECRETS_SUFFIX


def save_protocols_yaml(creds: ProtocolCredentials, path: Path) -> None:
    """Write client-facing credentials to reports/<test_id>/protocols.yaml.

    Server-only secrets (WG/AWG server private keys, Reality server
    private key) are deliberately *omitted* from this file because it
    gets committed to git so the client container can pull it. They
    live in a sibling `protocols-server.secret.yaml` (gitignored, mode
    0o600) which the listener loads at startup if it exists.

    Symmetric secrets (OpenVPN PSK, Shadowsocks password, Hysteria 2
    auth + obfs) and client-side private keys (WG/AWG client_private)
    remain in the committed file because both sides need them.
    """
    data: dict[str, Any] = {
        "_note": "One-time test credentials. Do not use for production VPN.",
        "openvpn": {
            "port": creds.openvpn_port,
            "protocol": "udp",
            "psk_pem": creds.openvpn_psk_pem,
        },
        "wireguard": {
            "port": creds.wg_port,
            "server_public_key": creds.wg_server_public,
            "client_private_key": creds.wg_client_private,
            "client_public_key": creds.wg_client_public,
            "preshared_key": creds.wg_preshared_key,
        },
        "amneziawg": {
            "port": creds.awg_port,
            "server_public_key": creds.awg_server_public,
            "client_private_key": creds.awg_client_private,
            "client_public_key": creds.awg_client_public,
            "preshared_key": creds.awg_preshared_key,
            "jc": creds.awg_jc,
            "jmin": creds.awg_jmin,
            "jmax": creds.awg_jmax,
            "s1": creds.awg_s1,
            "s2": creds.awg_s2,
            "h1": creds.awg_h1,
            "h2": creds.awg_h2,
            "h3": creds.awg_h3,
            "h4": creds.awg_h4,
        },
        "shadowsocks": {
            "port": creds.ss_port,
            "method": creds.ss_method,
            "password_b64": creds.ss_password_b64,
        },
        "vless_reality": {
            "port": creds.vless_port,
            "uuid": creds.vless_uuid,
            "public_key": creds.vless_pbk,
            "short_id": creds.vless_short_id,
            "server_name": creds.vless_server_name,
        },
        "hysteria2": {
            "port": creds.hy2_port,
            "auth": creds.hy2_auth,
            "obfs_password": creds.hy2_obfs_password,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    content = yaml.dump(data, allow_unicode=True, sort_keys=False)
    # Atomic write: if the process is killed mid-write the original file
    # (if any) stays intact; only a successful rename makes the new version live.
    tmp_path = path.with_suffix(".yaml.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)
    logger.info("Protocols written to %s", path)


def save_server_secrets(creds: ProtocolCredentials, path: Path) -> None:
    """Persist server-only private keys to a local 0o600 sidecar file.

    Written into the same dir as `protocols.yaml` but with a name that
    matches the gitignore pattern `*.secret.yaml`. Mode 0o600 so even
    on a multi-tenant host the file is readable only by its owner.
    """
    data: dict[str, Any] = {
        "_note": (
            "Server-only secrets for censprobe-listener. "
            "Never commit. Regenerated together with protocols.yaml."
        ),
        "wireguard": {
            "server_private_key": creds.wg_server_private,
        },
        "amneziawg": {
            "server_private_key": creds.awg_server_private,
        },
        "vless_reality": {
            "private_key": creds.vless_pvk,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = yaml.dump(data, allow_unicode=True, sort_keys=False)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(blob)
    except BaseException:
        # os.fdopen() failed before taking ownership of fd — close it manually.
        with contextlib.suppress(OSError):
            os.close(fd)
        raise
    logger.info("Server secrets written to %s (mode 0600, gitignored)", path)


def load_server_secrets(path: Path, creds: ProtocolCredentials) -> bool:
    """Populate server-only private keys from the sidecar file.

    Returns True iff the file existed and at least one server private
    key was loaded. The caller (listener main) treats a missing file
    on a previously-initialised TEST_ID as a fatal regeneration trigger.
    """
    if not path.exists():
        return False
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict):
        return False
    found_any = False
    wg = raw.get("wireguard") or {}
    if wg.get("server_private_key"):
        creds.wg_server_private = wg["server_private_key"]
        found_any = True
    awg = raw.get("amneziawg") or {}
    if awg.get("server_private_key"):
        creds.awg_server_private = awg["server_private_key"]
        found_any = True
    vless = raw.get("vless_reality") or {}
    if vless.get("private_key"):
        creds.vless_pvk = vless["private_key"]
        found_any = True
    return found_any


def load_protocols_yaml(path: Path) -> ProtocolCredentials:
    """Load client-facing credentials from an existing protocols.yaml.

    Note: server-only private keys (wg_server_private, awg_server_private,
    vless_pvk) are NOT supposed to be in this file — load them separately
    via `load_server_secrets()` which reads the gitignored sidecar.

    For backwards compatibility, if a legacy protocols.yaml still embeds
    those server-private fields (older listener versions did), they are
    surfaced into the returned object so the caller (listener main) can
    migrate them into the secrets sidecar and rewrite the public file
    without them. Without this migration path, upgrading the listener on
    an existing TEST_ID would discard the old server keys entirely.
    """
    parsed = yaml.safe_load(path.read_text())
    raw: dict[str, Any] = parsed if isinstance(parsed, dict) else {}
    c = ProtocolCredentials()

    ovpn = raw.get("openvpn", {})
    c.openvpn_psk_pem = ovpn.get("psk_pem", "")
    c.openvpn_port = ovpn.get("port", 1194)

    wg = raw.get("wireguard", {})
    c.wg_server_public = wg.get("server_public_key", "")
    # Legacy field — kept ONLY for the rewrite-on-load migration.
    c.wg_server_private = wg.get("server_private_key", "")
    c.wg_client_private = wg.get("client_private_key", "")
    c.wg_client_public = wg.get("client_public_key", "")
    c.wg_preshared_key = wg.get("preshared_key", "")
    c.wg_port = wg.get("port", 51820)

    awg = raw.get("amneziawg", {})
    c.awg_server_public = awg.get("server_public_key", "")
    # Legacy field — kept ONLY for the rewrite-on-load migration.
    c.awg_server_private = awg.get("server_private_key", "")
    c.awg_port = awg.get("port", 51821)
    c.awg_client_private = awg.get("client_private_key", "")
    c.awg_client_public = awg.get("client_public_key", "")
    c.awg_preshared_key = awg.get("preshared_key", "")
    c.awg_jc = awg.get("jc", 4)
    c.awg_jmin = awg.get("jmin", 40)
    c.awg_jmax = awg.get("jmax", 70)
    c.awg_s1 = awg.get("s1", 0)
    c.awg_s2 = awg.get("s2", 0)
    c.awg_h1 = awg.get("h1", 0)
    c.awg_h2 = awg.get("h2", 0)
    c.awg_h3 = awg.get("h3", 0)
    c.awg_h4 = awg.get("h4", 0)

    ss = raw.get("shadowsocks", {})
    c.ss_port = ss.get("port", 8388)
    c.ss_method = ss.get("method", "2022-blake3-aes-256-gcm")
    c.ss_password_b64 = ss.get("password_b64", "")

    vless = raw.get("vless_reality", {})
    c.vless_port = vless.get("port", 443)
    c.vless_uuid = vless.get("uuid", "")
    # Legacy field — kept ONLY for the rewrite-on-load migration.
    c.vless_pvk = vless.get("private_key", "")
    c.vless_pbk = vless.get("public_key", "")
    c.vless_short_id = vless.get("short_id", "")
    c.vless_server_name = vless.get("server_name", "apimaps.yandex.ru")

    hy2 = raw.get("hysteria2", {})
    c.hy2_port = hy2.get("port", 443)
    c.hy2_auth = hy2.get("auth", "")
    c.hy2_obfs_password = hy2.get("obfs_password", "")

    return c


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
