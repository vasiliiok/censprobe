#!/usr/bin/env python3
"""
Helper invoked by ``scripts/diagnose-awg-real.sh`` — runs ONLY the
AmneziaWG probe against a real running listener.

Why a focused script? The full ``censprobe-client`` runs all 9 probes
in sequence. If any earlier probe (notably WireGuard or OpenVPN) leaves
behind stale routes / interfaces / userspace state on a slow Wi-Fi,
the AWG probe inherits a broken environment and we can't tell whether
its verdict reflects the AWG layer or the contaminated state. This
script bypasses that by exercising AWG in isolation.

Inputs (env): SERVER_HOST, CREDS_PORT, CREDS_TOKEN, CREDS_CERT_SHA256.
"""

import asyncio
import hashlib
import os
import socket
import ssl
import sys

import yaml

sys.path.insert(0, "/work/packages/probe-core/src")

from censprobe_core.protocol_probes import (  # noqa: E402
    AmneziaWGObfuscation,
    probe_amneziawg,
)


def _fetch_creds_yaml(host: str, port: int, token: str, expected_sha256: str) -> str:
    """Replicate censprobe-client's cert-pinned, bearer-tokened cred fetch."""
    expected = expected_sha256.lower().replace(":", "").strip()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15.0) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            actual = hashlib.sha256(der).hexdigest()
            if actual != expected:
                raise RuntimeError(f"cert mismatch: got {actual}, want {expected}")
            tls.sendall(
                f"GET /creds HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n".encode()
            )
            buf = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                buf += chunk
    _, _, body = buf.partition(b"\r\n\r\n")
    return body.decode("utf-8", errors="replace")


async def main() -> None:
    host = os.environ["SERVER_HOST"]
    port = int(os.environ["CREDS_PORT"])
    token = os.environ["CREDS_TOKEN"]
    sha = os.environ["CREDS_CERT_SHA256"]

    print(f"[+] fetching creds from https://{host}:{port}/creds …", flush=True)
    body = _fetch_creds_yaml(host, port, token, sha)
    # Listener serves YAML with each protocol section at the top level
    # (see ``credentials.creds_to_yaml`` — flat schema, no "protocols:"
    # wrapper).
    creds = yaml.safe_load(body)
    awg = creds["amneziawg"]
    print(f"[+] AWG creds OK: port={awg['port']} jc={awg['jc']} s1={awg['s1']} s2={awg['s2']}", flush=True)

    obf = AmneziaWGObfuscation(
        jc=awg["jc"], jmin=awg["jmin"], jmax=awg["jmax"],
        s1=awg["s1"], s2=awg["s2"],
        h1=awg["h1"], h2=awg["h2"], h3=awg["h3"], h4=awg["h4"],
    )

    print(f"[+] probing AWG {host}:{awg['port']} (run 1) …", flush=True)
    r = await probe_amneziawg(
        host=host,
        port=awg["port"],
        server_public=awg["server_public_key"],
        preshared=awg["preshared_key"],
        private_key=awg["client_private_key"],
        obfuscation=obf,
    )
    print(
        f"  RESULT 1: verdict={r.verdict.value}  hs_ok={r.handshake_ok}  "
        f"data_ok={r.data_ok}  rtt={r.rtt_ms}  err={r.error}",
        flush=True,
    )

    print(f"[+] probing AWG {host}:{awg['port']} (run 2, fresh keys) …", flush=True)
    r = await probe_amneziawg(
        host=host,
        port=awg["port"],
        server_public=awg["server_public_key"],
        preshared=awg["preshared_key"],
        private_key=awg["client_private_key"],
        obfuscation=obf,
    )
    print(
        f"  RESULT 2: verdict={r.verdict.value}  hs_ok={r.handshake_ok}  "
        f"data_ok={r.data_ok}  rtt={r.rtt_ms}  err={r.error}",
        flush=True,
    )


asyncio.run(main())
