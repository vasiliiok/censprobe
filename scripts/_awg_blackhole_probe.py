#!/usr/bin/env python3
"""
Helper invoked by ``scripts/diagnose-awg.sh`` — runs probe_amneziawg()
against an RFC 5737 blackhole IP (192.0.2.1) twice in a row and prints
the verdict so a maintainer can compare what their machine reports
against the reference behavior described in the wrapper script.

Lives as a real file (not a heredoc'd inline snippet) because shells
disagree on indentation handling in heredocs and several users have
hit IndentationError when pasting the inline form into a terminal.
"""

import asyncio
import subprocess
import sys

sys.path.insert(0, "/work/packages/probe-core/src")

from censprobe_core.protocol_probes import (  # noqa: E402
    AmneziaWGObfuscation,
    probe_amneziawg,
)


def _gen_key() -> str:
    return subprocess.run(
        ["awg", "genkey"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _pubkey_of(private: str) -> str:
    return subprocess.run(
        ["awg", "pubkey"],
        input=private,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _gen_psk() -> str:
    return subprocess.run(
        ["awg", "genpsk"], capture_output=True, text=True, check=True
    ).stdout.strip()


async def _run_once(label: str, server_pub: str, psk: str, client_priv: str) -> None:
    obf = AmneziaWGObfuscation(
        jc=5,
        jmin=50,
        jmax=1000,
        s1=30,
        s2=60,
        h1=1234567890,
        h2=2345678901,
        h3=3456789012,
        h4=405061122,
    )
    print(f"=== {label}: AWG probe -> 192.0.2.1:51821 (blackhole) ===")
    r = await probe_amneziawg(
        host="192.0.2.1",
        port=51821,
        server_public=server_pub,
        preshared=psk,
        private_key=client_priv,
        obfuscation=obf,
    )
    print(
        f"  verdict={r.verdict.value}  "
        f"hs_ok={r.handshake_ok}  "
        f"data_ok={r.data_ok}  "
        f"rtt={r.rtt_ms}  "
        f"err={r.error}"
    )


async def main() -> None:
    sk_server = _gen_key()
    pk_server = _pubkey_of(sk_server)
    sk_client = _gen_key()
    psk = _gen_psk()
    await _run_once("Run 1", pk_server, psk, sk_client)
    await _run_once("Run 2", pk_server, psk, sk_client)


asyncio.run(main())
