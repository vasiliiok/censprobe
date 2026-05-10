#!/usr/bin/env bash
#
# diagnose-awg.sh — repro test for the suspected AmneziaWG client false-OK.
#
# What it does:
#   * Generates a throwaway AWG keypair locally inside the censprobe-client
#     image so no real listener is needed.
#   * Calls probe_amneziawg() against 192.0.2.1 (RFC 5737 TEST-NET-1, no
#     host can route there). The expected verdict is BLOCKED in every
#     environment that has no AWG server: handshake-poll never sees a
#     non-zero timestamp, ping_echo finds no peer, transfer rx_bytes
#     stays at zero. If you instead see OK or HANDSHAKE_ONLY, the local
#     AmneziaWG userspace/kernel implementation is producing fabricated
#     state and the probe's double-signal protection is being defeated
#     somewhere outside our code.
#   * Runs the probe twice in a row to catch any stale-state caching
#     between consecutive bring-ups (we delete the iface + socket each
#     time, but kernel-level peer tables could persist).
#
# Usage:
#   bash scripts/diagnose-awg.sh
#
# Run from the censprobe repo root with the censprobe-client:main image
# already built locally (`docker compose build client`).

set -euo pipefail

cd "$(dirname "$0")/.."

# Need NET_ADMIN + /dev/net/tun for awg-quick to bring up the userspace
# tunnel; --network host so the iface lives in the host netns and is
# visible to `awg show` from any side.
sudo docker run --rm --network host --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD:/work" -w /work --entrypoint python3 \
  outtakes/censprobe-client:main /work/scripts/_awg_blackhole_probe.py
