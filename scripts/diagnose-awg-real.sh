#!/usr/bin/env bash
#
# diagnose-awg-real.sh — focused AWG-only probe against a live listener.
#
# Usage (on client):
#   bash scripts/diagnose-awg-real.sh \
#       <SERVER_HOST> <CREDS_PORT> <CREDS_TOKEN> <CREDS_CERT_SHA256>
#
# Captures host-side packets on UDP/<awg_port> via tcpdump while the
# probe runs, so a maintainer can correlate verdict with what actually
# went on the wire. Output:
#   * stdout: probe verdict for two consecutive AWG runs
#   * $HOME/awg-real-pcap.pcap: packet capture
#   * $HOME/awg-real-state.log: tcpdump summary (auto-generated post-run)
#
# Designed to NOT run any other probe — the multi-probe path can leave
# stale ifaces / routes from earlier protocols (most often WireGuard's
# wg-quick teardown on a flaky Wi-Fi) that contaminate AWG. By running
# AWG in isolation we get a clean signal.

set -euo pipefail

if [ $# -lt 4 ]; then
  echo "Usage: $0 <SERVER_HOST> <CREDS_PORT> <CREDS_TOKEN> <CREDS_CERT_SHA256>"
  exit 64
fi

SERVER_HOST="$1"
CREDS_PORT="$2"
CREDS_TOKEN="$3"
CREDS_CERT_SHA256="$4"

cd "$(dirname "$0")/.."

# Capture host-side AWG traffic. Default AWG port is 51821; if the
# listener is on a different port, the dump still catches all traffic
# to/from <SERVER_HOST> on UDP — the BPF filter widens accordingly.
PCAP="$HOME/awg-real-pcap.pcap"
sudo pkill tcpdump 2>/dev/null || true
rm -f "$PCAP"
sudo tcpdump -i any -nn -Z root \
  -w "$PCAP" \
  "host $SERVER_HOST and udp" &
TCPDUMP_PID=$!
sleep 1

# Run focused probe inside the censprobe-client image. Mount the repo
# read-only so we use the live source tree, never a stale image bake.
sudo docker run --rm --network host --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD:/work" -w /work \
  -e SERVER_HOST="$SERVER_HOST" \
  -e CREDS_PORT="$CREDS_PORT" \
  -e CREDS_TOKEN="$CREDS_TOKEN" \
  -e CREDS_CERT_SHA256="$CREDS_CERT_SHA256" \
  --entrypoint python3 \
  outtakes/censprobe-client:main /work/scripts/_awg_real_probe.py

sudo pkill tcpdump 2>/dev/null || true
sleep 1

echo
echo "===== Packet capture summary ====="
ls -la "$PCAP"
PKT_COUNT=$(sudo tcpdump -r "$PCAP" -nn 2>/dev/null | wc -l)
echo "total packets to/from $SERVER_HOST on UDP: $PKT_COUNT"
echo
echo "--- first 20 packets ---"
sudo tcpdump -r "$PCAP" -nn 2>/dev/null | head -20
echo
echo "--- last 10 packets ---"
sudo tcpdump -r "$PCAP" -nn 2>/dev/null | tail -10
