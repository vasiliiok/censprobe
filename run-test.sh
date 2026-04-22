#!/usr/bin/env bash
# run-test.sh — Helper script for running a full Censprobe test in the correct order.
#
# Usage: TEST_ID=selectel-spb-001 ./run-test.sh
#
# Order is critical:
#   1. solo  — tests server's outbound view (must run BEFORE listener)
#   2. listener — VPN port listeners (user manually stops with Ctrl+C)
#
# Why this order matters:
#   Listener opens VPN ports (1194/UDP, 51820/UDP, 443 TCP/UDP, etc.)
#   ТСПУ may intensify filtering of the server's OUTBOUND traffic after detecting
#   these ports. Running solo AFTER listener gives biased uplink quality results.

set -euo pipefail

if [[ -z "${TEST_ID:-}" ]]; then
    echo "Error: TEST_ID is required."
    echo "Usage: TEST_ID=selectel-spb-001 ./run-test.sh"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════"
echo "  Censprobe Test: ${TEST_ID}"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Step 1/2: Running SOLO probe (tests from this server's perspective)..."
echo "         This may take 5-15 minutes."
echo ""

TEST_ID="${TEST_ID}" docker compose --profile solo up --abort-on-container-exit

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  SOLO complete! Report pushed to GitHub."
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Step 2/2: Start LISTENER for client network testing."
echo ""
echo "For each client network you want to test, run:"
echo ""
echo "  TEST_ID=${TEST_ID} SESSION_ID=client-home-rt-spb \\"
echo "    docker compose --profile listener up"
echo ""
echo "Then on the client machine:"
echo ""
echo "  TEST_ID=${TEST_ID} SERVER_HOST=$(hostname -I | awk '{print $1}') \\"
echo "    docker compose --profile client up"
echo ""
echo "After testing each network: Ctrl+C on listener → it pushes report."
echo ""
echo "View results: docker compose --profile dashboard up -d"
echo "Then open http://localhost:3000 and click 'Pull & Refresh'"
echo "═══════════════════════════════════════════════════════════"
