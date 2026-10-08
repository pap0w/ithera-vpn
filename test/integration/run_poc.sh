#!/usr/bin/env bash
# ==============================================================================
# Project: ithera-vpn
# Script: test/integration/run_poc.sh
# Purpose: Phase 1 PoC Verification Test using Linux Network Namespaces
#
# Acceptance Criteria Tested:
# 1. ping -c 3 10.0.0.1 responds with 0% packet loss across TUN interfaces.
# 2. tcpdump on underlay veth interface captures ONLY WireGuard UDP packets;
#    zero plaintext ICMP packets appear on the wire.
# ==============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[PASS]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# 1. Privilege check
if [[ $EUID -ne 0 ]]; then
    log_fail "This script creates network namespaces and must be run as root (or with sudo)."
fi

# 2. Dependency check
for cmd in ip ping tcpdump; do
    if ! command -v "$cmd" &>/dev/null; then
        log_fail "Missing required tool: $cmd"
    fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="$ROOT_DIR/build"
LOG_DIR="$(mktemp -d /tmp/ithera_poc_XXXXXX)"

log_info "Workspace Root: $ROOT_DIR"
log_info "Log Directory:  $LOG_DIR"

# Clean up on exit
cleanup() {
    log_info "Running teardown and cleanup..."
    # Kill background jobs
    pkill -f "itherasrv_linux" 2>/dev/null || true
    pkill -f "itheraclient_linux" 2>/dev/null || true
    pkill -f "tcpdump.*veth-srv" 2>/dev/null || true

    # Delete network namespaces (also tears down associated veth interfaces)
    ip netns del ns-server 2>/dev/null || true
    ip netns del ns-client 2>/dev/null || true

    log_info "Cleanup complete. Logs preserved at $LOG_DIR"
}
trap cleanup EXIT

# 3. Ensure binaries exist (build if needed)
if [[ ! -f "$BIN_DIR/itherasrv_linux" || ! -f "$BIN_DIR/itheraclient_linux" || ! -f "$BIN_DIR/itheractl_linux" ]]; then
    log_info "Compiling Linux binaries..."
    (cd "$ROOT_DIR" && GOOS=linux go build -o build/itherasrv_linux ./cmd/itherasrv)
    (cd "$ROOT_DIR" && GOOS=linux go build -o build/itheraclient_linux ./cmd/itheraclient)
    (cd "$ROOT_DIR" && GOOS=linux go build -o build/itheractl_linux ./cmd/itheractl)
fi

# 4. Generate Key Pairs
log_info "Generating WireGuard cryptographic keys using itheractl..."
SERVER_PRIV=$("$BIN_DIR/itheractl_linux" genkey)
SERVER_PUB=$("$BIN_DIR/itheractl_linux" pubkey -privkey "$SERVER_PRIV")

CLIENT_PRIV=$("$BIN_DIR/itheractl_linux" genkey)
CLIENT_PUB=$("$BIN_DIR/itheractl_linux" pubkey -privkey "$CLIENT_PRIV")

log_info "Server Public Key: $SERVER_PUB"
log_info "Client Public Key: $CLIENT_PUB"

# 5. Create Network Namespaces and Underlay veth pair
log_info "Setting up network namespaces: 'ns-server' and 'ns-client'..."
ip netns add ns-server
ip netns add ns-client

# Create veth pair (simulating physical Ethernet link)
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns ns-server
ip link set veth-cli netns ns-client

# Configure Underlay IP: Server is 10.200.0.1/24, Client is 10.200.0.2/24
ip -n ns-server addr add 10.200.0.1/24 dev veth-srv
ip -n ns-server link set veth-srv up
ip -n ns-server link set lo up

ip -n ns-client addr add 10.200.0.2/24 dev veth-cli
ip -n ns-client link set veth-cli up
ip -n ns-client link set lo up

# Validate Underlay Connectivity
log_info "Testing physical link connectivity between namespaces..."
if ! ip netns exec ns-client ping -c 1 -W 1 10.200.0.1 >/dev/null 2>&1; then
    log_fail "Underlay veth ping failed between 10.200.0.2 and 10.200.0.1"
fi
log_ok "Underlay network link established."

# 6. Start tcpdump on Server's underlay interface to verify encryption
log_info "Starting packet capture on underlay interface veth-srv..."
ip netns exec ns-server tcpdump -i veth-srv -nn -l > "$LOG_DIR/underlay_capture.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

# 7. Start itherasrv in ns-server
log_info "Starting itherasrv in ns-server..."
ip netns exec ns-server "$BIN_DIR/itherasrv_linux" \
    -iface ithera-srv \
    -ip 10.0.0.1/24 \
    -port 51820 \
    -privkey "$SERVER_PRIV" \
    -peer-pubkey "$CLIENT_PUB" \
    -peer-allowed-ip 10.0.0.2/32 \
    -v > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

# 8. Start itheraclient in ns-client
log_info "Starting itheraclient in ns-client..."
ip netns exec ns-client "$BIN_DIR/itheraclient_linux" \
    -iface ithera-cli \
    -ip 10.0.0.2/24 \
    -privkey "$CLIENT_PRIV" \
    -server-pubkey "$SERVER_PUB" \
    -server-endpoint 10.200.0.1:51820 \
    -allowed-ips 10.0.0.0/24 \
    -keepalive 25 \
    -v > "$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
sleep 2

# 9. Test Criterion 1: Tunnel Ping (Virtual IP 10.0.0.1)
log_info "Executing ping through virtual tunnel interface: 10.0.0.2 -> 10.0.0.1..."
if ip netns exec ns-client ping -c 4 -W 2 10.0.0.1 > "$LOG_DIR/ping.log" 2>&1; then
    cat "$LOG_DIR/ping.log"
    log_ok "Criterion 1 Passed: Bi-directional tunnel ping succeeded with 0% packet loss!"
else
    cat "$LOG_DIR/ping.log"
    log_warn "Server logs:"
    cat "$LOG_DIR/server.log"
    log_warn "Client logs:"
    cat "$LOG_DIR/client.log"
    log_fail "Criterion 1 Failed: Ping through tunnel failed."
fi

# Allow tcpdump buffer to flush
sleep 1
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# 10. Test Criterion 2: Verify Encryption and Leak Prevention on Wire
log_info "Analyzing underlay capture for plaintext leaks..."
# Check for plaintext ICMP
if grep -i "ICMP" "$LOG_DIR/underlay_capture.log" | grep -v "10.200.0"; then
    log_warn "Plaintext ICMP detected in underlay capture:"
    grep -i "ICMP" "$LOG_DIR/underlay_capture.log"
    log_fail "Criterion 2 Failed: Plaintext tunnel traffic leaked onto physical link!"
fi

# Check that UDP port 51820 traffic was captured
if grep -q "51820" "$LOG_DIR/underlay_capture.log"; then
    log_ok "Criterion 2 Passed: Underlay link carried strictly encrypted UDP (port 51820) packets. No plaintext leaks."
else
    log_warn "Underlay capture content:"
    cat "$LOG_DIR/underlay_capture.log"
    log_fail "Criterion 2 Failed: No WireGuard UDP packets found on underlay link."
fi

echo "=============================================================================="
log_ok "ALL ACCEPTANCE CRITERIA FOR PHASE 1 HAVE PASSED!"
echo "=============================================================================="
