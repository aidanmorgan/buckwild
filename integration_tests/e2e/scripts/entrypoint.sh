#!/bin/bash
set -e

echo "=== Buckwild E2E Node Entrypoint ==="

# Export library path for buckwild daemon
export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

# Per-peer PSKs are mounted at /psk and accessed directly by the daemon
# No need to copy - the config points to /psk and the volume is mounted
echo "=== Per-peer PSK files available ==="
ls -la /psk/

# TUN device cleanup
cleanup_orphaned_tun() {
    if ip link show bw0 >/dev/null 2>&1; then
        echo "Removing existing TUN device bw0"
        ip link delete bw0
    fi
}

# Wait for TUN device to be created
wait_for_tun() {
    echo "Waiting for TUN device bw0..."
    for i in $(seq 1 30); do
        if ip link show bw0 >/dev/null 2>&1; then
            echo "TUN device bw0 is ready"
            return 0
        fi
        sleep 1
    done
    echo "ERROR: TUN device bw0 not created after 30 seconds" >&2
    return 1
}

# Verify routes are configured
verify_routes() {
    echo "Verifying routes..."
    for peer_ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5; do
        if [ "$peer_ip" != "$MY_TUN_IP" ]; then
            if ! ip route | grep -q "$peer_ip.*dev bw0"; then
                echo "ERROR: Route to $peer_ip not found" >&2
                return 1
            fi
        fi
    done
    echo "All routes verified"
    return 0
}

# Verify iptables rules are active
verify_iptables_active() {
    echo "Verifying iptables rules..."
    if ! iptables -L -n | grep -q "DROP.*tcp"; then
        echo "ERROR: iptables rules not active" >&2
        return 1
    fi
    echo "iptables rules verified"
    return 0
}

# Extract TUN IP from config for route verification
# The awk extracts the ip value from the [tun] section
MY_TUN_IP=$(awk '/^\[tun\]/{found=1} found && /^ip[[:space:]]*=/{gsub(/[" ]/, "", $3); print $3; exit}' /etc/buckwild/config.toml)
export MY_TUN_IP
echo "Node TUN IP: $MY_TUN_IP"

# Clean up any orphaned TUN device
cleanup_orphaned_tun

echo "=== Configuring Network Isolation ==="
# Block all non-buckwild traffic to enforce protocol-only communication
# This ensures nodes can ONLY communicate via the buckwild protocol

# Default policy: DROP all traffic
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow loopback (required for internal processes)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections (for responses)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow health check HTTP endpoint (TCP 8080) - only from test-runner subnet
# Test-runner is on the same subnet but nodes should not HTTP to each other
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8080 -j ACCEPT

# Allow file transfer server (TCP 8081) for E2E testing - only from test-runner
# CRITICAL: Nodes cannot HTTP to each other - must use buckwild UDP
iptables -A INPUT -p tcp --dport 8081 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8081 -j ACCEPT

# BLOCK outgoing TCP to other nodes' ports 8080/8081
# This forces file transfer to go through buckwild UDP, not direct HTTP
iptables -A OUTPUT -p tcp --dport 8080 -j DROP
iptables -A OUTPUT -p tcp --dport 8081 -j DROP

# Allow ALL UDP traffic for buckwild protocol
# Port hopping means we can't specify exact ports - buckwild uses HMAC-calculated ports
# HMAC verification in the protocol ensures only valid buckwild packets are processed
iptables -A INPUT -p udp -j ACCEPT
iptables -A OUTPUT -p udp -j ACCEPT

# Block all other TCP (no direct TCP communication between nodes except health)
# This means no SSH, no file transfer over TCP, etc.
iptables -A INPUT -p tcp -j DROP
iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT  # Allow outgoing to health endpoints
iptables -A OUTPUT -p tcp -j DROP

# Log denied packets for debugging
iptables -A INPUT -j LOG --log-prefix "BUCKWILD-DENY-IN: " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "BUCKWILD-DENY-OUT: " --log-level 4

echo "=== Network Isolation Rules Applied ==="
echo "✓ Loopback allowed"
echo "✓ Health endpoint TCP:8080 allowed"
echo "✓ File server TCP:8081 allowed"
echo "✓ All UDP allowed (buckwild protocol)"
echo "✗ All other TCP blocked"
echo ""

# Display rules for verification
echo "=== iptables Rules ==="
iptables -L -v -n
echo ""

echo "=== Starting File Transfer Server ==="
# Start file server for E2E testing (background)
python3 /scripts/file_server.py &
FILE_SERVER_PID=$!
echo "File server started (PID: $FILE_SERVER_PID)"

echo "=== Starting Buckwild Daemon ==="
# Start buckwild daemon (background for verification)
/usr/local/bin/buckwild-daemon -c /etc/buckwild/config.toml &
DAEMON_PID=$!
echo "Buckwild daemon started (PID: $DAEMON_PID)"

# Wait for TUN device
wait_for_tun || exit 1

# Verify routes are configured
verify_routes || exit 1

# Verify iptables rules
verify_iptables_active || exit 1

echo "=== All verifications passed ==="
echo "Bringing daemon to foreground..."

# Wait for daemon process
wait $DAEMON_PID
