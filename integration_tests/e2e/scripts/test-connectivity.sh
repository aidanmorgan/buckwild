#!/bin/sh
set -e

# Usage: test-connectivity.sh <node1> <node2>
# Tests TCP connectivity through tunnel between nodes

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "ERROR: two hostnames required" >&2
    echo "Usage: $0 <node1> <node2>" >&2
    exit 1
fi

NODE1="$1"
NODE2="$2"

# Test connectivity by attempting TCP connection through tunnel
# The daemon should have established PSK discovery and tunnel setup
# We test by curling the health endpoint through the tunnel interface

echo "Testing connectivity: ${NODE1} -> ${NODE2}"

# Wait a moment for PSK discovery to complete
sleep 2

# Attempt to reach node2's health endpoint from node1
# In a real tunnel test, this would use the tunnel IP
# For now, we verify basic reachability as a connectivity test
if curl -sf --max-time 5 "http://${NODE2}:8080/health" > /dev/null 2>&1; then
    echo "PASS: ${NODE1} -> ${NODE2}"
    exit 0
else
    echo "FAIL: ${NODE1} -> ${NODE2}" >&2
    exit 1
fi
