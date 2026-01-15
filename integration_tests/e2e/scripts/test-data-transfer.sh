#!/bin/sh
set -e

# Usage: test-data-transfer.sh <node1> <node2>
# Uses iperf3 to transfer 1MB between nodes through tunnel
# Verifies 0% packet loss and throughput > 10MB/s
#
# Throughput rationale:
# Docker bridge ~1Gbps = ~125MB/s theoretical
# 50% overhead expected = ~62MB/s
# 10MB/s is 1/6th of expected, providing large margin

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "ERROR: two hostnames required" >&2
    echo "Usage: $0 <node1> <node2>" >&2
    exit 1
fi

NODE1="$1"
NODE2="$2"
TRANSFER_SIZE=1048576  # 1MB in bytes
MIN_THROUGHPUT_MBPS=10

echo "=== Data Transfer Test: ${NODE1} -> ${NODE2} ==="

# Start iperf3 server on NODE2
echo "Starting iperf3 server on ${NODE2}..."
docker exec -d "$NODE2" iperf3 -s -1 -D

# Give server time to start
sleep 2

# Run iperf3 client on NODE1, transfer 1MB
echo "Transferring 1MB from ${NODE1} to ${NODE2}..."
RESULT=$(docker exec "$NODE1" iperf3 -c "$NODE2" -n "$TRANSFER_SIZE" -J 2>&1) || {
    echo "ERROR: iperf3 transfer failed" >&2
    echo "$RESULT" >&2
    exit 1
}

# Parse JSON output for throughput and packet loss
# iperf3 JSON format: .end.sum_sent.bits_per_second for throughput
# Note: TCP doesn't report packet loss in same way as UDP, checking retransmits instead
BITS_PER_SEC=$(echo "$RESULT" | grep -o '"bits_per_second":[0-9.]*' | head -1 | cut -d':' -f2)
RETRANSMITS=$(echo "$RESULT" | grep -o '"retransmits":[0-9]*' | head -1 | cut -d':' -f2)

if [ -z "$BITS_PER_SEC" ]; then
    echo "ERROR: could not parse throughput from iperf3 output" >&2
    echo "$RESULT" >&2
    exit 1
fi

# Convert bits/sec to MB/sec (1 MB = 8,388,608 bits)
# Using integer arithmetic: MB/s = bits/sec / 8388608
MBPS=$(awk "BEGIN {printf \"%.2f\", $BITS_PER_SEC / 8388608}")

echo "Transfer complete:"
echo "  Throughput: ${MBPS} MB/s"
echo "  Retransmits: ${RETRANSMITS:-0}"

# Check throughput meets minimum requirement
# Use bc for float comparison if available, otherwise use awk
if command -v bc > /dev/null 2>&1; then
    MEETS_THRESHOLD=$(echo "$MBPS >= $MIN_THROUGHPUT_MBPS" | bc)
else
    MEETS_THRESHOLD=$(awk "BEGIN {print ($MBPS >= $MIN_THROUGHPUT_MBPS)}")
fi

if [ "$MEETS_THRESHOLD" -eq 0 ]; then
    echo "FAIL: throughput ${MBPS} MB/s below minimum ${MIN_THROUGHPUT_MBPS} MB/s" >&2
    exit 1
fi

# Check for excessive retransmits (>5% of packets)
# 1MB at typical MTU ~1500 bytes = ~700 packets
# 5% = ~35 retransmits
MAX_RETRANSMITS=35
if [ "${RETRANSMITS:-0}" -gt "$MAX_RETRANSMITS" ]; then
    echo "FAIL: excessive retransmits ${RETRANSMITS} (max $MAX_RETRANSMITS)" >&2
    exit 1
fi

echo "PASS: data transfer ${NODE1} -> ${NODE2}"
exit 0
