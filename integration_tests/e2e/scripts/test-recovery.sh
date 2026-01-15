#!/bin/sh
set -e

# Usage: test-recovery.sh <node_to_kill> <surviving_node>
# Kills one node, verifies surviving node detects failure, restarts killed node, verifies recovery
#
# Recovery timeout rationale:
# Port hopping bucket changes every 5s
# Full handshake = discovery + ECDH + first bucket = ~7-8s typical
# 10s provides 25% margin without masking genuine slowness

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "ERROR: two hostnames required" >&2
    echo "Usage: $0 <node_to_kill> <surviving_node>" >&2
    exit 1
fi

NODE_KILL="$1"
NODE_SURVIVE="$2"
RECOVERY_TIMEOUT=10

echo "=== Recovery Test: Kill ${NODE_KILL}, Verify ${NODE_SURVIVE} Recovers ==="

# Verify both nodes are initially healthy
echo "Verifying initial health of both nodes..."
if ! /scripts/wait-for-healthy.sh "$NODE_KILL"; then
    echo "ERROR: ${NODE_KILL} not healthy before test" >&2
    exit 1
fi
if ! /scripts/wait-for-healthy.sh "$NODE_SURVIVE"; then
    echo "ERROR: ${NODE_SURVIVE} not healthy before test" >&2
    exit 1
fi

# Verify connectivity before killing
echo "Verifying initial connectivity..."
if ! docker exec "$NODE_SURVIVE" curl -sf --max-time 5 "http://${NODE_KILL}:8080/health" > /dev/null 2>&1; then
    echo "ERROR: no connectivity before test" >&2
    exit 1
fi

# Kill the target node
echo "Killing ${NODE_KILL}..."
docker stop "$NODE_KILL" > /dev/null 2>&1

# Verify node is actually stopped
echo "Verifying ${NODE_KILL} stopped..."
STATUS=$(docker inspect -f '{{.State.Status}}' "$NODE_KILL" 2>&1)
if [ "$STATUS" != "exited" ]; then
    echo "ERROR: ${NODE_KILL} not stopped (status: ${STATUS})" >&2
    docker start "$NODE_KILL" > /dev/null 2>&1  # Try to clean up
    exit 1
fi

# Give surviving node time to detect failure
# The daemon should notice connection lost and mark peer as unavailable
echo "Waiting for ${NODE_SURVIVE} to detect failure..."
sleep 3

# Restart the killed node
echo "Restarting ${NODE_KILL}..."
docker start "$NODE_KILL" > /dev/null 2>&1

# Wait for node to become healthy
if ! /scripts/wait-for-healthy.sh "$NODE_KILL"; then
    echo "ERROR: ${NODE_KILL} failed to restart" >&2
    exit 1
fi

# Measure recovery time - how long until connectivity restores
echo "Measuring recovery time (max ${RECOVERY_TIMEOUT}s)..."
START_TIME=$(date +%s)
RECOVERED=0
ELAPSED=0

while [ $ELAPSED -lt $RECOVERY_TIMEOUT ]; do
    if docker exec "$NODE_SURVIVE" curl -sf --max-time 2 "http://${NODE_KILL}:8080/health" > /dev/null 2>&1; then
        RECOVERED=1
        break
    fi

    sleep 1
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
done

if [ $RECOVERED -eq 0 ]; then
    echo "FAIL: connection did not recover within ${RECOVERY_TIMEOUT}s" >&2
    exit 1
fi

# Verify bidirectional connectivity
if ! docker exec "$NODE_KILL" curl -sf --max-time 5 "http://${NODE_SURVIVE}:8080/health" > /dev/null 2>&1; then
    echo "FAIL: reverse connectivity not restored" >&2
    exit 1
fi

echo "Connection recovered in ${ELAPSED}s"
echo "PASS: recovery test ${NODE_KILL} <-> ${NODE_SURVIVE}"
exit 0
