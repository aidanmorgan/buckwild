#!/bin/sh
set -e

# Usage: NODES=node-a,node-b ./run-e2e-tests.sh
# Tests all node pairs for connectivity

if [ -z "$NODES" ]; then
    echo "ERROR: NODES environment variable required" >&2
    echo "Usage: NODES=node-a,node-b,node-c $0" >&2
    exit 1
fi

# Convert comma-separated list to space-separated
NODE_LIST=$(echo "$NODES" | tr ',' ' ')

echo "=== E2E Test Suite ==="
echo "Nodes: $NODE_LIST"
echo ""

# Wait for all nodes to become healthy
echo "=== Phase 1: Health Checks ==="
for node in $NODE_LIST; do
    if ! /scripts/wait-for-healthy.sh "$node"; then
        echo "ERROR: Node $node failed health check" >&2
        exit 1
    fi
done
echo ""

# Test connectivity between all node pairs
echo "=== Phase 2: Connectivity Tests ==="
FAILED=0

for node1 in $NODE_LIST; do
    for node2 in $NODE_LIST; do
        # Skip self-tests
        if [ "$node1" = "$node2" ]; then
            continue
        fi

        echo -n "Testing ${node1} -> ${node2}: "
        if /scripts/test-connectivity.sh "$node1" "$node2"; then
            echo "PASS"
        else
            echo "FAIL" >&2
            FAILED=1
        fi
    done
done

echo ""

# Run advanced tests if RUN_ADVANCED=true
if [ "$RUN_ADVANCED" = "true" ]; then
    echo "=== Phase 3: Advanced Tests ==="

    # Get first two nodes for advanced tests
    NODE_A=$(echo "$NODE_LIST" | cut -d' ' -f1)
    NODE_B=$(echo "$NODE_LIST" | cut -d' ' -f2)

    if [ -z "$NODE_B" ]; then
        echo "WARNING: Need at least 2 nodes for advanced tests, skipping" >&2
    else
        # Data transfer test
        echo -n "Data transfer ${NODE_A} -> ${NODE_B}: "
        if /scripts/test-data-transfer.sh "$NODE_A" "$NODE_B"; then
            echo "PASS"
        else
            echo "FAIL" >&2
            FAILED=1
        fi

        # Recovery test
        echo -n "Recovery test ${NODE_A} <-> ${NODE_B}: "
        if /scripts/test-recovery.sh "$NODE_A" "$NODE_B"; then
            echo "PASS"
        else
            echo "FAIL" >&2
            FAILED=1
        fi
    fi
    echo ""
fi

if [ $FAILED -eq 0 ]; then
    echo "=== All Tests Passed ==="
    exit 0
else
    echo "=== Some Tests Failed ===" >&2
    exit 1
fi
