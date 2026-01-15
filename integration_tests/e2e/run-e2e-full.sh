#!/bin/bash
# run-e2e-full.sh - Full E2E test orchestration from host
# Builds unified image, starts containers, runs tests, cleans up
#
# Usage: ./run-e2e-full.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# WHY trap with filtered cleanup: Suppress expected "No such container" but show unexpected errors
cleanup() {
    echo "=== Cleaning up ==="
    docker-compose -f "$SCRIPT_DIR/docker-compose.3-node.yml" down --volumes --remove-orphans 2>&1 | \
        grep -v "No such container" || true
}
trap cleanup EXIT

echo "=== Building Buckwild E2E Image ==="
# WHY build from project root: Dockerfile.unified needs access to full source tree
docker build -f "$SCRIPT_DIR/Dockerfile.unified" -t buckwild-e2e:latest "$PROJECT_ROOT"

echo "=== Starting E2E Environment ==="
docker-compose -f "$SCRIPT_DIR/docker-compose.3-node.yml" up -d

echo "=== Waiting for Health ==="
# Wait for each node to become healthy
for node in node-a node-b node-c; do
    echo "Waiting for $node..."
    timeout=60
    elapsed=0
    while [ $elapsed -lt $timeout ]; do
        # Get container IP and check health
        ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node" 2>/dev/null || echo "")
        if [ -n "$ip" ] && curl -sf "http://${ip}:8080/health" > /dev/null 2>&1; then
            echo "$node is healthy"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    if [ $elapsed -ge $timeout ]; then
        echo "ERROR: $node did not become healthy within ${timeout}s" >&2
        docker logs "$node" 2>&1 | tail -50
        exit 1
    fi
done

echo "=== Running E2E Tests ==="
# Run tests from the test-runner container
docker exec test-runner sh -c "NODES=node-a,node-b,node-c /scripts/run-e2e-tests.sh"

echo "=== E2E Tests Passed ==="
